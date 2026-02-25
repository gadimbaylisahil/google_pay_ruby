# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'json'
require 'net/http'
require 'uri'

module GooglePayRuby
  class SignatureVerifier
    SENDER_ID = 'Google'
    PROTOCOL_VERSION = 'ECv2'

    GOOGLE_ROOT_SIGNING_KEYS_URL = 'https://payments.developers.google.com/paymentmethodtoken/keys.json'
    GOOGLE_ROOT_SIGNING_KEYS_TEST_URL = 'https://payments.developers.google.com/paymentmethodtoken/test/keys.json'

    # @param root_signing_keys [Array<Hash>, nil] Pre-fetched root signing keys. If nil, they will be fetched from Google.
    # @param recipient_id [String, nil] The recipient ID, e.g. "merchant:12345" or "gateway:yourGatewayId". If nil, message signature verification (step 4) is skipped.
    # @param test [Boolean] Whether to use test keys URL (default: false)
    def initialize(root_signing_keys: nil, recipient_id: nil, test: false)
      @root_signing_keys = root_signing_keys
      @recipient_id = recipient_id
      @test = test
    end

    # Verifies the token's signatures and returns the intermediate signing key value
    # for use in decryption. Raises GooglePaymentDecryptionError on any failure.
    #
    # @param token [Hash] The full Google Pay token
    # @return [void]
    def verify!(token)
      protocol_version = token['protocolVersion'] || token[:protocolVersion]
      unless protocol_version == PROTOCOL_VERSION
        raise GooglePaymentDecryptionError.new(
          "Unsupported protocol version: #{protocol_version}. Only ECv2 is supported."
        )
      end

      intermediate_signing_key = token['intermediateSigningKey'] || token[:intermediateSigningKey]
      unless intermediate_signing_key
        raise GooglePaymentDecryptionError.new('Missing intermediateSigningKey in token')
      end

      signed_key = intermediate_signing_key['signedKey'] || intermediate_signing_key[:signedKey]
      signatures = intermediate_signing_key['signatures'] || intermediate_signing_key[:signatures]

      unless signed_key && signatures
        raise GooglePaymentDecryptionError.new('Missing signedKey or signatures in intermediateSigningKey')
      end

      # Step 1 & 2: Verify intermediate signing key signature against root keys
      verify_intermediate_signing_key_signature!(signed_key, signatures)

      # Step 3: Verify intermediate signing key hasn't expired
      verify_intermediate_signing_key_expiration!(signed_key)

      # Step 4: Verify message signature using intermediate signing key
      signed_message = token['signedMessage'] || token[:signedMessage]
      signature = token['signature'] || token[:signature]

      unless signed_message && signature
        raise GooglePaymentDecryptionError.new('Missing signedMessage or signature in token')
      end

      parsed_signed_key = JSON.parse(signed_key)
      intermediate_key_value = parsed_signed_key['keyValue']

      # Only verify message signature if recipient_id is provided
      if @recipient_id && !@recipient_id.empty?
        verify_message_signature!(signed_message, signature, intermediate_key_value)
      end
    end

    private

    def root_signing_keys
      @root_signing_keys ||= fetch_root_signing_keys
    end

    def fetch_root_signing_keys
      url = @test ? GOOGLE_ROOT_SIGNING_KEYS_TEST_URL : GOOGLE_ROOT_SIGNING_KEYS_URL
      uri = URI.parse(url)

      response = Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
        http.open_timeout = 10
        http.read_timeout = 10
        http.get(uri.request_uri)
      end

      unless response.is_a?(Net::HTTPSuccess)
        raise GooglePaymentDecryptionError.new(
          "Failed to fetch Google root signing keys: HTTP #{response.code}"
        )
      end

      parsed = JSON.parse(response.body)
      keys = parsed['keys'] || []

      # Filter to only ECv2 keys
      keys.select { |k| k['protocolVersion'] == PROTOCOL_VERSION }
    rescue JSON::ParserError => e
      raise GooglePaymentDecryptionError.new("Failed to parse Google root signing keys: #{e.message}")
    rescue StandardError => e
      raise e if e.is_a?(GooglePaymentDecryptionError)

      raise GooglePaymentDecryptionError.new("Failed to fetch Google root signing keys: #{e.message}")
    end

    # Step 2: Verify that the intermediate signing key signature is valid
    # by any of the non-expired root signing keys.
    def verify_intermediate_signing_key_signature!(signed_key, signatures)
      signed_string = build_signed_string_for_intermediate_key(signed_key)
      now_ms = (Time.now.to_f * 1000).to_i

      non_expired_root_keys = root_signing_keys.select do |key|
        expiration = key['keyExpiration']
        expiration.nil? || expiration.to_i > now_ms
      end

      if non_expired_root_keys.empty?
        raise GooglePaymentDecryptionError.new('No non-expired Google root signing keys available')
      end

      verified = false

      signatures.each do |sig_b64|
        sig_bytes = Base64.strict_decode64(sig_b64)

        non_expired_root_keys.each do |root_key|
          ec_key = build_ec_public_key(root_key['keyValue'])
          if ec_key.dsa_verify_asn1(
            OpenSSL::Digest::SHA256.digest(signed_string),
            sig_bytes
          )
            verified = true
            break
          end
        rescue OpenSSL::PKey::ECError
          next
        end

        break if verified
      end

      unless verified
        raise GooglePaymentDecryptionError.new(
          'Could not verify intermediate signing key signature against any non-expired root key'
        )
      end
    end

    # Step 3: Verify that the intermediate signing key hasn't expired.
    def verify_intermediate_signing_key_expiration!(signed_key)
      parsed = JSON.parse(signed_key)
      key_expiration = parsed['keyExpiration']

      unless key_expiration
        raise GooglePaymentDecryptionError.new('intermediateSigningKey.signedKey is missing keyExpiration')
      end

      now_ms = (Time.now.to_f * 1000).to_i

      if key_expiration.to_i <= now_ms
        raise GooglePaymentDecryptionError.new(
          "Intermediate signing key has expired (expiration: #{key_expiration})"
        )
      end
    end

    # Step 4: Verify that the message signature is valid using the intermediate signing key.
    def verify_message_signature!(signed_message, signature_b64, intermediate_key_value)
      signed_string = build_signed_string_for_message(signed_message)
      sig_bytes = Base64.strict_decode64(signature_b64)

      ec_key = build_ec_public_key(intermediate_key_value)

      valid = ec_key.dsa_verify_asn1(
        OpenSSL::Digest::SHA256.digest(signed_string),
        sig_bytes
      )

      unless valid
        raise GooglePaymentDecryptionError.new('Message signature verification failed')
      end
    rescue OpenSSL::PKey::ECError => e
      raise GooglePaymentDecryptionError.new("Message signature verification error: #{e.message}")
    end

    # Construct the byte-string for intermediate signing key signature verification:
    # signedString = length_of_sender_id || sender_id || length_of_protocol_version || protocol_version || length_of_signed_key || signed_key
    def build_signed_string_for_intermediate_key(signed_key)
      sender_id_bytes = SENDER_ID.encode('UTF-8')
      protocol_version_bytes = PROTOCOL_VERSION.encode('UTF-8')
      signed_key_bytes = signed_key.encode('UTF-8')

      [sender_id_bytes.bytesize].pack('V') + sender_id_bytes +
        [protocol_version_bytes.bytesize].pack('V') + protocol_version_bytes +
        [signed_key_bytes.bytesize].pack('V') + signed_key_bytes
    end

    # Construct the byte-string for message signature verification:
    # signedString = length_of_sender_id || sender_id || length_of_recipient_id || recipient_id || length_of_protocol_version || protocol_version || length_of_signed_message || signed_message
    def build_signed_string_for_message(signed_message)
      sender_id_bytes = SENDER_ID.encode('UTF-8')
      recipient_id_bytes = @recipient_id.encode('UTF-8')
      protocol_version_bytes = PROTOCOL_VERSION.encode('UTF-8')
      signed_message_bytes = signed_message.encode('UTF-8')

      [sender_id_bytes.bytesize].pack('V') + sender_id_bytes +
        [recipient_id_bytes.bytesize].pack('V') + recipient_id_bytes +
        [protocol_version_bytes.bytesize].pack('V') + protocol_version_bytes +
        [signed_message_bytes.bytesize].pack('V') + signed_message_bytes
    end

    # Build an OpenSSL EC public key from a base64-encoded SubjectPublicKeyInfo value.
    def build_ec_public_key(key_value_b64)
      key_der = Base64.strict_decode64(key_value_b64)
      OpenSSL::PKey::EC.new(key_der)
    end
  end
end

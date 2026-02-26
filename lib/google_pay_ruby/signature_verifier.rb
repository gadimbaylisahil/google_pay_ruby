# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'json'
require 'net/http'
require 'uri'

module GooglePayRuby
  # Implements Google Pay ECv2 signature verification as specified in:
  # https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography
  #
  # Verification steps:
  #   1. Fetch Google root signing keys
  #   2. Verify intermediate signing key signature against non-expired root keys
  #   3. Verify intermediate signing key hasn't expired
  #   4. Verify message signature using intermediate signing key
  class SignatureVerifier
    SENDER_ID = 'Google'
    PROTOCOL_VERSION = 'ECv2'

    GOOGLE_ROOT_SIGNING_KEYS_PROD_URL = 'https://payments.developers.google.com/paymentmethodtoken/keys.json'
    GOOGLE_ROOT_SIGNING_KEYS_TEST_URL = 'https://payments.developers.google.com/paymentmethodtoken/test/keys.json'

    # @param root_signing_keys [Array<Hash>, nil] Pre-fetched root signing keys (ECv2 only).
    #   Each hash should have 'keyValue', 'protocolVersion', and optionally 'keyExpiration'.
    #   If nil, keys are fetched from Google's public URL.
    # @param recipient_id [String] The recipient ID used in message signature verification.
    #   For merchants: "merchant:<merchantId>" (merchantId from Google Pay & Wallet Console).
    #   For gateways: "gateway:<gatewayId>".
    # @param test [Boolean] Whether to use Google's test keys URL (default: false).
    def initialize(root_signing_keys: nil, recipient_id:, test: false)
      @root_signing_keys = root_signing_keys
      @recipient_id = recipient_id
      @test = test
    end

    # Runs all verification steps (1-4) on the given token.
    # Raises GooglePaymentDecryptionError on any verification failure.
    #
    # @param token [Hash] The full Google Pay payment method token (parsed)
    # @param raw_token_json [String, nil] The original raw JSON string of the token.
    #   When provided, signedKey and signedMessage are extracted from this raw string
    #   to preserve the exact byte sequences that Google signed over (e.g. \u003d escapes).
    #   JSON.parse decodes \u003d to '=' which changes the signed content and breaks verification.
    # @return [void]
    def verify!(token, raw_token_json: nil)
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

      signed_key_json = intermediate_signing_key['signedKey'] || intermediate_signing_key[:signedKey]
      signatures = intermediate_signing_key['signatures'] || intermediate_signing_key[:signatures]

      unless signed_key_json && signatures
        raise GooglePaymentDecryptionError.new('Missing signedKey or signatures in intermediateSigningKey')
      end

      # Extract original signedKey and signedMessage from raw JSON if available.
      # This preserves the exact byte sequences (including unicode escapes like \u003d)
      # that Google used when computing signatures.
      if raw_token_json
        raw_signed_key = extract_json_string_value(raw_token_json, 'signedKey')
        raw_signed_message = extract_json_string_value(raw_token_json, 'signedMessage')
        signed_key_json = raw_signed_key if raw_signed_key
        signed_message_for_verify = raw_signed_message
      end

      # Step 2: Verify intermediate signing key signature against non-expired root keys
      verify_intermediate_signing_key_signature!(signed_key_json, signatures)

      # Step 3: Verify intermediate signing key hasn't expired
      verify_intermediate_signing_key_expiration!(signed_key_json)

      # Step 4: Verify message signature using intermediate signing key
      signed_message = signed_message_for_verify || token['signedMessage'] || token[:signedMessage]
      signature = token['signature'] || token[:signature]

      unless signed_message && signature
        raise GooglePaymentDecryptionError.new('Missing signedMessage or signature in token')
      end

      parsed_signed_key = JSON.parse(signed_key_json)
      intermediate_key_value = parsed_signed_key['keyValue']

      verify_message_signature!(signed_message, signature, intermediate_key_value)
    end

    private

    # Step 1: Fetch or return cached root signing keys (filtered to ECv2).
    def root_signing_keys
      @root_signing_keys ||= fetch_root_signing_keys
    end

    def fetch_root_signing_keys
      url = @test ? GOOGLE_ROOT_SIGNING_KEYS_TEST_URL : GOOGLE_ROOT_SIGNING_KEYS_PROD_URL
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

      # Filter to ECv2 keys only
      keys.select { |k| k['protocolVersion'] == PROTOCOL_VERSION }
    rescue JSON::ParserError => e
      raise GooglePaymentDecryptionError.new("Failed to parse Google root signing keys: #{e.message}")
    rescue StandardError => e
      raise e if e.is_a?(GooglePaymentDecryptionError)

      raise GooglePaymentDecryptionError.new("Failed to fetch Google root signing keys: #{e.message}")
    end

    # Step 2: Verify that at least one signature in intermediateSigningKey.signatures
    # is valid against any non-expired root signing key.
    #
    # Per spec: "iterate over all the signatures in intermediateSigningKey.signatures
    # and try to validate each one with the non-expired Google signing keys in keys.json.
    # If at least one signature validation works, consider the verification complete."
    def verify_intermediate_signing_key_signature!(signed_key_json, signatures)
      signed_bytes = build_signed_bytes_for_intermediate_key(signed_key_json)
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
        break if verified

        sig_der = Base64.strict_decode64(sig_b64)

        non_expired_root_keys.each do |root_key|
          begin
            ec_key = build_ec_public_key(root_key['keyValue'])
            if ec_key.dsa_verify_asn1(
              OpenSSL::Digest::SHA256.digest(signed_bytes),
              sig_der
            )
              verified = true
              break
            end
          rescue OpenSSL::PKey::ECError
            next
          end
        end
      end

      unless verified
        raise GooglePaymentDecryptionError.new(
          'Could not verify intermediate signing key signature against any non-expired root key'
        )
      end
    end

    # Step 3: Verify that the intermediate signing key hasn't expired.
    def verify_intermediate_signing_key_expiration!(signed_key_json)
      parsed = JSON.parse(signed_key_json)
      key_expiration = parsed['keyExpiration']

      unless key_expiration
        raise GooglePaymentDecryptionError.new('intermediateSigningKey.signedKey is missing keyExpiration')
      end

      now_ms = (Time.now.to_f * 1000).to_i

      if key_expiration.to_i <= now_ms
        raise GooglePaymentDecryptionError.new(
          "Intermediate signing key has expired (keyExpiration: #{key_expiration})"
        )
      end
    end

    # Step 4: Verify that the message signature is valid using the intermediate signing key.
    def verify_message_signature!(signed_message, signature_b64, intermediate_key_value_b64)
      signed_bytes = build_signed_bytes_for_message(signed_message)
      sig_der = Base64.strict_decode64(signature_b64)

      ec_key = build_ec_public_key(intermediate_key_value_b64)

      valid = ec_key.dsa_verify_asn1(
        OpenSSL::Digest::SHA256.digest(signed_bytes),
        sig_der
      )

      unless valid
        raise GooglePaymentDecryptionError.new('Message signature verification failed')
      end
    rescue OpenSSL::PKey::ECError => e
      raise GooglePaymentDecryptionError.new("Message signature verification error: #{e.message}")
    end

    # Construct the byte-string for intermediate signing key signature verification:
    #
    #   signedStringForIntermediateSigningKeySignature =
    #     length_of_sender_id || sender_id ||
    #     length_of_protocol_version || protocol_version ||
    #     length_of_signed_key || signed_key
    #
    # Each component is UTF-8 encoded. Lengths are 4 bytes little-endian.
    def build_signed_bytes_for_intermediate_key(signed_key_json)
      sender_id_bytes = SENDER_ID.encode('UTF-8')
      protocol_version_bytes = PROTOCOL_VERSION.encode('UTF-8')
      signed_key_bytes = signed_key_json.encode('UTF-8')

      [sender_id_bytes.bytesize].pack('V') + sender_id_bytes +
        [protocol_version_bytes.bytesize].pack('V') + protocol_version_bytes +
        [signed_key_bytes.bytesize].pack('V') + signed_key_bytes
    end

    # Construct the byte-string for message signature verification:
    #
    #   signedStringForMessageSignature =
    #     length_of_sender_id || sender_id ||
    #     length_of_recipient_id || recipient_id ||
    #     length_of_protocolVersion || protocolVersion ||
    #     length_of_signedMessage || signedMessage
    #
    # Each component is UTF-8 encoded. Lengths are 4 bytes little-endian.
    # Per spec: "don't parse or modify signedMessage"
    def build_signed_bytes_for_message(signed_message)
      sender_id_bytes = SENDER_ID.encode('UTF-8')
      recipient_id_bytes = @recipient_id.encode('UTF-8')
      protocol_version_bytes = PROTOCOL_VERSION.encode('UTF-8')
      signed_message_bytes = signed_message.encode('UTF-8')

      [sender_id_bytes.bytesize].pack('V') + sender_id_bytes +
        [recipient_id_bytes.bytesize].pack('V') + recipient_id_bytes +
        [protocol_version_bytes.bytesize].pack('V') + protocol_version_bytes +
        [signed_message_bytes.bytesize].pack('V') + signed_message_bytes
    end

    # Build an OpenSSL EC public key from a base64-encoded SubjectPublicKeyInfo DER value.
    def build_ec_public_key(key_value_b64)
      key_der = Base64.strict_decode64(key_value_b64)
      OpenSSL::PKey::EC.new(key_der)
    end

    # Extract a JSON string value from raw JSON without decoding unicode escapes.
    # This is critical because Google signs over the exact string content including
    # any \uXXXX escapes. Ruby's JSON.parse decodes \u003d to '=' which changes
    # the bytes and invalidates signatures.
    #
    # For a key like "signedKey", the value in the outer JSON is a JSON-encoded string.
    # We need to extract and unescape the JSON string escapes (\" -> ", \\\\ -> \\)
    # but preserve \uXXXX sequences as-is.
    def extract_json_string_value(raw_json, key)
      # Match "key":"<value>" where value may contain escaped characters
      pattern = /"#{Regexp.escape(key)}"\s*:\s*"/
      match = pattern.match(raw_json)
      return nil unless match

      start_pos = match.end(0)
      # Walk through the string to find the unescaped closing quote
      pos = start_pos
      result = String.new
      while pos < raw_json.length
        char = raw_json[pos]
        if char == '\\'
          next_char = raw_json[pos + 1]
          case next_char
          when '"'
            result << '"'
            pos += 2
          when '\\'
            result << '\\'
            pos += 2
          when '/'
            result << '/'
            pos += 2
          when 'n'
            result << "\n"
            pos += 2
          when 'r'
            result << "\r"
            pos += 2
          when 't'
            result << "\t"
            pos += 2
          when 'b'
            result << "\b"
            pos += 2
          when 'f'
            result << "\f"
            pos += 2
          when 'u'
            # Preserve \uXXXX as literal characters in the output
            result << raw_json[pos..pos + 5]
            pos += 6
          else
            result << char
            pos += 1
          end
        elsif char == '"'
          break
        else
          result << char
          pos += 1
        end
      end
      result
    end
  end
end

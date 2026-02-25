# frozen_string_literal: true

module GooglePayRuby
  class GooglePaymentMethodTokenContext
    attr_reader :merchants

    # @param options [Hash]
    # @option options [Array<Hash>] :merchants List of merchant configs with :private_key_pem and optional :identifier
    # @option options [String] :recipient_id The recipient ID for signature verification (e.g. "merchant:12345" or "gateway:yourGatewayId")
    # @option options [Array<Hash>, nil] :root_signing_keys Pre-fetched Google root signing keys. If nil, fetched automatically.
    # @option options [Boolean] :test Whether to use Google's test keys URL (default: false)
    # @option options [Boolean] :verify_signature Whether to verify token signatures (default: true)
    # @option options [Boolean] :verify_expiration Whether to verify messageExpiration after decryption (default: true)
    def initialize(options)
      @merchants = options[:merchants] || []
      @recipient_id = options[:recipient_id]
      @root_signing_keys = options[:root_signing_keys]
      @test = options.fetch(:test, false)
      @verify_signature = options.fetch(:verify_signature, true)
      @verify_expiration = options.fetch(:verify_expiration, true)

      if @merchants.empty?
        raise GooglePaymentDecryptionError.new(
          'No merchant configuration provided for decryption context.'
        )
      end

      # recipient_id is optional — if not provided, message signature verification (step 4) is skipped
      # while intermediate key verification (steps 1-3) still runs

      validate_merchant_configurations!
    end

    def decrypt(token)
      protocol_version = token['protocolVersion'] || token[:protocolVersion]
      unless protocol_version == 'ECv2'
        raise GooglePaymentDecryptionError.new(
          "Unsupported decryption for protocol version #{protocol_version}"
        )
      end

      # Steps 1-4: Signature verification before decryption
      if @verify_signature
        verifier = SignatureVerifier.new(
          root_signing_keys: @root_signing_keys,
          recipient_id: @recipient_id,
          test: @test
        )
        verifier.verify!(token)
      end

      # Step 5: Decrypt the payload
      errors = []
      signed_message = token['signedMessage'] || token[:signedMessage]

      decrypted_data = nil
      @merchants.each do |merchant|
        begin
          strategy = EcV2DecryptionStrategy.new(merchant[:private_key_pem])
          decrypted_data = strategy.decrypt(signed_message)
          break
        rescue StandardError => e
          e.define_singleton_method(:merchant_identifier) { merchant[:identifier] }
          errors << e
        end
      end

      unless decrypted_data
        raise GooglePaymentDecryptionError.new(
          'Failed to decrypt payment data using provided merchant configuration(s).',
          errors
        )
      end

      # Step 6: Verify message hasn't expired
      if @verify_expiration
        verify_message_expiration!(decrypted_data)
      end

      decrypted_data
    end

    private

    # Step 6: Verify that the current time is less than messageExpiration
    def verify_message_expiration!(decrypted_data)
      message_expiration = decrypted_data['messageExpiration']

      unless message_expiration
        raise GooglePaymentDecryptionError.new(
          'Decrypted message is missing messageExpiration field'
        )
      end

      now_ms = (Time.now.to_f * 1000).to_i

      if message_expiration.to_i <= now_ms
        raise GooglePaymentDecryptionError.new(
          "Decrypted message has expired (messageExpiration: #{message_expiration})"
        )
      end
    end

    def validate_merchant_configurations!
      @merchants.each_with_index do |merchant, index|
        unless merchant.is_a?(Hash)
          raise ArgumentError, "Merchant configuration at index #{index} must be a Hash"
        end

        unless merchant[:private_key_pem]
          raise ArgumentError, "Merchant configuration at index #{index} must include :private_key_pem"
        end
      end
    end
  end
end

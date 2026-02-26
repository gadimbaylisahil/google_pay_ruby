# frozen_string_literal: true

module GooglePayRuby
  class GooglePaymentMethodTokenContext
    attr_reader :merchants

    # @param options [Hash]
    # @option options [Array<Hash>] :merchants List of merchant configs with :private_key_pem and optional :identifier
    # @option options [String] :recipient_id The recipient ID for message signature verification
    #   (e.g. "merchant:<merchantId>" or "gateway:<gatewayId>"). Required when verify_signature is true.
    # @option options [Array<Hash>, nil] :root_signing_keys Pre-fetched Google root signing keys (ECv2 only).
    #   If nil, fetched automatically from Google's public URL.
    # @option options [Boolean] :test Whether to use Google's test keys URL (default: false)
    # @option options [Boolean] :verify_signature Whether to verify token signatures before decryption (default: true)
    # @option options [Boolean] :verify_expiration Whether to verify messageExpiration after decryption (default: true)
    # @option options [String, nil] :gateway_merchant_id Expected gatewayMerchantId to verify in the decrypted payload.
    #   When provided, the decrypted paymentMethodDetails.gatewayMerchantId must match this value.
    # @option options [Boolean] :verify_merchant_id Whether to verify gatewayMerchantId after decryption (default: true if gateway_merchant_id is provided)
    def initialize(options)
      @merchants = options[:merchants] || []
      @recipient_id = options[:recipient_id]
      @root_signing_keys = options[:root_signing_keys]
      @gateway_merchant_id = options[:gateway_merchant_id]
      @test = options.fetch(:test, false)
      @verify_signature = options.fetch(:verify_signature, true)
      @verify_expiration = options.fetch(:verify_expiration, true)
      @verify_merchant_id = options.fetch(:verify_merchant_id, !@gateway_merchant_id.nil?)

      if @merchants.empty?
        raise GooglePaymentDecryptionError.new(
          'No merchant configuration provided for decryption context.'
        )
      end

      if @verify_signature && (@recipient_id.nil? || @recipient_id.empty?)
        raise ArgumentError, ':recipient_id is required when signature verification is enabled'
      end

      validate_merchant_configurations!
    end

    # @param token [Hash, String] The Google Pay payment method token.
    #   Can be a Hash (already parsed) or a JSON String (will be parsed internally).
    #   When a String is provided, the raw JSON is preserved for signature verification
    #   to handle unicode escapes (e.g. \u003d) that JSON.parse would decode.
    def decrypt(token)
      if token.is_a?(String)
        raw_token_json = token
        token = JSON.parse(token)
      end

      protocol_version = token['protocolVersion'] || token[:protocolVersion]
      unless protocol_version == 'ECv2'
        raise GooglePaymentDecryptionError.new(
          "Unsupported decryption for protocol version #{protocol_version}"
        )
      end

      # Steps 1-4: Verify signatures before decryption
      if @verify_signature
        verifier = SignatureVerifier.new(
          root_signing_keys: @root_signing_keys,
          recipient_id: @recipient_id,
          test: @test
        )
        verifier.verify!(token, raw_token_json: raw_token_json)
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

      # Step 7: Verify gatewayMerchantId matches expected value
      if @verify_merchant_id
        verify_gateway_merchant_id!(decrypted_data)
      end

      decrypted_data
    end

    private

    # Step 7: Verify that the gatewayMerchantId in the decrypted payload matches the expected value.
    # Per spec: "Verify that the gatewayMerchantId matches the ID of the merchant that gave you the payload."
    def verify_gateway_merchant_id!(decrypted_data)
      actual_merchant_id = decrypted_data['gatewayMerchantId']

      unless actual_merchant_id
        raise GooglePaymentDecryptionError.new(
          'Decrypted message is missing gatewayMerchantId field'
        )
      end

      unless actual_merchant_id == @gateway_merchant_id
        raise GooglePaymentDecryptionError.new(
          "gatewayMerchantId mismatch: expected '#{@gateway_merchant_id}', got '#{actual_merchant_id}'"
        )
      end
    end

    # Step 6: Verify that the current time is less than the messageExpiration field
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

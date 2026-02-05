# frozen_string_literal: true

module GooglePayRuby
  class GooglePaymentMethodTokenContext
    attr_reader :merchants

    def initialize(options)
      @merchants = options[:merchants] || []
      
      if @merchants.empty?
        raise GooglePaymentDecryptionError.new(
          'No merchant configuration provided for decryption context.'
        )
      end
      
      validate_merchant_configurations!
    end

    def decrypt(token)
      protocol_version = token['protocolVersion'] || token[:protocolVersion]
      unless protocol_version == 'ECv2'
        raise GooglePaymentDecryptionError.new(
          "Unsupported decryption for protocol version #{protocol_version}"
        )
      end

      errors = []
      signed_message = token['signedMessage'] || token[:signedMessage]

      @merchants.each do |merchant|
        begin
          strategy = EcV2DecryptionStrategy.new(merchant[:private_key_pem])
          return strategy.decrypt(signed_message)
        rescue StandardError => e
          e.define_singleton_method(:merchant_identifier) { merchant[:identifier] }
          errors << e
        end
      end

      raise GooglePaymentDecryptionError.new(
        'Failed to decrypt payment data using provided merchant configuration(s).',
        errors
      )
    end

    private

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

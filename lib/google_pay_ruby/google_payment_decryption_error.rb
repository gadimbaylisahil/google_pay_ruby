# frozen_string_literal: true

module GooglePayRuby
  class GooglePaymentDecryptionError < StandardError
    attr_reader :errors

    def initialize(message, errors = [])
      @errors = errors
      super(message)
    end

    def full_message
      message_parts = [message]
      
      if errors.any?
        message_parts << "\nDecryption attempts failed:"
        errors.each_with_index do |error, index|
          merchant_id = error.respond_to?(:merchant_identifier) ? error.merchant_identifier : "Unknown"
          message_parts << "  [#{index + 1}] Merchant: #{merchant_id} - #{error.message}"
        end
      end
      
      message_parts.join("\n")
    end
  end
end

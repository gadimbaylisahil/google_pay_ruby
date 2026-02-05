# GooglePayRuby

A Ruby utility for securely decrypting Google Pay PaymentMethodTokens using the ECv2 protocol. This gem is a Ruby port of the [Basis Theory google-pay-js](https://github.com/Basis-Theory/google-pay-js) library.

## Features

- **Google Pay PaymentMethodToken Decryption**: Securely decrypt user-authorized Google Pay transaction tokens using easy-to-use interfaces
- **Key Rotation Support**: Handle multiple private keys simultaneously to support seamless key rotation without missing payments
- **Pure Ruby Implementation**: No external dependencies beyond OpenSSL (included in Ruby standard library)
- **ECv2 Protocol Support**: Implements Google Pay's ECv2 encryption protocol

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'google_pay_ruby'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install google_pay_ruby
```

## Google Pay Setup

Follow [Google Pay API guides](https://developers.google.com/pay/api) for your platform. To use this library, you need to:

1. Be PCI Level 1 certified
2. Choose tokenization type `DIRECT`
3. Generate and register your encryption keys with Google

⚠️ **Important**: If you are not PCI Level 1 certified, consider using `PAYMENT_GATEWAY` tokenization type or contact a payment gateway provider.

## Usage

### Basic Example

```ruby
require 'google_pay_ruby'

# Load your private key (from file, KMS, secrets manager, etc.)
private_key_pem = File.read('path/to/your/private_key.pem')

# Create the decryption context
context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [
    {
      identifier: 'my-merchant-identifier',  # Optional, for debugging
      private_key_pem: private_key_pem
    }
  ]
)

# Get the token from Google Pay API response
token = {
  'protocolVersion' => 'ECv2',
  'signature' => '...',
  'signedMessage' => '{"encryptedMessage":"...","ephemeralPublicKey":"...","tag":"..."}'
}

# Decrypt the token
begin
  decrypted_data = context.decrypt(token)
  
  puts "PAN: #{decrypted_data['paymentMethodDetails']['pan']}"
  puts "Expiration: #{decrypted_data['paymentMethodDetails']['expirationMonth']}/#{decrypted_data['paymentMethodDetails']['expirationYear']}"
  puts "Cryptogram: #{decrypted_data['paymentMethodDetails']['cryptogram']}"
rescue GooglePayRuby::GooglePaymentDecryptionError => e
  puts "Decryption failed: #{e.message}"
end
```

### Key Rotation Support

Handle key rotation gracefully by providing multiple private keys:

```ruby
context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [
    {
      identifier: 'current-key',
      private_key_pem: File.read('current_key.pem')
    },
    {
      identifier: 'previous-key',
      private_key_pem: File.read('previous_key.pem')
    }
  ]
)

# The library will try each key until decryption succeeds
decrypted_data = context.decrypt(token)
```

### Decrypted Data Structure

The decrypted payment data contains:

```ruby
{
  "gatewayMerchantId" => "your-gateway-merchant-id",
  "messageExpiration" => "1234567890123",
  "messageId" => "AH2Ejtc...",
  "paymentMethod" => "CARD",
  "paymentMethodDetails" => {
    "pan" => "4111111111111111",
    "expirationMonth" => 12,
    "expirationYear" => 2025,
    "authMethod" => "CRYPTOGRAM_3DS",
    "cryptogram" => "AAAAAA...",
    "eciIndicator" => "05"
  }
}
```

## Error Handling

The gem raises `GooglePayRuby::GooglePaymentDecryptionError` when decryption fails:

```ruby
begin
  decrypted_data = context.decrypt(token)
rescue GooglePayRuby::GooglePaymentDecryptionError => e
  # Access detailed error information
  puts e.message
  puts e.full_message  # Includes details from all attempted keys
  
  # Access individual errors
  e.errors.each do |error|
    puts "Merchant: #{error.merchant_identifier}"
    puts "Error: #{error.message}"
  end
end
```

## Development

After checking out the repo, run `bundle install` to install dependencies. Then, run `rake spec` to run the tests.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/better-payment/google-pay-ruby.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Credits

This Ruby implementation is based on the [Basis Theory google-pay-js](https://github.com/Basis-Theory/google-pay-js) library.

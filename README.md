# GooglePayRuby

A Ruby utility for securely decrypting Google Pay PaymentMethodTokens using the ECv2 protocol. This gem is inspired from [Basis Theory google-pay-js](https://github.com/Basis-Theory/google-pay-js) library.

## Features

- **ECv2 Signature Verification**: Full Google Pay ECv2 PaymentMethodToken signature verification per [Google Pay cryptography spec](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography)
- **Google Pay PaymentMethodToken Decryption**: Securely decrypt user-authorized Google Pay transaction tokens using easy-to-use interfaces
- **Message Expiration Verification**: Automatically verify that decrypted messages haven't expired
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

### Basic Example (with full verification)

```ruby
require 'google_pay_ruby'

# Load your private key (from file, KMS, secrets manager, etc.)
private_key_pem = File.read('path/to/your/private_key.pem')

# Create the decryption context with signature verification
context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [
    {
      identifier: 'my-merchant-identifier',  # Optional, for debugging
      private_key_pem: private_key_pem
    }
  ],
  recipient_id: 'gateway:your-gateway-id'  # or 'merchant:your-merchant-id'
)

# Get the token from Google Pay API response
token = {
  'protocolVersion' => 'ECv2',
  'signature' => '...',
  'intermediateSigningKey' => {
    'signedKey' => '{"keyValue":"...","keyExpiration":"..."}',
    'signatures' => ['...']
  },
  'signedMessage' => '{"encryptedMessage":"...","ephemeralPublicKey":"...","tag":"..."}'
}

# Decrypt the token (signature verification + expiration check happen automatically)
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
  ],
  recipient_id: 'gateway:your-gateway-id'
)

# The library will try each key until decryption succeeds
decrypted_data = context.decrypt(token)
```

### Configuration Options

```ruby
context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [...],
  recipient_id: 'gateway:your-gateway-id',   # Required when verify_signature is true
  root_signing_keys: nil,                     # Pre-fetched keys, or nil to fetch from Google
  test: false,                                # Use Google's test keys URL
  verify_signature: true,                     # Enable/disable signature verification
  verify_expiration: true                     # Enable/disable message expiration check
)
```

### Decryption Only (no verification)

To preserve v1 behavior without signature verification:

```ruby
context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [{ private_key_pem: private_key_pem }],
  verify_signature: false,
  verify_expiration: false
)
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

After checking out the repo, run `bundle install` to install dependencies. Then, run the tests:

```bash
ruby test/test_signature_verifier.rb
ruby test/test_context_with_verification.rb
ruby test/test_decrypt.rb
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/better-payment/google-pay-ruby.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Credits

This Ruby implementation is inspired from [Basis Theory google-pay-js](https://github.com/Basis-Theory/google-pay-js) library.

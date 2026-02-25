# GooglePayRuby

A Ruby utility for securely verifying and decrypting Google Pay PaymentMethodTokens using the ECv2 protocol. This gem implements the full [Google Pay payment data cryptography specification](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography) and is inspired from [Basis Theory google-pay-js](https://github.com/Basis-Theory/google-pay-js) library.

## Features

- **Full Google Pay ECv2 Compliance**: Implements all required verification and decryption steps per Google's specification
- **Signature Verification**: Fetches Google root signing keys and verifies the full signature chain (root → intermediate → message)
- **Intermediate Key Expiration Check**: Validates that the intermediate signing key hasn't expired
- **Message Expiration Check**: Validates that the decrypted message hasn't expired (`messageExpiration`)
- **Key Rotation Support**: Handle multiple private keys simultaneously to support seamless key rotation
- **Pure Ruby Implementation**: No external dependencies beyond OpenSSL and net/http (Ruby standard library)
- **ECv2 Protocol Support**: Implements Google Pay's ECv2 encryption protocol

### Google Pay Verification Steps

This library implements all required steps from the [Google Pay processor integration guide](https://developers.google.com/pay/api/processors/guides/implementation/overview):

1. **Fetch Google root signing keys** — from `keys.json` (production or test URL)
2. **Verify intermediate signing key signature** — against non-expired root signing keys
3. **Verify intermediate signing key expiration** — checks `keyExpiration`
4. **Verify message signature** — using the intermediate signing key
5. **Decrypt the payload** — ECIES-KEM with HKDF-SHA256 and AES-256-CTR
6. **Verify message expiration** — checks `messageExpiration` in decrypted contents

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

### Basic Example (with full signature verification)

```ruby
require 'google_pay_ruby'

# Load your private key (from file, KMS, secrets manager, etc.)
private_key_pem = File.read('path/to/your/private_key.pem')

# Create the decryption context with signature verification enabled (default)
context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [
    {
      identifier: 'my-merchant-identifier',  # Optional, for debugging
      private_key_pem: private_key_pem
    }
  ],
  recipient_id: 'merchant:12345'  # Required — your Google Pay merchant ID
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

# Decrypt the token (signature verification + decryption + expiration check)
begin
  decrypted_data = context.decrypt(token)

  puts "PAN: #{decrypted_data['paymentMethodDetails']['pan']}"
  puts "Expiration: #{decrypted_data['paymentMethodDetails']['expirationMonth']}/#{decrypted_data['paymentMethodDetails']['expirationYear']}"
  puts "Cryptogram: #{decrypted_data['paymentMethodDetails']['cryptogram']}"
rescue GooglePayRuby::GooglePaymentDecryptionError => e
  puts "Decryption failed: #{e.message}"
end
```

### Using Test Environment

For development/testing with Google's test keys:

```ruby
context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [{ private_key_pem: private_key_pem }],
  recipient_id: 'merchant:12345',
  test: true  # Uses Google's test keys URL
)
```

### Pre-fetching Root Signing Keys

For performance or caching, you can pre-fetch and supply root signing keys:

```ruby
# Fetch and cache keys (e.g. in Redis, Rails.cache, etc.)
root_keys = fetch_and_cache_google_root_keys

context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [{ private_key_pem: private_key_pem }],
  recipient_id: 'merchant:12345',
  root_signing_keys: root_keys  # Array of { 'keyValue' => '...', 'protocolVersion' => 'ECv2', 'keyExpiration' => '...' }
)
```

### Disabling Verification (not recommended for production)

```ruby
context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [{ private_key_pem: private_key_pem }],
  verify_signature: false,   # Skip signature verification
  verify_expiration: false   # Skip messageExpiration check
)
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
  recipient_id: 'merchant:12345'
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

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `merchants` | `Array<Hash>` | *required* | List of merchant configs with `:private_key_pem` and optional `:identifier` |
| `recipient_id` | `String` | *required** | Recipient ID for signature verification (e.g. `"merchant:12345"` or `"gateway:yourId"`) |
| `root_signing_keys` | `Array<Hash>` | `nil` | Pre-fetched Google root signing keys. If `nil`, fetched automatically from Google |
| `test` | `Boolean` | `false` | Use Google's test keys URL instead of production |
| `verify_signature` | `Boolean` | `true` | Enable/disable signature verification |
| `verify_expiration` | `Boolean` | `true` | Enable/disable messageExpiration check |

\* `recipient_id` is only required when `verify_signature` is `true`.

## Error Handling

The gem raises `GooglePayRuby::GooglePaymentDecryptionError` when verification or decryption fails:

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

After checking out the repo, run `bundle install` to install dependencies. Then run the tests:

```bash
ruby test/test_signature_verifier.rb
ruby test/test_context_with_verification.rb
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/better-payment/google-pay-ruby.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Credits

This Ruby implementation is inspired from [Basis Theory google-pay-js](https://github.com/Basis-Theory/google-pay-js) library.

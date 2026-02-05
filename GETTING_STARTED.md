# Getting Started with GooglePayRuby

## Quick Start

### 1. Installation

From the gem directory:

```bash
bundle install
```

To use in your application, add to your `Gemfile`:

```ruby
gem 'google_pay_ruby'
```

Or to install system-wide:

```bash
gem build google_pay_ruby.gemspec
gem install google_pay_ruby-1.0.0.gem
```

### 2. Basic Usage

```ruby
require 'google_pay_ruby'

# Load your private key
private_key = File.read('path/to/private_key.pem')

# Create decryption context
context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [
    {
      identifier: 'my-merchant-id',
      private_key_pem: private_key
    }
  ]
)

# Decrypt the token from Google Pay
token = {
  'protocolVersion' => 'ECv2',
  'signature' => '...',
  'signedMessage' => '...'
}

decrypted = context.decrypt(token)

# Access payment details
pan = decrypted['paymentMethodDetails']['pan']
expiry_month = decrypted['paymentMethodDetails']['expirationMonth']
expiry_year = decrypted['paymentMethodDetails']['expirationYear']
cryptogram = decrypted['paymentMethodDetails']['cryptogram']
```

### 3. Integration with Existing Code

Replace your current Google Pay decryption code:

```ruby
context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [{ private_key_pem: private_key }]
)
decrypted = context.decrypt(token)
```

### 4. Key Benefits

**No external dependencies** - Uses Ruby's built-in OpenSSL  
**Key rotation support** - Handle multiple keys seamlessly  
**Pure Ruby** - No native extensions required  
**Comprehensive error handling** - Detailed error messages for debugging  

### 5. Testing

Run the included test with your actual token:

```bash
ruby test/test_decrypt.rb
```

Expected output:
```
Decryption successful!
PAN: 5204240250197840
Expiration: 12/2031
Auth Method: CRYPTOGRAM_3DS
Cryptogram: ALnt+yWSJdXBACMLLWMNGgADFA==
```

### 6. Examples

See `examples/basic_usage.rb` for more examples including:
- Single key decryption
- Key rotation with multiple keys
- Error handling patterns

### 7. API Reference

#### GooglePaymentMethodTokenContext

**Constructor:**
```ruby
new(merchants: Array<Hash>)
```

Merchant hash structure:
- `identifier` (optional): String identifier for debugging
- `private_key_pem`: String containing PEM-formatted EC private key

**Methods:**
- `decrypt(token)`: Decrypts a Google Pay token and returns payment details

#### GooglePaymentDecryptionError

**Attributes:**
- `message`: Error description
- `errors`: Array of individual decryption attempt errors

**Methods:**
- `full_message`: Detailed error message including all attempts

### 8. Troubleshooting

**"No merchant configuration provided"**
- Ensure you pass at least one merchant in the merchants array

**"Unsupported decryption for protocol version"**
- Only ECv2 protocol is supported
- Check that token['protocolVersion'] == 'ECv2'

**"Tag is not a valid MAC"**
- Wrong private key
- Token may be corrupted or tampered with

**"Failed to decrypt payment data"**
- None of the provided private keys could decrypt the token
- Check that keys match what's registered with Google
- Verify token is for the correct merchant/gateway

### 9. Production Considerations

1. **Secure Key Storage**: Never commit private keys to version control
2. **Key Rotation**: Maintain 2-3 keys during rotation periods
3. **Error Monitoring**: Log decryption failures for investigation
4. **PCI Compliance**: Ensure proper handling of decrypted PANs
5. **Performance**: Cache the context object, don't recreate per request

### 10. Next Steps

- Review the full API documentation in README.md
- Check examples/ directory for more usage patterns
- Integrate into your payment processing flow
- Set up key rotation procedures
- Configure monitoring and alerting

## Support

For issues or questions about the gem:
- Check CHANGELOG.md for version changes
- Review README.md for complete documentation
- See examples/ for usage patterns

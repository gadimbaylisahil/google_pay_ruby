# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-06-18

### Added
- **Signature Verification**: Full Google Pay ECv2 PaymentMethodToken signature verification per [Google Pay cryptography spec](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography)
  - Fetch Google root signing keys from production or test URLs
  - Verify intermediate signing key signature against non-expired root keys
  - Verify intermediate signing key expiration
  - Verify message signature using intermediate signing key
- **Message Expiration Check**: Verify `messageExpiration` field after decryption
- New `SignatureVerifier` class encapsulating all verification logic
- New initialization options for `GooglePaymentMethodTokenContext`:
  - `:recipient_id` — required when signature verification is enabled (e.g. `"gateway:<gatewayId>"` or `"merchant:<merchantId>"`)
  - `:root_signing_keys` — optional pre-fetched root keys (fetched automatically if nil)
  - `:test` — use Google's test keys URL (default: false)
  - `:verify_signature` — enable/disable signature verification (default: true)
  - `:verify_expiration` — enable/disable message expiration check (default: true)

### Breaking Changes
- `GooglePaymentMethodTokenContext.new` now requires `:recipient_id` by default (signature verification is enabled by default)
- To preserve v1 behavior, pass `verify_signature: false, verify_expiration: false`

## [1.0.1] - 2026-02-05

### Added

- Updated gemspec

## [1.0.0] - 2026-02-05

### Added
- Initial release
- ECv2 protocol support for Google Pay token decryption
- Multiple merchant key support for key rotation
- Pure Ruby implementation using OpenSSL
- Comprehensive error handling with detailed error messages
- Support for both string and symbol keys in token hashes

### Features
- `GooglePaymentMethodTokenContext` class for managing decryption context
- `EcV2DecryptionStrategy` class implementing ECv2 decryption algorithm
- `GooglePaymentDecryptionError` exception class with detailed error tracking
- ECDH shared secret computation
- HKDF key derivation
- HMAC verification
- AES-256-CTR decryption

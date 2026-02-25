# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-25

### Added
- **Signature Verification** (`SignatureVerifier` class): Full Google Pay ECv2 signature chain verification
  - Fetch Google root signing keys from production or test URLs
  - Verify intermediate signing key signature against non-expired root keys
  - Verify intermediate signing key expiration (`keyExpiration`)
  - Verify message signature using the intermediate signing key
  - Correct signed string construction with length-prefixed concatenation per Google spec
- **Message Expiration Check**: Validates `messageExpiration` in decrypted contents
- **New configuration options**: `recipient_id`, `root_signing_keys`, `test`, `verify_signature`, `verify_expiration`
- Comprehensive test suite for signature verification and full integration flow

### Changed
- **BREAKING**: `GooglePaymentMethodTokenContext.new` now requires `:recipient_id` option (unless `verify_signature: false`)
- Signature verification is enabled by default — tokens are fully verified before decryption
- Message expiration check is enabled by default after decryption

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

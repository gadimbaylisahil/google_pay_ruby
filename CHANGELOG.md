# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

#!/usr/bin/env ruby
# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/google_pay_ruby'
require 'json'
require 'openssl'
require 'base64'

class TestSignatureVerifier < Minitest::Test
  def setup
    # Generate a root signing key pair (simulates Google's root key)
    @root_key = OpenSSL::PKey::EC.generate('prime256v1')
    @root_key_value_b64 = Base64.strict_encode64(@root_key.public_to_der)

    # Generate an intermediate signing key pair
    @intermediate_key = OpenSSL::PKey::EC.generate('prime256v1')
    @intermediate_key_value_b64 = Base64.strict_encode64(@intermediate_key.public_to_der)

    @recipient_id = 'merchant:12345'
  end

  # Helper: build signed_key JSON string
  def build_signed_key(key_value_b64: @intermediate_key_value_b64, key_expiration: future_ms)
    JSON.generate({
      'keyValue' => key_value_b64,
      'keyExpiration' => key_expiration.to_s
    })
  end

  # Helper: sign the intermediate key with the root key
  def sign_intermediate_key(signed_key_json, signing_key: @root_key)
    signed_bytes = build_signed_bytes_for_intermediate_key(signed_key_json)
    digest = OpenSSL::Digest::SHA256.digest(signed_bytes)
    sig = signing_key.dsa_sign_asn1(digest)
    Base64.strict_encode64(sig)
  end

  # Helper: sign the message with the intermediate key
  def sign_message(signed_message, signing_key: @intermediate_key)
    signed_bytes = build_signed_bytes_for_message(signed_message)
    digest = OpenSSL::Digest::SHA256.digest(signed_bytes)
    sig = signing_key.dsa_sign_asn1(digest)
    Base64.strict_encode64(sig)
  end

  # Helper: build signed bytes for intermediate key (mirrors SignatureVerifier logic)
  def build_signed_bytes_for_intermediate_key(signed_key_json)
    sender = 'Google'.encode('UTF-8')
    protocol = 'ECv2'.encode('UTF-8')
    key_bytes = signed_key_json.encode('UTF-8')

    [sender.bytesize].pack('V') + sender +
      [protocol.bytesize].pack('V') + protocol +
      [key_bytes.bytesize].pack('V') + key_bytes
  end

  # Helper: build signed bytes for message (mirrors SignatureVerifier logic)
  def build_signed_bytes_for_message(signed_message)
    sender = 'Google'.encode('UTF-8')
    recipient = @recipient_id.encode('UTF-8')
    protocol = 'ECv2'.encode('UTF-8')
    msg_bytes = signed_message.encode('UTF-8')

    [sender.bytesize].pack('V') + sender +
      [recipient.bytesize].pack('V') + recipient +
      [protocol.bytesize].pack('V') + protocol +
      [msg_bytes.bytesize].pack('V') + msg_bytes
  end

  def future_ms
    ((Time.now.to_f + 3600) * 1000).to_i
  end

  def past_ms
    ((Time.now.to_f - 3600) * 1000).to_i
  end

  # Helper: build a valid token
  def build_valid_token
    signed_key_json = build_signed_key
    signed_message = '{"encryptedMessage":"abc","ephemeralPublicKey":"def","tag":"ghi"}'
    intermediate_sig = sign_intermediate_key(signed_key_json)
    message_sig = sign_message(signed_message)

    {
      'protocolVersion' => 'ECv2',
      'signature' => message_sig,
      'intermediateSigningKey' => {
        'signedKey' => signed_key_json,
        'signatures' => [intermediate_sig]
      },
      'signedMessage' => signed_message
    }
  end

  def build_root_keys(key: @root_key, expiration: future_ms)
    [{
      'keyValue' => Base64.strict_encode64(key.public_to_der),
      'protocolVersion' => 'ECv2',
      'keyExpiration' => expiration.to_s
    }]
  end

  # === Tests ===

  def test_valid_token_passes_verification
    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: build_root_keys,
      recipient_id: @recipient_id
    )

    # Should not raise
    verifier.verify!(build_valid_token)
  end

  def test_rejects_non_ecv2_protocol
    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: build_root_keys,
      recipient_id: @recipient_id
    )

    token = build_valid_token.merge('protocolVersion' => 'ECv1')

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(token)
    end
    assert_match(/Unsupported protocol version/, error.message)
  end

  def test_rejects_missing_intermediate_signing_key
    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: build_root_keys,
      recipient_id: @recipient_id
    )

    token = build_valid_token.tap { |t| t.delete('intermediateSigningKey') }

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(token)
    end
    assert_match(/Missing intermediateSigningKey/, error.message)
  end

  def test_rejects_expired_intermediate_key
    signed_key_json = build_signed_key(key_expiration: past_ms)
    signed_message = '{"encryptedMessage":"abc","ephemeralPublicKey":"def","tag":"ghi"}'
    intermediate_sig = sign_intermediate_key(signed_key_json)
    message_sig = sign_message(signed_message)

    token = {
      'protocolVersion' => 'ECv2',
      'signature' => message_sig,
      'intermediateSigningKey' => {
        'signedKey' => signed_key_json,
        'signatures' => [intermediate_sig]
      },
      'signedMessage' => signed_message
    }

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: build_root_keys,
      recipient_id: @recipient_id
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(token)
    end
    assert_match(/expired/, error.message)
  end

  def test_rejects_invalid_intermediate_key_signature
    # Sign the intermediate key with a different (wrong) key
    wrong_key = OpenSSL::PKey::EC.generate('prime256v1')
    signed_key_json = build_signed_key
    wrong_sig = sign_intermediate_key(signed_key_json, signing_key: wrong_key)

    signed_message = '{"encryptedMessage":"abc","ephemeralPublicKey":"def","tag":"ghi"}'
    message_sig = sign_message(signed_message)

    token = {
      'protocolVersion' => 'ECv2',
      'signature' => message_sig,
      'intermediateSigningKey' => {
        'signedKey' => signed_key_json,
        'signatures' => [wrong_sig]
      },
      'signedMessage' => signed_message
    }

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: build_root_keys,
      recipient_id: @recipient_id
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(token)
    end
    assert_match(/Could not verify intermediate signing key/, error.message)
  end

  def test_rejects_invalid_message_signature
    signed_key_json = build_signed_key
    signed_message = '{"encryptedMessage":"abc","ephemeralPublicKey":"def","tag":"ghi"}'
    intermediate_sig = sign_intermediate_key(signed_key_json)

    # Sign message with a different (wrong) key
    wrong_key = OpenSSL::PKey::EC.generate('prime256v1')
    wrong_message_sig = sign_message(signed_message, signing_key: wrong_key)

    token = {
      'protocolVersion' => 'ECv2',
      'signature' => wrong_message_sig,
      'intermediateSigningKey' => {
        'signedKey' => signed_key_json,
        'signatures' => [intermediate_sig]
      },
      'signedMessage' => signed_message
    }

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: build_root_keys,
      recipient_id: @recipient_id
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(token)
    end
    assert_match(/Message signature verification failed/, error.message)
  end

  def test_skips_expired_root_keys_and_uses_valid_one
    expired_root_key = OpenSSL::PKey::EC.generate('prime256v1')
    expired_root_keys = [{
      'keyValue' => Base64.strict_encode64(expired_root_key.public_to_der),
      'protocolVersion' => 'ECv2',
      'keyExpiration' => past_ms.to_s
    }]

    # Combine expired + valid root keys
    all_root_keys = expired_root_keys + build_root_keys

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: all_root_keys,
      recipient_id: @recipient_id
    )

    # Should succeed because the valid root key is present
    verifier.verify!(build_valid_token)
  end

  def test_rejects_when_all_root_keys_expired
    expired_root_keys = [{
      'keyValue' => @root_key_value_b64,
      'protocolVersion' => 'ECv2',
      'keyExpiration' => past_ms.to_s
    }]

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: expired_root_keys,
      recipient_id: @recipient_id
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(build_valid_token)
    end
    assert_match(/No non-expired/, error.message)
  end

  def test_multiple_signatures_with_one_valid
    # First signature is from a random key (invalid), second is from actual root key
    random_key = OpenSSL::PKey::EC.generate('prime256v1')
    signed_key_json = build_signed_key
    signed_message = '{"encryptedMessage":"abc","ephemeralPublicKey":"def","tag":"ghi"}'

    bad_sig = sign_intermediate_key(signed_key_json, signing_key: random_key)
    good_sig = sign_intermediate_key(signed_key_json)
    message_sig = sign_message(signed_message)

    token = {
      'protocolVersion' => 'ECv2',
      'signature' => message_sig,
      'intermediateSigningKey' => {
        'signedKey' => signed_key_json,
        'signatures' => [bad_sig, good_sig]
      },
      'signedMessage' => signed_message
    }

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: build_root_keys,
      recipient_id: @recipient_id
    )

    # Should pass because at least one signature is valid
    verifier.verify!(token)
  end

  def test_signed_bytes_format_for_intermediate_key
    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: build_root_keys,
      recipient_id: @recipient_id
    )

    signed_key = '{"keyValue":"abc","keyExpiration":"123"}'
    signed_bytes = verifier.send(:build_signed_bytes_for_intermediate_key, signed_key)

    # Verify format: 4-byte LE length || "Google" || 4-byte LE length || "ECv2" || 4-byte LE length || signed_key
    expected = "\x06\x00\x00\x00Google\x04\x00\x00\x00ECv2"
    expected += [signed_key.bytesize].pack('V') + signed_key
    assert_equal expected, signed_bytes
  end

  def test_signed_bytes_format_for_message
    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: build_root_keys,
      recipient_id: @recipient_id
    )

    signed_message = '{"tag":"abc"}'
    signed_bytes = verifier.send(:build_signed_bytes_for_message, signed_message)

    # Verify format: 4-byte LE length || "Google" || 4-byte LE length || recipient_id || 4-byte LE length || "ECv2" || 4-byte LE length || signed_message
    expected = "\x06\x00\x00\x00Google"
    expected += [14].pack('V') + 'merchant:12345'
    expected += "\x04\x00\x00\x00ECv2"
    expected += [signed_message.bytesize].pack('V') + signed_message
    assert_equal expected, signed_bytes
  end
end

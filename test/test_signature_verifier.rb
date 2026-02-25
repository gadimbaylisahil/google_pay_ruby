#!/usr/bin/env ruby
# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/google_pay_ruby'
require 'json'
require 'openssl'
require 'base64'
require 'time'

class TestSignatureVerifier < Minitest::Test
  def setup
    # Generate a root signing key pair (simulating Google's root key)
    @root_key = OpenSSL::PKey::EC.generate('prime256v1')
    @root_public_key_der = @root_key.public_to_der
    @root_public_key_b64 = Base64.strict_encode64(@root_public_key_der)

    # Generate an intermediate signing key pair
    @intermediate_key = OpenSSL::PKey::EC.generate('prime256v1')
    @intermediate_public_key_der = @intermediate_key.public_to_der
    @intermediate_public_key_b64 = Base64.strict_encode64(@intermediate_public_key_der)

    # Generate a merchant encryption key pair
    @merchant_key = OpenSSL::PKey::EC.generate('prime256v1')
    @merchant_private_key_pem = @merchant_key.to_pem

    @recipient_id = 'merchant:test-merchant-12345'

    # Key expiration: 1 hour from now in milliseconds
    @key_expiration = ((Time.now.to_f + 3600) * 1000).to_i.to_s
  end

  def test_verify_with_valid_token
    token = build_valid_token
    root_signing_keys = [build_root_key_entry]

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: root_signing_keys,
      recipient_id: @recipient_id
    )

    # Should not raise
    verifier.verify!(token)
  end

  def test_verify_rejects_expired_intermediate_key
    expired_expiration = ((Time.now.to_f - 3600) * 1000).to_i.to_s
    token = build_valid_token(key_expiration: expired_expiration)
    root_signing_keys = [build_root_key_entry]

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: root_signing_keys,
      recipient_id: @recipient_id
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(token)
    end
    assert_match(/expired/, error.message)
  end

  def test_verify_rejects_invalid_intermediate_key_signature
    token = build_valid_token

    # Use a different root key that didn't sign the intermediate key
    different_root_key = OpenSSL::PKey::EC.generate('prime256v1')
    different_root_key_b64 = Base64.strict_encode64(different_root_key.public_to_der)

    root_signing_keys = [{
      'keyValue' => different_root_key_b64,
      'protocolVersion' => 'ECv2',
      'keyExpiration' => @key_expiration
    }]

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: root_signing_keys,
      recipient_id: @recipient_id
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(token)
    end
    assert_match(/Could not verify intermediate signing key/, error.message)
  end

  def test_verify_rejects_invalid_message_signature
    signed_key_json = JSON.generate({
      'keyValue' => @intermediate_public_key_b64,
      'keyExpiration' => @key_expiration
    })

    # Sign intermediate key with root key (valid)
    intermediate_signed_string = build_signed_string_for_intermediate_key(signed_key_json)
    intermediate_signature = sign_with_key(@root_key, intermediate_signed_string)

    # Build a signed message
    signed_message = '{"encryptedMessage":"abc","ephemeralPublicKey":"def","tag":"ghi"}'

    # Sign with a DIFFERENT key (not the intermediate key) - making it invalid
    wrong_key = OpenSSL::PKey::EC.generate('prime256v1')
    message_signed_string = build_signed_string_for_message(signed_message)
    message_signature = sign_with_key(wrong_key, message_signed_string)

    token = {
      'protocolVersion' => 'ECv2',
      'signature' => Base64.strict_encode64(message_signature),
      'intermediateSigningKey' => {
        'signedKey' => signed_key_json,
        'signatures' => [Base64.strict_encode64(intermediate_signature)]
      },
      'signedMessage' => signed_message
    }

    root_signing_keys = [build_root_key_entry]

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: root_signing_keys,
      recipient_id: @recipient_id
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(token)
    end
    assert_match(/Message signature verification failed/, error.message)
  end

  def test_verify_rejects_all_expired_root_keys
    expired_root_key_entry = {
      'keyValue' => @root_public_key_b64,
      'protocolVersion' => 'ECv2',
      'keyExpiration' => ((Time.now.to_f - 3600) * 1000).to_i.to_s
    }

    token = build_valid_token
    root_signing_keys = [expired_root_key_entry]

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: root_signing_keys,
      recipient_id: @recipient_id
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(token)
    end
    assert_match(/No non-expired Google root signing keys/, error.message)
  end

  def test_verify_rejects_unsupported_protocol
    token = { 'protocolVersion' => 'ECv1' }

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: [build_root_key_entry],
      recipient_id: @recipient_id
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(token)
    end
    assert_match(/Unsupported protocol version/, error.message)
  end

  def test_verify_rejects_missing_intermediate_signing_key
    token = {
      'protocolVersion' => 'ECv2',
      'signature' => 'abc',
      'signedMessage' => 'def'
    }

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: [build_root_key_entry],
      recipient_id: @recipient_id
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      verifier.verify!(token)
    end
    assert_match(/Missing intermediateSigningKey/, error.message)
  end

  def test_verify_works_with_multiple_root_keys
    # First root key is wrong, second is correct
    different_root_key = OpenSSL::PKey::EC.generate('prime256v1')
    different_root_key_b64 = Base64.strict_encode64(different_root_key.public_to_der)

    root_signing_keys = [
      {
        'keyValue' => different_root_key_b64,
        'protocolVersion' => 'ECv2',
        'keyExpiration' => @key_expiration
      },
      build_root_key_entry
    ]

    token = build_valid_token

    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: root_signing_keys,
      recipient_id: @recipient_id
    )

    # Should not raise - second root key should work
    verifier.verify!(token)
  end

  def test_signed_string_for_intermediate_key_format
    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: [build_root_key_entry],
      recipient_id: @recipient_id
    )

    signed_key = '{"keyValue":"abc","keyExpiration":"123"}'
    result = verifier.send(:build_signed_string_for_intermediate_key, signed_key)

    # Verify format: length(4 bytes LE) || "Google" || length(4 bytes LE) || "ECv2" || length(4 bytes LE) || signed_key
    expected = [6].pack('V') + 'Google' +
               [4].pack('V') + 'ECv2' +
               [signed_key.bytesize].pack('V') + signed_key

    assert_equal expected, result
  end

  def test_signed_string_for_message_format
    verifier = GooglePayRuby::SignatureVerifier.new(
      root_signing_keys: [build_root_key_entry],
      recipient_id: @recipient_id
    )

    signed_message = '{"tag":"abc","ephemeralPublicKey":"def","encryptedMessage":"ghi"}'
    result = verifier.send(:build_signed_string_for_message, signed_message)

    expected = [6].pack('V') + 'Google' +
               [@recipient_id.bytesize].pack('V') + @recipient_id +
               [4].pack('V') + 'ECv2' +
               [signed_message.bytesize].pack('V') + signed_message

    assert_equal expected, result
  end

  private

  def build_root_key_entry
    {
      'keyValue' => @root_public_key_b64,
      'protocolVersion' => 'ECv2',
      'keyExpiration' => @key_expiration
    }
  end

  def build_valid_token(key_expiration: nil)
    key_exp = key_expiration || @key_expiration

    signed_key_json = JSON.generate({
      'keyValue' => @intermediate_public_key_b64,
      'keyExpiration' => key_exp
    })

    # Sign the intermediate key with the root key
    intermediate_signed_string = build_signed_string_for_intermediate_key(signed_key_json)
    intermediate_signature = sign_with_key(@root_key, intermediate_signed_string)

    # Build a signed message (content doesn't matter for signature verification tests)
    signed_message = '{"encryptedMessage":"abc","ephemeralPublicKey":"def","tag":"ghi"}'

    # Sign the message with the intermediate key
    message_signed_string = build_signed_string_for_message(signed_message)
    message_signature = sign_with_key(@intermediate_key, message_signed_string)

    {
      'protocolVersion' => 'ECv2',
      'signature' => Base64.strict_encode64(message_signature),
      'intermediateSigningKey' => {
        'signedKey' => signed_key_json,
        'signatures' => [Base64.strict_encode64(intermediate_signature)]
      },
      'signedMessage' => signed_message
    }
  end

  def build_signed_string_for_intermediate_key(signed_key)
    sender_id = 'Google'
    protocol_version = 'ECv2'

    [sender_id.bytesize].pack('V') + sender_id +
      [protocol_version.bytesize].pack('V') + protocol_version +
      [signed_key.bytesize].pack('V') + signed_key
  end

  def build_signed_string_for_message(signed_message)
    sender_id = 'Google'
    protocol_version = 'ECv2'

    [sender_id.bytesize].pack('V') + sender_id +
      [@recipient_id.bytesize].pack('V') + @recipient_id +
      [protocol_version.bytesize].pack('V') + protocol_version +
      [signed_message.bytesize].pack('V') + signed_message
  end

  def sign_with_key(ec_key, data)
    digest = OpenSSL::Digest::SHA256.digest(data)
    ec_key.dsa_sign_asn1(digest)
  end
end

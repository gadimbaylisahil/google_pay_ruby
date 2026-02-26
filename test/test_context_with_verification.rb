#!/usr/bin/env ruby
# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/google_pay_ruby'
require 'json'
require 'openssl'
require 'base64'

class TestContextWithVerification < Minitest::Test
  def test_requires_recipient_id_when_signature_verification_enabled
    error = assert_raises(ArgumentError) do
      GooglePayRuby::GooglePaymentMethodTokenContext.new(
        merchants: [{ private_key_pem: 'fake-key' }]
      )
    end
    assert_match(/:recipient_id is required/, error.message)
  end

  def test_allows_nil_recipient_id_when_verification_disabled
    # Should not raise
    context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
      merchants: [{ private_key_pem: 'fake-key' }],
      verify_signature: false,
      verify_expiration: false
    )
    assert_instance_of GooglePayRuby::GooglePaymentMethodTokenContext, context
  end

  def test_decrypt_without_verification_works
    # Generate a merchant key pair
    merchant_key = OpenSSL::PKey::EC.generate('prime256v1')
    merchant_pem = merchant_key.to_pem

    # Build an encrypted signed message
    signed_message_json = build_encrypted_signed_message(merchant_key)

    token = {
      'protocolVersion' => 'ECv2',
      'signature' => 'unused-because-verification-disabled',
      'intermediateSigningKey' => {
        'signedKey' => '{"keyValue":"unused","keyExpiration":"9999999999999"}',
        'signatures' => ['unused']
      },
      'signedMessage' => signed_message_json
    }

    context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
      merchants: [{ identifier: 'test', private_key_pem: merchant_pem }],
      verify_signature: false,
      verify_expiration: false
    )

    result = context.decrypt(token)
    assert_equal 'CARD', result['paymentMethod']
    assert_equal '4111111111111111', result['paymentMethodDetails']['pan']
  end

  def test_expired_message_raises_error
    merchant_key = OpenSSL::PKey::EC.generate('prime256v1')
    merchant_pem = merchant_key.to_pem

    # Build encrypted message with expired messageExpiration
    plaintext = {
      'messageExpiration' => '1000000000000', # far in the past
      'paymentMethod' => 'CARD',
      'paymentMethodDetails' => { 'pan' => '4111111111111111' }
    }
    signed_message_json = build_encrypted_signed_message(merchant_key, plaintext: plaintext)

    token = {
      'protocolVersion' => 'ECv2',
      'signedMessage' => signed_message_json
    }

    context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
      merchants: [{ identifier: 'test', private_key_pem: merchant_pem }],
      verify_signature: false,
      verify_expiration: true
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      context.decrypt(token)
    end
    assert_match(/expired/, error.message)
  end

  def test_full_verification_and_decryption_flow
    # === Set up the full signing + encryption chain ===

    # 1. Root signing key (simulates Google's root key)
    root_key = OpenSSL::PKey::EC.generate('prime256v1')
    root_keys = [{
      'keyValue' => Base64.strict_encode64(root_key.public_to_der),
      'protocolVersion' => 'ECv2',
      'keyExpiration' => future_ms.to_s
    }]

    # 2. Intermediate signing key
    intermediate_key = OpenSSL::PKey::EC.generate('prime256v1')
    signed_key_json = JSON.generate({
      'keyValue' => Base64.strict_encode64(intermediate_key.public_to_der),
      'keyExpiration' => future_ms.to_s
    })

    # 3. Sign the intermediate key with the root key
    intermediate_signed_bytes = build_signed_bytes_for_intermediate_key(signed_key_json)
    intermediate_sig = Base64.strict_encode64(
      root_key.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(intermediate_signed_bytes))
    )

    # 4. Merchant encryption key
    merchant_key = OpenSSL::PKey::EC.generate('prime256v1')
    merchant_pem = merchant_key.to_pem

    # 5. Build the encrypted payload
    plaintext = {
      'messageExpiration' => future_ms.to_s,
      'gatewayMerchantId' => 'test-merchant',
      'paymentMethod' => 'CARD',
      'paymentMethodDetails' => {
        'pan' => '4111111111111111',
        'expirationMonth' => 12,
        'expirationYear' => 2030,
        'authMethod' => 'CRYPTOGRAM_3DS',
        'cryptogram' => 'AAAAAAAAAAAAA'
      }
    }
    signed_message_json = build_encrypted_signed_message(merchant_key, plaintext: plaintext)

    # 6. Sign the message with the intermediate key
    recipient_id = 'gateway:test-gateway'
    message_signed_bytes = build_signed_bytes_for_message(signed_message_json, recipient_id)
    message_sig = Base64.strict_encode64(
      intermediate_key.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(message_signed_bytes))
    )

    # 7. Assemble the full token
    token = {
      'protocolVersion' => 'ECv2',
      'signature' => message_sig,
      'intermediateSigningKey' => {
        'signedKey' => signed_key_json,
        'signatures' => [intermediate_sig]
      },
      'signedMessage' => signed_message_json
    }

    # 8. Decrypt with full verification
    context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
      merchants: [{ identifier: 'test', private_key_pem: merchant_pem }],
      recipient_id: recipient_id,
      root_signing_keys: root_keys,
      verify_signature: true,
      verify_expiration: true
    )

    result = context.decrypt(token)
    assert_equal 'CARD', result['paymentMethod']
    assert_equal '4111111111111111', result['paymentMethodDetails']['pan']
    assert_equal 'test-merchant', result['gatewayMerchantId']
  end

  def test_full_flow_fails_with_wrong_recipient_id
    root_key = OpenSSL::PKey::EC.generate('prime256v1')
    root_keys = [{
      'keyValue' => Base64.strict_encode64(root_key.public_to_der),
      'protocolVersion' => 'ECv2',
      'keyExpiration' => future_ms.to_s
    }]

    intermediate_key = OpenSSL::PKey::EC.generate('prime256v1')
    signed_key_json = JSON.generate({
      'keyValue' => Base64.strict_encode64(intermediate_key.public_to_der),
      'keyExpiration' => future_ms.to_s
    })

    intermediate_signed_bytes = build_signed_bytes_for_intermediate_key(signed_key_json)
    intermediate_sig = Base64.strict_encode64(
      root_key.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(intermediate_signed_bytes))
    )

    merchant_key = OpenSSL::PKey::EC.generate('prime256v1')
    merchant_pem = merchant_key.to_pem
    signed_message_json = build_encrypted_signed_message(merchant_key)

    # Sign with "gateway:correct-id"
    correct_recipient_id = 'gateway:correct-id'
    message_signed_bytes = build_signed_bytes_for_message(signed_message_json, correct_recipient_id)
    message_sig = Base64.strict_encode64(
      intermediate_key.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(message_signed_bytes))
    )

    token = {
      'protocolVersion' => 'ECv2',
      'signature' => message_sig,
      'intermediateSigningKey' => {
        'signedKey' => signed_key_json,
        'signatures' => [intermediate_sig]
      },
      'signedMessage' => signed_message_json
    }

    # Verify with a WRONG recipient_id — message signature check should fail
    context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
      merchants: [{ identifier: 'test', private_key_pem: merchant_pem }],
      recipient_id: 'gateway:wrong-id',
      root_signing_keys: root_keys
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      context.decrypt(token)
    end
    assert_match(/Message signature verification failed/, error.message)
  end

  private

  def future_ms
    ((Time.now.to_f + 3600) * 1000).to_i
  end

  # Build an encrypted signedMessage JSON string from a plaintext payload,
  # using ECIES-KEM with the given merchant's public key.
  def build_encrypted_signed_message(merchant_key, plaintext: nil)
    plaintext ||= {
      'messageExpiration' => future_ms.to_s,
      'paymentMethod' => 'CARD',
      'paymentMethodDetails' => { 'pan' => '4111111111111111' }
    }

    plaintext_json = JSON.generate(plaintext)

    # Generate ephemeral key pair
    ephemeral_key = OpenSSL::PKey::EC.generate('prime256v1')
    ephemeral_public_key_bytes = ephemeral_key.public_key.to_octet_string(:uncompressed)

    # ECDH shared secret
    shared_secret = ephemeral_key.dh_compute_key(merchant_key.public_key)

    # HKDF
    ikm = ephemeral_public_key_bytes + shared_secret
    salt = "\x00" * 32
    prk = OpenSSL::HMAC.digest('SHA256', salt, ikm)

    t = ''
    okm = ''
    counter = 1
    while okm.length < 64
      t = OpenSSL::HMAC.digest('SHA256', prk, t + 'Google' + [counter].pack('C'))
      okm += t
      counter += 1
    end
    derived_key = okm[0...64]

    symmetric_key = derived_key[0...32]
    mac_key = derived_key[32...64]

    # AES-256-CTR encrypt
    cipher = OpenSSL::Cipher.new('AES-256-CTR')
    cipher.encrypt
    cipher.key = symmetric_key
    cipher.iv = "\x00" * 16
    encrypted = cipher.update(plaintext_json) + cipher.final

    # HMAC tag
    tag = OpenSSL::HMAC.digest('SHA256', mac_key, encrypted)

    JSON.generate({
      'encryptedMessage' => Base64.strict_encode64(encrypted),
      'ephemeralPublicKey' => Base64.strict_encode64(ephemeral_public_key_bytes),
      'tag' => Base64.strict_encode64(tag)
    })
  end

  def build_signed_bytes_for_intermediate_key(signed_key_json)
    sender = 'Google'.encode('UTF-8')
    protocol = 'ECv2'.encode('UTF-8')
    key_bytes = signed_key_json.encode('UTF-8')

    [sender.bytesize].pack('V') + sender +
      [protocol.bytesize].pack('V') + protocol +
      [key_bytes.bytesize].pack('V') + key_bytes
  end

  def build_signed_bytes_for_message(signed_message, recipient_id)
    sender = 'Google'.encode('UTF-8')
    recipient = recipient_id.encode('UTF-8')
    protocol = 'ECv2'.encode('UTF-8')
    msg_bytes = signed_message.encode('UTF-8')

    [sender.bytesize].pack('V') + sender +
      [recipient.bytesize].pack('V') + recipient +
      [protocol.bytesize].pack('V') + protocol +
      [msg_bytes.bytesize].pack('V') + msg_bytes
  end
end

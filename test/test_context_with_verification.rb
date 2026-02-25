#!/usr/bin/env ruby
# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/google_pay_ruby'
require 'json'
require 'openssl'
require 'base64'

class TestContextWithVerification < Minitest::Test
  def test_allows_nil_recipient_id_with_signature_verification_enabled
    # recipient_id is optional — message signature check (step 4) is skipped when nil
    context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
      merchants: [{ private_key_pem: 'fake-key' }]
    )
    assert_instance_of GooglePayRuby::GooglePaymentMethodTokenContext, context
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

  def test_decrypt_with_signature_verification_disabled
    # Generate a merchant key
    merchant_key = OpenSSL::PKey::EC.generate('prime256v1')

    # Build encrypted payload manually using EcV2DecryptionStrategy's expected format
    plaintext = JSON.generate({
      'messageExpiration' => ((Time.now.to_f + 3600) * 1000).to_i.to_s,
      'messageId' => 'test-msg-id',
      'paymentMethod' => 'CARD',
      'paymentMethodDetails' => {
        'pan' => '4111111111111111',
        'expirationMonth' => 12,
        'expirationYear' => 2030,
        'authMethod' => 'CRYPTOGRAM_3DS',
        'cryptogram' => 'AAAAAA=='
      }
    })

    encrypted_message = encrypt_for_ec_key(merchant_key, plaintext)

    token = {
      'protocolVersion' => 'ECv2',
      'signature' => 'unused-when-verification-disabled',
      'intermediateSigningKey' => {
        'signedKey' => '{"keyValue":"unused","keyExpiration":"9999999999999"}',
        'signatures' => ['unused']
      },
      'signedMessage' => JSON.generate(encrypted_message)
    }

    context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
      merchants: [{ private_key_pem: merchant_key.to_pem, identifier: 'test' }],
      verify_signature: false
    )

    decrypted = context.decrypt(token)
    assert_equal 'CARD', decrypted['paymentMethod']
    assert_equal '4111111111111111', decrypted['paymentMethodDetails']['pan']
  end

  def test_decrypt_rejects_expired_message
    merchant_key = OpenSSL::PKey::EC.generate('prime256v1')

    # Build encrypted payload with expired messageExpiration
    plaintext = JSON.generate({
      'messageExpiration' => ((Time.now.to_f - 3600) * 1000).to_i.to_s,
      'messageId' => 'test-msg-id',
      'paymentMethod' => 'CARD',
      'paymentMethodDetails' => {
        'pan' => '4111111111111111',
        'expirationMonth' => 12,
        'expirationYear' => 2030
      }
    })

    encrypted_message = encrypt_for_ec_key(merchant_key, plaintext)

    token = {
      'protocolVersion' => 'ECv2',
      'signature' => 'unused',
      'intermediateSigningKey' => {
        'signedKey' => '{"keyValue":"unused","keyExpiration":"9999999999999"}',
        'signatures' => ['unused']
      },
      'signedMessage' => JSON.generate(encrypted_message)
    }

    context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
      merchants: [{ private_key_pem: merchant_key.to_pem, identifier: 'test' }],
      verify_signature: false,
      verify_expiration: true
    )

    error = assert_raises(GooglePayRuby::GooglePaymentDecryptionError) do
      context.decrypt(token)
    end
    assert_match(/expired/, error.message)
  end

  def test_decrypt_allows_non_expired_message
    merchant_key = OpenSSL::PKey::EC.generate('prime256v1')

    # Build encrypted payload with future messageExpiration
    plaintext = JSON.generate({
      'messageExpiration' => ((Time.now.to_f + 3600) * 1000).to_i.to_s,
      'messageId' => 'test-msg-id',
      'paymentMethod' => 'CARD',
      'paymentMethodDetails' => {
        'pan' => '4111111111111111',
        'expirationMonth' => 12,
        'expirationYear' => 2030
      }
    })

    encrypted_message = encrypt_for_ec_key(merchant_key, plaintext)

    token = {
      'protocolVersion' => 'ECv2',
      'signature' => 'unused',
      'intermediateSigningKey' => {
        'signedKey' => '{"keyValue":"unused","keyExpiration":"9999999999999"}',
        'signatures' => ['unused']
      },
      'signedMessage' => JSON.generate(encrypted_message)
    }

    context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
      merchants: [{ private_key_pem: merchant_key.to_pem, identifier: 'test' }],
      verify_signature: false,
      verify_expiration: true
    )

    decrypted = context.decrypt(token)
    assert_equal 'CARD', decrypted['paymentMethod']
  end

  def test_full_flow_with_signature_verification
    # This test simulates the complete Google Pay token verification and decryption flow
    root_key = OpenSSL::PKey::EC.generate('prime256v1')
    intermediate_key = OpenSSL::PKey::EC.generate('prime256v1')
    merchant_key = OpenSSL::PKey::EC.generate('prime256v1')

    recipient_id = 'merchant:full-test-12345'
    key_expiration = ((Time.now.to_f + 3600) * 1000).to_i.to_s

    # Build encrypted payload
    plaintext = JSON.generate({
      'messageExpiration' => ((Time.now.to_f + 3600) * 1000).to_i.to_s,
      'messageId' => 'test-msg-id',
      'paymentMethod' => 'CARD',
      'paymentMethodDetails' => {
        'pan' => '4111111111111111',
        'expirationMonth' => 12,
        'expirationYear' => 2030,
        'authMethod' => 'CRYPTOGRAM_3DS',
        'cryptogram' => 'AAAAAA=='
      }
    })

    encrypted_message = encrypt_for_ec_key(merchant_key, plaintext)
    signed_message_json = JSON.generate(encrypted_message)

    # Build signed key
    intermediate_public_key_b64 = Base64.strict_encode64(intermediate_key.public_to_der)
    signed_key_json = JSON.generate({
      'keyValue' => intermediate_public_key_b64,
      'keyExpiration' => key_expiration
    })

    # Sign intermediate key
    intermediate_signed_string = build_signed_string_for_intermediate_key(signed_key_json)
    intermediate_signature = sign_with_key(root_key, intermediate_signed_string)

    # Sign message
    message_signed_string = build_signed_string_for_message(signed_message_json, recipient_id)
    message_signature = sign_with_key(intermediate_key, message_signed_string)

    token = {
      'protocolVersion' => 'ECv2',
      'signature' => Base64.strict_encode64(message_signature),
      'intermediateSigningKey' => {
        'signedKey' => signed_key_json,
        'signatures' => [Base64.strict_encode64(intermediate_signature)]
      },
      'signedMessage' => signed_message_json
    }

    root_signing_keys = [{
      'keyValue' => Base64.strict_encode64(root_key.public_to_der),
      'protocolVersion' => 'ECv2',
      'keyExpiration' => key_expiration
    }]

    context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
      merchants: [{ private_key_pem: merchant_key.to_pem, identifier: 'test-merchant' }],
      recipient_id: recipient_id,
      root_signing_keys: root_signing_keys,
      verify_signature: true,
      verify_expiration: true
    )

    decrypted = context.decrypt(token)
    assert_equal 'CARD', decrypted['paymentMethod']
    assert_equal '4111111111111111', decrypted['paymentMethodDetails']['pan']
    assert_equal 'CRYPTOGRAM_3DS', decrypted['paymentMethodDetails']['authMethod']
  end

  private

  # Encrypts plaintext for a given EC key using the same scheme as Google Pay ECv2:
  # ECIES-KEM with HKDF-SHA256 and AES-256-CTR
  def encrypt_for_ec_key(recipient_key, plaintext)
    # Generate ephemeral key pair
    ephemeral_key = OpenSSL::PKey::EC.generate('prime256v1')
    ephemeral_public_key_bytes = ephemeral_key.public_key.to_octet_string(:uncompressed)
    ephemeral_public_key_b64 = Base64.strict_encode64(ephemeral_public_key_bytes)

    # Compute shared secret
    shared_secret = ephemeral_key.dh_compute_key(recipient_key.public_key)
    shared_secret_hex = shared_secret.unpack1('H*')

    # Derive keys using HKDF
    info = ephemeral_public_key_bytes + [shared_secret_hex].pack('H*')
    salt = "\x00" * 32
    prk = OpenSSL::HMAC.digest('SHA256', salt, info)

    t = ''
    okm = ''
    counter = 1
    while okm.length < 64
      t = OpenSSL::HMAC.digest('SHA256', prk, t + 'Google' + [counter].pack('C'))
      okm += t
      counter += 1
    end

    derived_key_hex = okm[0...64].unpack1('H*')
    symmetric_encryption_key = derived_key_hex[0...64]
    mac_key = derived_key_hex[64..]

    # Encrypt with AES-256-CTR
    cipher = OpenSSL::Cipher.new('AES-256-CTR')
    cipher.encrypt
    cipher.key = [symmetric_encryption_key].pack('H*')
    cipher.iv = "\x00" * 16
    encrypted_data = cipher.update(plaintext) + cipher.final
    encrypted_message_b64 = Base64.strict_encode64(encrypted_data)

    # Compute HMAC tag
    mac_key_bytes = [mac_key].pack('H*')
    tag = Base64.strict_encode64(OpenSSL::HMAC.digest('SHA256', mac_key_bytes, encrypted_data))

    {
      'encryptedMessage' => encrypted_message_b64,
      'ephemeralPublicKey' => ephemeral_public_key_b64,
      'tag' => tag
    }
  end

  def build_signed_string_for_intermediate_key(signed_key)
    sender_id = 'Google'
    protocol_version = 'ECv2'

    [sender_id.bytesize].pack('V') + sender_id +
      [protocol_version.bytesize].pack('V') + protocol_version +
      [signed_key.bytesize].pack('V') + signed_key
  end

  def build_signed_string_for_message(signed_message, recipient_id)
    sender_id = 'Google'
    protocol_version = 'ECv2'

    [sender_id.bytesize].pack('V') + sender_id +
      [recipient_id.bytesize].pack('V') + recipient_id +
      [protocol_version.bytesize].pack('V') + protocol_version +
      [signed_message.bytesize].pack('V') + signed_message
  end

  def sign_with_key(ec_key, data)
    digest = OpenSSL::Digest::SHA256.digest(data)
    ec_key.dsa_sign_asn1(digest)
  end
end

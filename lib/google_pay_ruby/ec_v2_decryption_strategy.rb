# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'json'

module GooglePayRuby
  class EcV2DecryptionStrategy
    def initialize(private_key_pem)
      @private_key = OpenSSL::PKey::EC.new(private_key_pem)
    end

    def decrypt(signed_message)
      parsed_message = JSON.parse(signed_message)
      
      ephemeral_public_key = parsed_message['ephemeralPublicKey']
      encrypted_message = parsed_message['encryptedMessage']
      tag = parsed_message['tag']

      shared_key = get_shared_key(ephemeral_public_key)
      derived_key = get_derived_key(ephemeral_public_key, shared_key)

      symmetric_encryption_key = derived_key[0...64]
      mac_key = derived_key[64..-1]

      verify_message_hmac(mac_key, tag, encrypted_message)

      decrypted_message = decrypt_message(encrypted_message, symmetric_encryption_key)

      JSON.parse(decrypted_message)
    end

    private

    def get_shared_key(ephemeral_public_key_b64)
      # Decode the ephemeral public key from base64
      ephemeral_public_key_bytes = Base64.strict_decode64(ephemeral_public_key_b64)
      
      # Create an EC point object for the ephemeral public key
      group = OpenSSL::PKey::EC::Group.new('prime256v1')
      point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(ephemeral_public_key_bytes, 2))

      # Compute ECDH shared secret directly from the point (OpenSSL 3.0 compatible)
      shared_secret = @private_key.dh_compute_key(point)
      
      shared_secret.unpack1('H*')
    end

    def get_derived_key(ephemeral_public_key, shared_key)
      # Concatenate ephemeral public key and shared key
      info = Base64.strict_decode64(ephemeral_public_key) + [shared_key].pack('H*')
      
      # Use HKDF with SHA-256
      salt = "\x00" * 32
      
      # HKDF implementation
      prk = OpenSSL::HMAC.digest('SHA256', salt, info)
      
      # Expand with info="Google" to get 64 bytes
      t = ''
      okm = ''
      counter = 1
      
      while okm.length < 64
        t = OpenSSL::HMAC.digest('SHA256', prk, t + 'Google' + [counter].pack('C'))
        okm += t
        counter += 1
      end
      
      okm[0...64].unpack1('H*')
    end

    def verify_message_hmac(mac_key, tag, encrypted_message)
      mac_key_bytes = [mac_key].pack('H*')
      encrypted_message_bytes = Base64.strict_decode64(encrypted_message)
      
      calculated_hmac = OpenSSL::HMAC.digest('SHA256', mac_key_bytes, encrypted_message_bytes)
      calculated_tag = Base64.strict_encode64(calculated_hmac)

      unless calculated_tag == tag
        raise GooglePaymentDecryptionError, 'Tag is not a valid MAC for the encrypted message'
      end
    end

    def decrypt_message(encrypted_message, symmetric_encryption_key)
      key = [symmetric_encryption_key].pack('H*')
      iv = "\x00" * 16
      
      encrypted_data = Base64.strict_decode64(encrypted_message)
      
      decipher = OpenSSL::Cipher.new('AES-256-CTR')
      decipher.decrypt
      decipher.key = key
      decipher.iv = iv
      
      decrypted = decipher.update(encrypted_data) + decipher.final
      
      decrypted.force_encoding('UTF-8')
    end
  end
end

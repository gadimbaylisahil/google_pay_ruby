#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../lib/google_pay_ruby'
require 'json'

# The raw token JSON as received from Google Pay API.
# Contains \u003d unicode escapes which Google signed over literally.
token_json = "{\"signature\":\"MEUCIFS8IaIbAfIYmNoI7SivLSG4/wiXy37UuiHecFfQvmWoAiEAlFqY5lq/uU4AYw+A67AN99xbhWuu9ejJENv/o2CVVCM\\u003d\",\"intermediateSigningKey\":{\"signedKey\":\"{\\\"keyValue\\\":\\\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE81XjTt6ocjW3YeWmUepxf0hdM1NQb+fwtUPg4yzCpXDaseQcq4JVnZvH1BQjTteBOKDF46fge7IjrhGUTBxdIw\\u003d\\u003d\\\",\\\"keyExpiration\\\":\\\"1772218886000\\\"}\",\"signatures\":[\"MEYCIQCjcqD20ehvVeXLz1j/owXwVYhshO+45g9ewK1pf6b70QIhAKdzSimqiy7PJ/L9lPuhjIIqBz9Dy9UCuZA2V6uTFXyx\"]},\"protocolVersion\":\"ECv2\",\"signedMessage\":\"{\\\"encryptedMessage\\\":\\\"5+VAA6Yov/WW9Dv9Mi8E4tDeY55/6DosIjFp+V7HjnP2LcBLlp7CYEOsi12ir552O/Fj9NItYZZuBp+Xgnkg1qIMXrVIGnvXxTh2zsb+rxdfYkq6OoCPTWPBkN8RauuNdsYxC+cJnoI9sc+z+QtSdUBD7+IgSIDiUvEtwZZtnnUCbj2XAk6j45/54zfAzlRQkBVnJJzpto3e+kp/1l7Xnh78fdRFOrAVDPkcYHke50+qa81E5/lS1h0384s+2SD937jZCUyBPHwwB17ktiQsdWUHx2i/UHdeuEMGY0Nk1RzzwS/cbiImel0RfRHNPVSaLa723eMAA4w2QwORf2yscxx67hawac2HQlTJ/I46R9Pc3+VRwRQROEb1iIdRdPPqvMZwAhF1Z/4a+CHkONorfbr2Oomh5/V1uYsm9b9oKcJ2iAhzOB0xXRfaInE94Z/sZJfHo1WLaciZ9oLv4avUrPaqPBY37aYP4lono3P3lEjFRzO2RPWCM+R9+qCrYoL31sagemEeTNLsDc+QVEIcLG4CNUbWswmfW2V5/5c/Gqwn93P54TX8rRbP4dCV57jW5TVSfycP8bRhqiVdLDydXGPQ9mtMdjjfOpzQwlZEUtkIBTYDLNkfP8oWC95u8RZSYbJNrML8LG0D\\\",\\\"ephemeralPublicKey\\\":\\\"BCtB6f9vubiPoHen7jY6bib9te7pEKZ6eT4H9nk8U+R5uNLfi4ARUAPW1TAgsNqMIuTcZ/3ywOi3155HEj9v7KI\\u003d\\\",\\\"tag\\\":\\\"so9bmrRCQaHxp3LXkIX4ZxibvTb9JFI/P4Tqd8+tB2g\\u003d\\\"}\"}"

token = JSON.parse(token_json)

puts "=== Token Structure ==="
puts "protocolVersion: #{token['protocolVersion']}"

isk = token['intermediateSigningKey']
signed_key = JSON.parse(isk['signedKey'])
expiration_time = Time.at(signed_key['keyExpiration'].to_i / 1000)
puts "intermediateSigningKey expiration: #{expiration_time} (#{expiration_time > Time.now ? 'VALID' : 'EXPIRED'})"
puts ""

# Google production ECv2 root signing key
prod_keys = [
  {
    "keyValue" => "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElLiHStI30O9lVplgRhBN1AdlQdWyYgjQAcK3vgrqTvxs9WFkLs7CrxGge79+N5AHlklIHwlKu4WKv8E5IFX8DA==",
    "protocolVersion" => "ECv2",
    "keyExpiration" => "2154841200000"
  }
]

# Test 1: Verify with raw_token_json (should PASS)
puts "=== Test 1: SignatureVerifier with raw_token_json ==="
begin
  verifier = GooglePayRuby::SignatureVerifier.new(
    root_signing_keys: prod_keys,
    recipient_id: "gateway:betterpayment"
  )
  verifier.verify!(token, raw_token_json: token_json)
  puts "PASSED - Signature verification succeeded with raw JSON"
rescue GooglePayRuby::GooglePaymentDecryptionError => e
  puts "FAILED: #{e.message}"
end
puts ""

# Test 2: Verify WITHOUT raw_token_json (should FAIL due to \u003d decode)
puts "=== Test 2: SignatureVerifier without raw_token_json ==="
begin
  verifier = GooglePayRuby::SignatureVerifier.new(
    root_signing_keys: prod_keys,
    recipient_id: "gateway:betterpayment"
  )
  verifier.verify!(token)
  puts "PASSED - Signature verification succeeded without raw JSON"
rescue GooglePayRuby::GooglePaymentDecryptionError => e
  puts "FAILED (expected): #{e.message}"
end
puts ""

# Test 3: Context.decrypt with raw JSON string (should pass signature verification)
puts "=== Test 3: Context.decrypt with raw JSON string ==="
begin
  context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
    merchants: [{ identifier: 'test', private_key_pem: 'dummy-key' }],
    recipient_id: "gateway:betterpayment",
    root_signing_keys: prod_keys,
    verify_expiration: false
  )
  context.decrypt(token_json)
  puts "PASSED - Full decrypt with raw JSON"
rescue GooglePayRuby::GooglePaymentDecryptionError => e
  if e.message.include?('signature')
    puts "FAILED (signature): #{e.message}"
  else
    puts "PASSED (signature OK, decryption failed as expected without real key): #{e.message}"
  end
end

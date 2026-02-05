#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../lib/google_pay_ruby'
require 'json'

# Example 1: Basic single key decryption
puts "=" * 60
puts "Example 1: Basic Single Key Decryption"
puts "=" * 60

private_key_pem = <<~PEM
  -----BEGIN EC PRIVATE KEY-----
  MHcCAQEEICDJblDbSduEOQwS1QSv+Tf/xxJc0fRozuT+I2YjvRoioAoGCCqGSM49
  AwEHoUQDQgAEffadCB6zT8z4VrT+ND4EVTFJayhsNR+yIYJDwM+CcrZxvObguMTB
  WkakNF4IwTmbhwtT1/fwrCkWJUApj3nVUA==
  -----END EC PRIVATE KEY-----
PEM

context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [
    {
      identifier: 'my-merchant',
      private_key_pem: private_key_pem
    }
  ]
)

# Example token (you would get this from Google Pay API)
token = {
  "signature": "MEYCIQCjqYS6T/29qQ27ZS5laoC9MeNodPauX1uNtUa9dmiL6gIhAOfzCbnLhJnzDsHZNBfLpWPg/XFyYq/QKqubNRbdyiOM",
  "intermediateSigningKey": {
    "signedKey": "{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEusLZZqP8Z1hvi9IU9rm7NcNLeokbvZ6Z0vXCWNoypycgpKTkrSXNMOWqAQS6hT37I3+qfLX5xRSo4q2kT63uw\\u003d\\u003d\",\"keyExpiration\":\"1709020759412\"}",
    "signatures": [
      "MEUCICaWaE8BUlQueV+ZrJ/OMJY7TwnaXeuTFx9fBzDHb1EXAiEAoeOYc4VbDJXSJQjTUiWhxua8zK855TKrCdkw0S3PNC0="
    ]
  },
  "protocolVersion": "ECv2",
  "signedMessage": "{\"encryptedMessage\":\"4Ipj9cRTdZju7aPB8aZx1TXv7jn9aH1uIXeB40+zhn/P532RTRyEdSG3fPdG+gv/sllBOhEfCk9o9if+QkLkyH2J4NpbeGEKjNFNZz7UGDlkzwJ1rG6KJQNIqchbfD6cnqhjNSmEgLysg0y5lxAkTfdly/I5h9qLAsOX5BFlNMIU5ZsX1Y0Xl/qMbNJO58h19lYNDC7V866YVc/YQSrpV5zl6lQDIkzyVdFzA/yvIs8RGaUkwEyPb01hEnO0mkssV8UIJyd7jBTDCTyXBubffHT84DQR1Vm4L8nK9IXJsQau8oHyF0as9dld9bOP5f9RJadImCcqu5JNmJ/l5tEHQP/FSereNlWSQTknzP+ZZP92tjuytbuKJV8kUEP+W5V2uLoUYjQdTA75WcaA8HbdavttxCZuYnIajroc9kVBPAaIpqH3tb1wOBnOlVQ\\u003d\",\"ephemeralPublicKey\":\"BFkRPgpI/NW2bYYZS+1M0o8FxEeR6B2EGI+3Ufvh8DFpGoFhfT3Zqo+hTp3129emDQ6a0lWEEuQpxqiB9mV/9dY\\u003d\",\"tag\":\"AZKdgPhVu7hz1VTH4Y38+TJ58wkO1dz7R3rKQMQa3+A\\u003d\"}"
}

begin
  decrypted = context.decrypt(token)
  puts "Decryption successful"
  puts "PAN: #{decrypted['paymentMethodDetails']['pan']}"
  puts "Expiry: #{decrypted['paymentMethodDetails']['expirationMonth']}/#{decrypted['paymentMethodDetails']['expirationYear']}"
rescue GooglePayRuby::GooglePaymentDecryptionError => e
  puts "✗ Decryption failed: #{e.message}"
end

puts

# Example 2: Key rotation with multiple keys
puts "=" * 60
puts "Example 2: Key Rotation Support"
puts "=" * 60

context_with_rotation = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [
    {
      identifier: 'current-key',
      private_key_pem: private_key_pem
    },
    {
      identifier: 'old-key',
      private_key_pem: private_key_pem  # In reality, this would be a different old key
    }
  ]
)

begin
  decrypted = context_with_rotation.decrypt(token)
  puts "Decryption successful with key rotation support"
  puts "Payment Method: #{decrypted['paymentMethod']}"
rescue GooglePayRuby::GooglePaymentDecryptionError => e
  puts "Decryption failed: #{e.message}"
end

puts

# Example 3: Error handling
puts "=" * 60
puts "Example 3: Error Handling"
puts "=" * 60

invalid_token = {
  'protocolVersion' => 'ECv2',
  'signedMessage' => '{"encryptedMessage":"invalid","ephemeralPublicKey":"invalid","tag":"invalid"}'
}

begin
  context.decrypt(invalid_token)
rescue GooglePayRuby::GooglePaymentDecryptionError => e
  puts "Error caught successfully"
  puts "Error message: #{e.message}"
  puts "Number of failed attempts: #{e.errors.length}"
end

puts
puts "=" * 60
puts "Examples completed"
puts "=" * 60

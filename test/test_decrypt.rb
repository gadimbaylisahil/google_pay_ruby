#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "../lib/google_pay_ruby"
require "json"

# Load the token from payload.json
token_data = {
  signature: "MEYCIQCjqYS6T/29qQ27ZS5laoC9MeNodPauX1uNtUa9dmiL6gIhAOfzCbnLhJnzDsHZNBfLpWPg/XFyYq/QKqubNRbdyiOM",
  intermediateSigningKey: {
    signedKey: "{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEusLZZqP8Z1hvi9IU9rm7NcNLeokbvZ6Z0vXCWNoypycgpKTkrSXNMOWqAQS6hT37I3+qfLX5xRSo4q2kT63uw\\u003d\\u003d\",\"keyExpiration\":\"1709020759412\"}",
    signatures: [
      "MEUCICaWaE8BUlQueV+ZrJ/OMJY7TwnaXeuTFx9fBzDHb1EXAiEAoeOYc4VbDJXSJQjTUiWhxua8zK855TKrCdkw0S3PNC0="
    ]
  },
  protocolVersion: "ECv2",
  signedMessage: "{\"encryptedMessage\":\"4Ipj9cRTdZju7aPB8aZx1TXv7jn9aH1uIXeB40+zhn/P532RTRyEdSG3fPdG+gv/sllBOhEfCk9o9if+QkLkyH2J4NpbeGEKjNFNZz7UGDlkzwJ1rG6KJQNIqchbfD6cnqhjNSmEgLysg0y5lxAkTfdly/I5h9qLAsOX5BFlNMIU5ZsX1Y0Xl/qMbNJO58h19lYNDC7V866YVc/YQSrpV5zl6lQDIkzyVdFzA/yvIs8RGaUkwEyPb01hEnO0mkssV8UIJyd7jBTDCTyXBubffHT84DQR1Vm4L8nK9IXJsQau8oHyF0as9dld9bOP5f9RJadImCcqu5JNmJ/l5tEHQP/FSereNlWSQTknzP+ZZP92tjuytbuKJV8kUEP+W5V2uLoUYjQdTA75WcaA8HbdavttxCZuYnIajroc9kVBPAaIpqH3tb1wOBnOlVQ\\u003d\",\"ephemeralPublicKey\":\"BFkRPgpI/NW2bYYZS+1M0o8FxEeR6B2EGI+3Ufvh8DFpGoFhfT3Zqo+hTp3129emDQ6a0lWEEuQpxqiB9mV/9dY\\u003d\",\"tag\":\"AZKdgPhVu7hz1VTH4Y38+TJ58wkO1dz7R3rKQMQa3+A\\u003d\"}"
}

# Load the private key
private_key_pem = <<~PEM
  -----BEGIN EC PRIVATE KEY-----
  MHcCAQEEICDJblDbSduEOQwS1QSv+Tf/xxJc0fRozuT+I2YjvRoioAoGCCqGSM49
  AwEHoUQDQgAEffadCB6zT8z4VrT+ND4EVTFJayhsNR+yIYJDwM+CcrZxvObguMTB
  WkakNF4IwTmbhwtT1/fwrCkWJUApj3nVUA==
  -----END EC PRIVATE KEY-----
PEM

# Create the decryption context
context = GooglePayRuby::GooglePaymentMethodTokenContext.new(
  merchants: [
    {
      identifier: "test-merchant",
      private_key_pem: private_key_pem
    }
  ]
)

begin
  puts "Attempting to decrypt Google Pay token..."
  puts "=" * 60

  decrypted_data = context.decrypt(token_data)

  puts "✓ Decryption successful!"
  puts "=" * 60
  puts JSON.pretty_generate(decrypted_data)
  puts "=" * 60

  # Extract key payment details
  payment_details = decrypted_data["paymentMethodDetails"]
  puts "\nPayment Details Summary:"
  puts "  PAN: #{payment_details["pan"]}"
  puts "  Expiration: #{payment_details["expirationMonth"]}/#{payment_details["expirationYear"]}"
  puts "  Auth Method: #{payment_details["authMethod"]}"
  puts "  Cryptogram: #{payment_details["cryptogram"]}"
  puts "  ECI Indicator: #{payment_details["eciIndicator"]}"
rescue GooglePayRuby::GooglePaymentDecryptionError => e
  puts "Decryption failed!"
  puts "=" * 60
  puts e.full_message
  puts "=" * 60
  exit 1
rescue StandardError => e
  puts "Unexpected error!"
  puts "=" * 60
  puts "#{e.class}: #{e.message}"
  puts e.backtrace.first(5)
  puts "=" * 60
  exit 1
end

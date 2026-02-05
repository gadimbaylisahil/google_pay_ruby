# frozen_string_literal: true

require_relative "lib/google_pay_ruby/version"

Gem::Specification.new do |spec|
  spec.name = "google_pay_ruby"
  spec.version = GooglePayRuby::VERSION
  spec.authors = ["Sahil Gadimbayli"]
  spec.email = ["contact@sahilgadimbayli.com"]

  spec.summary = "Ruby utility for decrypting Google Pay Tokens"
  spec.description = "A Ruby implementation for securely decrypting Google Pay PaymentMethodTokens using ECv2 protocol. Supports key rotation and multiple merchant configurations."
  spec.homepage = "https://github.com/better-payment/google-pay-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/better-payment/google-pay-ruby"
  spec.metadata["changelog_uri"] = "https://github.com/better-payment/google-pay-ruby/blob/main/CHANGELOG.md"

  spec.files = Dir.glob("{lib}/**/*") + %w[LICENSE.txt README.md CHANGELOG.md]
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rubocop", "~> 1.21"
end

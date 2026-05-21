# frozen_string_literal: true

require_relative "lib/better_auth/passkey/version"

Gem::Specification.new do |spec|
  spec.name = "better_auth-passkey"
  spec.version = BetterAuth::Passkey::VERSION
  spec.authors = ["Sebastian Sala"]
  spec.email = ["sebastian.sala.tech@gmail.com"]

  spec.summary = "Passkey/WebAuthn plugin package for Better Auth Ruby"
  spec.description = [
    "Adds passkey/WebAuthn registration, authentication, and credential management routes for Better Auth Ruby.",
    "Better Auth Ruby is an independent modern authentication framework for Ruby inspired by Better Auth."
  ].join(" ")
  spec.homepage = "https://github.com/sebasxsala/better-auth-rb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sebasxsala/better-auth-rb"
  spec.metadata["changelog_uri"] = "https://github.com/sebasxsala/better-auth-rb/blob/main/packages/better_auth-passkey/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "https://github.com/sebasxsala/better-auth-rb/issues"

  spec.files = Dir.glob("lib/**/*", File::FNM_DOTMATCH).select { |file| File.file?(file) } +
    ["LICENSE.md", "README.md", "CHANGELOG.md"].select { |file| File.exist?(file) }
  spec.require_paths = ["lib"]

  spec.add_dependency "better_auth", "~> 0.1"
  spec.add_dependency "base64", ">= 0.2", "< 1.0"
  spec.add_dependency "webauthn", "~> 3.4", ">= 3.4.3"

  spec.add_development_dependency "bundler", "~> 2.5"
  spec.add_development_dependency "minitest", "~> 5.25"
  spec.add_development_dependency "mysql2", "~> 0.5"
  spec.add_development_dependency "pg", "~> 1.5"
  spec.add_development_dependency "rake", "~> 13.2"
  spec.add_development_dependency "sequel", "~> 5.83"
  spec.add_development_dependency "sqlite3", "~> 2.0"
  spec.add_development_dependency "standardrb", "~> 1.0"
  spec.add_development_dependency "tiny_tds", "~> 2.1"
end

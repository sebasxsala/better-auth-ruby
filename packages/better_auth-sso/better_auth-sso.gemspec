# frozen_string_literal: true

require_relative "lib/better_auth/sso/version"

Gem::Specification.new do |spec|
  spec.name = "better_auth-sso"
  spec.version = BetterAuth::SSO::VERSION
  spec.authors = ["Sebastian Sala"]
  spec.email = ["sebastian.sala.tech@gmail.com"]

  spec.summary = "SSO plugin package for Better Auth Ruby"
  spec.description = [
    "Adds SSO provider management, domain verification, and composed OIDC/SAML routes for Better Auth Ruby.",
    "Requires better_auth-oidc; add better_auth-saml when using SAML identity providers.",
    "Better Auth Ruby is an independent modern authentication framework for Ruby inspired by Better Auth."
  ].join(" ")
  spec.homepage = "https://github.com/sebasxsala/better-auth-rb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sebasxsala/better-auth-rb"
  spec.metadata["changelog_uri"] = "https://github.com/sebasxsala/better-auth-rb/blob/main/packages/better_auth-sso/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "https://github.com/sebasxsala/better-auth-rb/issues"

  spec.files = Dir.glob("lib/**/*", File::FNM_DOTMATCH).select { |file| File.file?(file) } +
    ["LICENSE.md", "README.md", "CHANGELOG.md"].select { |file| File.exist?(file) }
  spec.require_paths = ["lib"]

  spec.add_dependency "better_auth", "~> 0.1"
  spec.add_dependency "better_auth-oidc", "0.10.0"
  spec.add_dependency "base64", ">= 0.2", "< 1.0"
  spec.add_dependency "logger", ">= 1.6", "< 2.0"

  spec.add_development_dependency "better_auth-saml", "0.10.0"
  spec.add_development_dependency "bundler", "~> 2.5"
  spec.add_development_dependency "minitest", "~> 5.25"
  spec.add_development_dependency "rake", "~> 13.2"
  spec.add_development_dependency "standardrb", "~> 1.0"
end

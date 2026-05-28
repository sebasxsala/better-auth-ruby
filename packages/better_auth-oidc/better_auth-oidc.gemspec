# frozen_string_literal: true

require_relative "lib/better_auth/oidc/version"

Gem::Specification.new do |spec|
  spec.name = "better_auth-oidc"
  spec.version = BetterAuth::OIDC::VERSION
  spec.authors = ["Sebastian Sala"]
  spec.email = ["sebastian.sala.tech@gmail.com"]

  spec.summary = "Enterprise OIDC RP support for Better Auth Ruby SSO"
  spec.description = [
    "OpenID Connect relying party primitives and plugin extensions for Better Auth Ruby enterprise SSO.",
    "Pair with better_auth-sso for provider management or require directly for OIDC-only integrations."
  ].join(" ")
  spec.homepage = "https://github.com/sebasxsala/better-auth-rb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sebasxsala/better-auth-rb"
  spec.metadata["changelog_uri"] = "https://github.com/sebasxsala/better-auth-rb/blob/main/packages/better_auth-oidc/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "https://github.com/sebasxsala/better-auth-rb/issues"

  spec.files = Dir.glob("lib/**/*", File::FNM_DOTMATCH).select { |file| File.file?(file) } +
    ["LICENSE.md", "README.md", "CHANGELOG.md"].select { |file| File.exist?(file) }
  spec.require_paths = ["lib"]

  spec.add_dependency "better_auth", "~> 0.1"
  spec.add_dependency "base64", ">= 0.2", "< 1.0"
  spec.add_dependency "jwt", "~> 2.8"
  spec.add_dependency "logger", ">= 1.6", "< 2.0"

  spec.add_development_dependency "bundler", "~> 2.5"
  spec.add_development_dependency "minitest", "~> 5.25"
  spec.add_development_dependency "rake", "~> 13.2"
  spec.add_development_dependency "standardrb", "~> 1.0"
end

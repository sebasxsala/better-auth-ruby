# frozen_string_literal: true

require_relative "lib/better_auth/cli/version"

Gem::Specification.new do |spec|
  spec.name = "better_auth-cli"
  spec.version = BetterAuth::CLI::VERSION
  spec.authors = ["Sebastian Sala"]
  spec.email = ["sebastian.sala.tech@gmail.com"]

  spec.summary = "Command-line tools for Better Auth Ruby"
  spec.description = "Generates and applies Better Auth Ruby database migrations from app configuration."
  spec.homepage = "https://github.com/sebasxsala/better-auth-rb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sebasxsala/better-auth-rb"

  spec.files = Dir.glob("lib/**/*", File::FNM_DOTMATCH).select { |file| File.file?(file) } +
    Dir.glob("exe/**/*", File::FNM_DOTMATCH).select { |file| File.file?(file) } +
    ["README.md", "CHANGELOG.md"].select { |file| File.exist?(file) }
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |file| File.basename(file) }
  spec.require_paths = ["lib"]

  spec.add_dependency "better_auth", BetterAuth::CLI::VERSION
  spec.add_development_dependency "minitest", "~> 5.25"
  spec.add_development_dependency "rake", "~> 13.2"
  spec.add_development_dependency "sqlite3", "~> 2.0"
end

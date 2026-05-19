# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "openauth-redis-storage"
  spec.version = "0.9.0"
  spec.authors = ["Sebastian Sala"]
  spec.email = ["sebastian.sala.tech@gmail.com"]

  spec.summary = "Alias package for better_auth-redis-storage"
  spec.description = "OpenAuth Redis storage alias package that installs better_auth-redis-storage."
  spec.homepage = "https://better-auth-rb.vercel.app/"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sebasxsala/better-auth-rb"
  spec.metadata["bug_tracker_uri"] = "https://github.com/sebasxsala/better-auth-rb/issues"
  spec.files = Dir.glob("lib/**/*", File::FNM_DOTMATCH).select { |file| File.file?(file) } + ["README.md", "CHANGELOG.md"].select { |file| File.exist?(file) }
  spec.require_paths = ["lib"]
  spec.add_dependency "better_auth-redis-storage", "0.9.0"
end

# frozen_string_literal: true

# Workspace Rakefile - Better Auth Ruby
# Runs tasks across all packages.

require "rake"

STANDARD_PATHS = [
  "Rakefile",
  "script",
  "test",
  "packages/better_auth/Rakefile",
  "packages/better_auth/lib",
  "packages/better_auth/test",
  "packages/better_auth-redis-storage/Rakefile",
  "packages/better_auth-redis-storage/lib",
  "packages/better_auth-redis-storage/test",
  "packages/better_auth-mongodb/Rakefile",
  "packages/better_auth-mongodb/lib",
  "packages/better_auth-mongodb/test",
  "packages/better_auth-mongo-adapter/Rakefile",
  "packages/better_auth-mongo-adapter/lib",
  "packages/better_auth-mongo-adapter/test",
  "packages/better_auth-api-key/Rakefile",
  "packages/better_auth-api-key/lib",
  "packages/better_auth-api-key/test",
  "packages/better_auth-passkey/Rakefile",
  "packages/better_auth-passkey/lib",
  "packages/better_auth-passkey/test",
  "packages/better_auth-stripe/Rakefile",
  "packages/better_auth-stripe/lib",
  "packages/better_auth-stripe/test",
  "packages/better_auth-oauth-provider/Rakefile",
  "packages/better_auth-oauth-provider/lib",
  "packages/better_auth-oauth-provider/test",
  "packages/better_auth-scim/Rakefile",
  "packages/better_auth-scim/lib",
  "packages/better_auth-scim/test",
  "packages/better_auth-sso/Rakefile",
  "packages/better_auth-sso/lib",
  "packages/better_auth-sso/test",
  "packages/better_auth-rails/Rakefile",
  "packages/better_auth-rails/lib",
  "packages/better_auth-rails/spec",
  "packages/better_auth-sinatra/Rakefile",
  "packages/better_auth-sinatra/lib",
  "packages/better_auth-sinatra/spec",
  "packages/better_auth-hanami/Rakefile",
  "packages/better_auth-hanami/lib",
  "packages/better_auth-hanami/spec"
].freeze

# Default task: run CI across all packages.
desc "Run CI in all packages"
task :ci do
  puts "🔧 Running CI in workspace..."

  # Global linting
  puts "\n📋 Running linter..."
  sh "bundle exec standardrb #{STANDARD_PATHS.join(" ")}"

  puts "\n🧪 Running workspace packaging tests..."
  sh "ruby -Itest test/openauth_alias_packages_test.rb test/release_version_manifest_test.rb"

  # Per-package tests
  puts "\n🧪 Running tests in packages/better_auth..."
  cd "packages/better_auth" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake ci"
  end

  puts "\n🧪 Running tests in packages/better_auth-redis-storage..."
  cd "packages/better_auth-redis-storage" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake"
    # Run real-Redis integration only when a local/CI Redis URL is configured.
    if ENV["REDIS_URL"] || ENV["RUN_REDIS_INTEGRATION"] == "1"
      sh "REDIS_INTEGRATION=1 BUNDLE_GEMFILE=Gemfile bundle exec rake test:integration"
    end
  end

  puts "\n🧪 Running tests in packages/better_auth-mongodb..."
  cd "packages/better_auth-mongodb" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake"
  end

  puts "\n🧪 Running compatibility tests in packages/better_auth-mongo-adapter..."
  cd "packages/better_auth-mongo-adapter" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake"
  end

  puts "\n🧪 Running tests in packages/better_auth-api-key..."
  cd "packages/better_auth-api-key" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake"
  end

  puts "\n🧪 Running tests in packages/better_auth-passkey..."
  cd "packages/better_auth-passkey" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake"
  end

  puts "\n🧪 Running tests in packages/better_auth-stripe..."
  cd "packages/better_auth-stripe" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake"
  end

  puts "\n🧪 Running tests in packages/better_auth-oauth-provider..."
  cd "packages/better_auth-oauth-provider" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake test"
  end

  puts "\n🧪 Running tests in packages/better_auth-scim..."
  cd "packages/better_auth-scim" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake test"
  end

  puts "\n🧪 Running tests in packages/better_auth-sso..."
  cd "packages/better_auth-sso" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake test"
  end

  puts "\n🧪 Running tests in packages/better_auth-rails..."
  cd "packages/better_auth-rails" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake ci"
  end

  puts "\n🧪 Running tests in packages/better_auth-sinatra..."
  cd "packages/better_auth-sinatra" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake ci"
  end

  puts "\n🧪 Running tests in packages/better_auth-hanami..."
  cd "packages/better_auth-hanami" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake ci"
  end

  puts "\n✅ Workspace CI completed successfully!"
end

desc "Install dependencies in all packages"
task :install do
  puts "📦 Installing workspace dependencies..."
  sh "bundle install"

  puts "\n📦 Installing packages/better_auth dependencies..."
  cd "packages/better_auth" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-redis-storage dependencies..."
  cd "packages/better_auth-redis-storage" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-mongodb dependencies..."
  cd "packages/better_auth-mongodb" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-mongo-adapter dependencies..."
  cd "packages/better_auth-mongo-adapter" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-api-key dependencies..."
  cd "packages/better_auth-api-key" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-passkey dependencies..."
  cd "packages/better_auth-passkey" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-stripe dependencies..."
  cd "packages/better_auth-stripe" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-oauth-provider dependencies..."
  cd "packages/better_auth-oauth-provider" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-scim dependencies..."
  cd "packages/better_auth-scim" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-sso dependencies..."
  cd "packages/better_auth-sso" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-rails dependencies..."
  cd "packages/better_auth-rails" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-sinatra dependencies..."
  cd "packages/better_auth-sinatra" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-hanami dependencies..."
  cd "packages/better_auth-hanami" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end
end

desc "Run linter across all packages"
task :lint do
  sh "bundle exec standardrb #{STANDARD_PATHS.join(" ")}"

  cd "packages/better_auth" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-redis-storage" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-mongodb" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-mongo-adapter" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-api-key" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-passkey" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-stripe" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-oauth-provider" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-scim" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-sso" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-rails" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-sinatra" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-hanami" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end
end

desc "Auto-fix linting issues across all packages"
task "lint:fix" do
  sh "bundle exec standardrb --fix #{STANDARD_PATHS.join(" ")}"

  cd "packages/better_auth" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-redis-storage" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-mongodb" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-mongo-adapter" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-api-key" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-passkey" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-stripe" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-oauth-provider" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-scim" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-sso" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-rails" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-sinatra" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-hanami" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end
end

desc "Run tests in specific package"
task :test, [:package] do |t, args|
  package = args[:package]

  unless package
    puts "❌ Usage: rake test[package_name]"
    puts "   Example: rake test[better_auth]"
    exit 1
  end

  cd "packages/#{package}" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake test"
  end
end

desc "Clean all packages"
task :clean do
  sh "rm -rf Gemfile.lock"

  cd "packages/better_auth" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-redis-storage" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-mongodb" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-mongo-adapter" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-api-key" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-passkey" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-stripe" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-oauth-provider" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-scim" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-sso" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-rails" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-sinatra" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-hanami" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end
end

desc "Sync package versions from .release.yml"
task "release:sync_versions" do
  sh "ruby script/sync_versions.rb"
end

task default: :ci

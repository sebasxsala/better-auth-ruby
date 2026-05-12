# frozen_string_literal: true

require "minitest/autorun"
require "rubygems"

class OpenAuthAliasPackagesTest < Minitest::Test
  PACKAGE_PAIRS = {
    "openauth" => ["better_auth", "openauth"],
    "openauth-api-key" => ["better_auth-api-key", "openauth/api_key"],
    "openauth-hanami" => ["better_auth-hanami", "openauth/hanami"],
    "openauth-mongodb" => ["better_auth-mongo-adapter", "openauth/mongodb"],
    "openauth-oauth-provider" => ["better_auth-oauth-provider", "openauth/oauth_provider"],
    "openauth-passkey" => ["better_auth-passkey", "openauth/passkey"],
    "openauth-rails" => ["better_auth-rails", "openauth/rails"],
    "openauth-redis-storage" => ["better_auth-redis-storage", "openauth/redis_storage"],
    "openauth-scim" => ["better_auth-scim", "openauth/scim"],
    "openauth-sinatra" => ["better_auth-sinatra", "openauth/sinatra"],
    "openauth-sso" => ["better_auth-sso", "openauth/sso"],
    "openauth-stripe" => ["better_auth-stripe", "openauth/stripe"]
  }.freeze

  def test_alias_packages_match_canonical_versions_and_documentation
    PACKAGE_PAIRS.each do |alias_name, (canonical_name, require_name)|
      package_dir = File.expand_path("../packages/#{alias_name}", __dir__)
      gemspec_path = File.join(package_dir, "#{alias_name}.gemspec")
      readme_path = File.join(package_dir, "README.md")
      require_path = File.join(package_dir, "lib", "#{require_name}.rb")

      assert_path_exists gemspec_path
      assert_path_exists readme_path
      assert_path_exists require_path

      spec = Gem::Specification.load(gemspec_path)
      assert_equal alias_name, spec.name
      assert_equal "0.7.0", spec.version.to_s
      assert_includes spec.runtime_dependencies.map(&:name), canonical_name

      readme = File.read(readme_path)
      assert_includes readme, "https://better-auth-rb.vercel.app/"
      assert_includes readme, "gem \"#{alias_name}\""
      assert_includes readme, "require \"#{require_name}\""
      assert_includes readme, canonical_name
    end
  end
end

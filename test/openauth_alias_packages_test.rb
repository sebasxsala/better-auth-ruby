# frozen_string_literal: true

require "minitest/autorun"
require "rubygems"
require "yaml"

class OpenAuthAliasPackagesTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)

  PACKAGE_PAIRS = {
    "openauth" => ["better_auth", "openauth"],
    "openauth-api-key" => ["better_auth-api-key", "openauth/api_key"],
    "openauth-hanami" => ["better_auth-hanami", "openauth/hanami"],
    "openauth-mongodb" => ["better_auth-mongodb", "openauth/mongodb"],
    "openauth-oauth-provider" => ["better_auth-oauth-provider", "openauth/oauth_provider"],
    "openauth-passkey" => ["better_auth-passkey", "openauth/passkey"],
    "openauth-rails" => ["better_auth-rails", "openauth/rails"],
    "openauth-redis-storage" => ["better_auth-redis-storage", "openauth/redis_storage"],
    "openauth-roda" => ["better_auth-roda", "openauth/roda"],
    "openauth-scim" => ["better_auth-scim", "openauth/scim"],
    "openauth-sinatra" => ["better_auth-sinatra", "openauth/sinatra"],
    "openauth-sso" => ["better_auth-sso", "openauth/sso"],
    "openauth-stripe" => ["better_auth-stripe", "openauth/stripe"],
    "openauth-telemetry" => ["better_auth-telemetry", "openauth/telemetry"]
  }.freeze

  OPENAUTH_REQUIRE_PATHS = PACKAGE_PAIRS.values.map(&:last).freeze

  PACKAGE_OPENAUTH_ALIASES = %i[
    APIKey
    Hanami
    MongoAdapter
    MongoDB
    OAuthProvider
    Passkey
    Rails
    RedisStorage
    Roda
    SCIM
    Sinatra
    SSO
    Stripe
    Telemetry
  ].freeze

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
      assert_equal release_version, spec.version.to_s
      assert_includes spec.runtime_dependencies.map(&:name), canonical_name

      readme = File.read(readme_path)
      assert_includes readme, "https://better-auth-rb.vercel.app/"
      assert_includes readme, "gem \"#{alias_name}\""
      assert_includes readme, "require \"#{require_name}\""
      assert_includes readme, canonical_name
    end
  end

  def test_openauth_exposes_core_and_package_constants_directly
    add_package_libs_to_load_path
    OPENAUTH_REQUIRE_PATHS.each { |path| require path }

    expected_aliases = (BetterAuth.constants(false) + PACKAGE_OPENAUTH_ALIASES).uniq
    missing_aliases = expected_aliases.reject { |constant_name| OpenAuth.const_defined?(constant_name, false) }

    assert_empty missing_aliases, "OpenAuth is missing direct aliases for: #{missing_aliases.sort.join(", ")}"

    assert_same BetterAuth::Adapters::Memory, OpenAuth::Adapters::Memory
    assert_same BetterAuth::Adapters::MongoDB, OpenAuth::Adapters::MongoDB
    assert_same BetterAuth::Plugins, OpenAuth::Plugins
    assert_same BetterAuth::APIKey, OpenAuth::APIKey
    assert_same BetterAuth::Rails, OpenAuth::Rails
    assert_same BetterAuth::Roda, OpenAuth::Roda
    assert_same BetterAuth::Sinatra, OpenAuth::Sinatra
    assert_same BetterAuth::MongoDB, OpenAuth::MongoDB
  end

  private

  def add_package_libs_to_load_path
    Dir[File.join(ROOT, "packages", "*", "lib")].sort.reverse_each do |path|
      $LOAD_PATH.unshift(path) unless $LOAD_PATH.include?(path)
    end
  end

  def release_version
    @release_version ||= YAML.safe_load_file(File.join(ROOT, ".release.yml")).fetch("version")
  end
end

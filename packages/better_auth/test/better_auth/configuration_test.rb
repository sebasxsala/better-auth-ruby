# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthConfigurationTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_default_configuration_matches_upstream_defaults
    config = BetterAuth::Configuration.new(secret: SECRET)

    assert_equal "/api/auth", config.base_path
    assert_equal 24 * 60 * 60, config.session[:update_age]
    assert_equal 60 * 60 * 24 * 7, config.session[:expires_in]
    assert_equal 60 * 60 * 24, config.session[:fresh_age]
    assert_equal 8, config.email_and_password[:min_password_length]
    assert_equal 128, config.email_and_password[:max_password_length]
    assert_equal :scrypt, config.password_hasher
    assert_equal "cookie", config.account[:store_state_strategy]
    assert_equal true, config.account[:store_account_cookie]
    assert_equal({enabled: true, strategy: "jwe", refresh_cache: true, max_age: 60 * 60 * 24 * 7}, config.session[:cookie_cache])
  end

  def test_secondary_storage_selects_secondary_rate_limit_storage_by_default
    storage = Object.new
    config = BetterAuth::Configuration.new(secret: SECRET, secondary_storage: storage)

    assert_equal "secondary-storage", config.rate_limit[:storage]
  end

  def test_secondary_storage_disables_cookie_refresh_cache
    storage = Object.new

    capture_io do
      @config = BetterAuth::Configuration.new(
        secret: SECRET,
        secondary_storage: storage,
        session: {cookie_cache: {refresh_cache: true}}
      )
    end

    assert_equal false, @config.session.dig(:cookie_cache, :refresh_cache)
  ensure
    remove_instance_variable(:@config) if defined?(@config)
  end

  def test_explicit_configuration_normalizes_ruby_option_names
    config = BetterAuth::Configuration.new(
      base_url: "http://localhost:3000",
      base_path: "/custom-path",
      secret: SECRET,
      trusted_origins: ["http://example.com"],
      session: {
        update_age: 1000,
        expires_in: 2000,
        fresh_age: 0
      },
      email_and_password: {
        enabled: true,
        min_password_length: 12,
        max_password_length: 256
      },
      password_hasher: :bcrypt
    )

    assert_equal "http://localhost:3000", config.base_url
    assert_equal "http://localhost:3000/custom-path", config.context_base_url
    assert_equal "/custom-path", config.base_path
    assert_equal ["http://localhost:3000", "http://example.com"], config.trusted_origins
    assert_equal 1000, config.session[:update_age]
    assert_equal 2000, config.session[:expires_in]
    assert_equal 0, config.session[:fresh_age]
    assert_equal 12, config.email_and_password[:min_password_length]
    assert_equal 256, config.email_and_password[:max_password_length]
    assert_equal :bcrypt, config.password_hasher
  end

  def test_base_url_base_path_env_and_protocol_match_upstream_context_cases
    with_env("BETTER_AUTH_URL" => "http://localhost:5147") do
      config = BetterAuth::Configuration.new(secret: SECRET)

      assert_equal "http://localhost:5147", config.base_url
      assert_equal "http://localhost:5147/api/auth", config.context_base_url
    end

    empty_path = BetterAuth::Configuration.new(base_url: "http://localhost:5147/", base_path: "", secret: SECRET)
    root_path = BetterAuth::Configuration.new(base_url: "http://localhost:5147/", base_path: "/", secret: SECRET)
    trailing = BetterAuth::Configuration.new(base_url: "http://localhost:5147////", secret: SECRET)
    special = BetterAuth::Configuration.new(base_url: "http://localhost:3000", base_path: "/api/v1/auth-service", secret: SECRET)
    https = BetterAuth::Configuration.new(base_url: "https://example.com/path/to/auth", secret: SECRET)

    assert_equal "http://localhost:5147", empty_path.context_base_url
    assert_equal "http://localhost:5147", root_path.context_base_url
    assert_equal "http://localhost:5147/api/auth", trailing.context_base_url
    assert_equal "http://localhost:3000/api/v1/auth-service", special.context_base_url
    assert_equal "https://example.com", https.base_url
    assert_equal "https://example.com/path/to/auth", https.context_base_url

    error = assert_raises(BetterAuth::Error) do
      BetterAuth::Configuration.new(base_url: "ftp://localhost:3000", secret: SECRET)
    end
    assert_includes error.message, "http://"
  end

  def test_open_auth_env_aliases_override_better_auth_env_values
    with_env(
      "OPEN_AUTH_SECRET" => "open-auth-secret-that-is-long-enough-for-validation",
      "BETTER_AUTH_SECRET" => "better-auth-secret-that-is-long-enough-for-validation",
      "OPEN_AUTH_URL" => "http://open-auth.example",
      "BETTER_AUTH_URL" => "http://better-auth.example",
      "OPEN_AUTH_TRUSTED_ORIGINS" => "http://open-one.example, http://open-two.example",
      "BETTER_AUTH_TRUSTED_ORIGINS" => "http://better-one.example",
      "OPEN_AUTH_SECRETS" => "2:open-auth-rotated-secret-that-is-long-enough",
      "BETTER_AUTH_SECRETS" => "1:better-auth-rotated-secret-that-is-long-enough"
    ) do
      config = BetterAuth::Configuration.new

      assert_equal "open-auth-rotated-secret-that-is-long-enough", config.secret
      assert_equal "http://open-auth.example", config.base_url
      assert_includes config.trusted_origins, "http://open-one.example"
      assert_includes config.trusted_origins, "http://open-two.example"
      refute_includes config.trusted_origins, "http://better-one.example"
    end
  end

  def test_better_auth_env_values_remain_supported_when_open_auth_aliases_are_absent
    with_env(
      "OPEN_AUTH_SECRET" => nil,
      "OPEN_AUTH_URL" => nil,
      "OPEN_AUTH_TRUSTED_ORIGINS" => nil,
      "OPEN_AUTH_SECRETS" => nil,
      "BETTER_AUTH_SECRET" => SECRET,
      "BETTER_AUTH_URL" => "http://better-auth.example",
      "BETTER_AUTH_TRUSTED_ORIGINS" => "http://better-one.example"
    ) do
      config = BetterAuth::Configuration.new

      assert_equal SECRET, config.secret
      assert_equal "http://better-auth.example", config.base_url
      assert_includes config.trusted_origins, "http://better-one.example"
    end
  end

  def test_rejects_unknown_password_hasher
    error = assert_raises(BetterAuth::Error) do
      BetterAuth::Configuration.new(secret: SECRET, password_hasher: :argon2)
    end

    assert_includes error.message, "Unsupported password hasher"
  end

  def test_base_url_with_existing_path_keeps_that_path_and_extracts_origin_for_options
    config = BetterAuth::Configuration.new(
      base_url: "http://localhost:3000/some/path?query=value",
      secret: SECRET
    )

    assert_equal "http://localhost:3000", config.base_url
    assert_equal "http://localhost:3000/some/path?query=value", config.context_base_url
  end

  def test_secret_resolution_prefers_options_then_environment
    with_env("BETTER_AUTH_SECRET" => "env-secret-that-is-long-enough-for-validation") do
      config = BetterAuth::Configuration.new(secret: SECRET)

      assert_equal SECRET, config.secret
    end

    with_env("BETTER_AUTH_SECRET" => "env-secret-that-is-long-enough-for-validation") do
      config = BetterAuth::Configuration.new

      assert_equal "env-secret-that-is-long-enough-for-validation", config.secret
    end

    with_env("BETTER_AUTH_SECRET" => nil, "AUTH_SECRET" => "auth-secret-that-is-long-enough-for-validation") do
      config = BetterAuth::Configuration.new

      assert_equal "auth-secret-that-is-long-enough-for-validation", config.secret
    end
  end

  def test_versioned_secrets_prefer_current_secret_and_preserve_legacy_secret
    config = BetterAuth::Configuration.new(
      secret: "legacy-secret-that-is-long-enough-for-validation",
      secrets: [
        {version: 2, value: "new-secret-that-is-long-enough-for-validation"},
        {version: 1, value: "old-secret-that-is-long-enough-for-validation"}
      ]
    )

    assert_equal "new-secret-that-is-long-enough-for-validation", config.secret
    assert_equal 2, config.secret_config.current_version
    assert_equal "new-secret-that-is-long-enough-for-validation", config.secret_config.current_secret
    assert_equal "old-secret-that-is-long-enough-for-validation", config.secret_config.keys.fetch(1)
    assert_equal "legacy-secret-that-is-long-enough-for-validation", config.secret_config.legacy_secret
  end

  def test_versioned_secrets_can_be_loaded_from_environment
    with_env(
      "BETTER_AUTH_SECRETS" => "2: env-new-secret-that-is-long-enough, 1: env-old-secret-that-is-long-enough",
      "BETTER_AUTH_SECRET" => "env-legacy-secret-that-is-long-enough"
    ) do
      config = BetterAuth::Configuration.new

      assert_equal "env-new-secret-that-is-long-enough", config.secret
      assert_equal 2, config.secret_config.current_version
      assert_equal "env-legacy-secret-that-is-long-enough", config.secret_config.legacy_secret
    end
  end

  def test_versioned_secrets_reject_invalid_and_duplicate_versions
    assert_raises(BetterAuth::Error) do
      BetterAuth::Configuration.new(secrets: [{version: "1e2", value: SECRET}])
    end

    assert_raises(BetterAuth::Error) do
      BetterAuth::Configuration.new(secrets: [{version: 1, value: SECRET}, {version: "1", value: SECRET}])
    end

    with_env("BETTER_AUTH_SECRETS" => "noseparator") do
      assert_raises(BetterAuth::Error) { BetterAuth::Configuration.new }
    end
  end

  def test_missing_secret_fails_outside_tests
    with_env("BETTER_AUTH_SECRET" => nil, "AUTH_SECRET" => nil, "RACK_ENV" => "production") do
      error = assert_raises(BetterAuth::Error) { BetterAuth::Configuration.new }

      assert_match "BETTER_AUTH_SECRET is missing", error.message
    end
  end

  def test_short_or_low_entropy_secret_warns
    warnings = []

    BetterAuth::Configuration.new(
      base_url: "http://localhost:3000",
      secret: "aaaaaaaa",
      logger: ->(level, message) { warnings << [level, message] }
    )

    assert warnings.any? { |level, message| level == :warn && message.include?("at least 32 characters") }
    assert warnings.any? { |level, message| level == :warn && message.include?("low-entropy") }
  end

  def test_trusted_origin_matching_matches_upstream_core_cases
    config = BetterAuth::Configuration.new(
      base_url: "http://localhost:3000",
      secret: SECRET,
      trusted_origins: ["https://trusted.com", "*.my-site.com", "https://*.protocol-site.com"]
    )

    assert config.trusted_origin?("http://localhost:3000/some/path")
    assert config.trusted_origin?("https://trusted.com/some/path")
    assert config.trusted_origin?("https://sub-domain.my-site.com/callback")
    assert config.trusted_origin?("https://api.protocol-site.com")
    refute config.trusted_origin?("https://trusted.com.malicious.com")
    refute config.trusted_origin?("http://sub-domain.trusted.com")
    refute config.trusted_origin?("http://api.protocol-site.com")
    refute config.trusted_origin?("/")
    assert config.trusted_origin?("/dashboard?email=123@email.com", allow_relative_paths: true)
    refute config.trusted_origin?("//evil.com", allow_relative_paths: true)
  end

  def test_custom_scheme_wildcard_trusted_origins_match_full_url
    config = BetterAuth::Configuration.new(
      base_url: "http://localhost:3000",
      secret: SECRET,
      trusted_origins: [
        "exp://10.0.0.*:*/*",
        "exp://192.168.*.*:*/*",
        "exp://172.*.*.*:*/*"
      ]
    )

    assert config.trusted_origin?("exp://10.0.0.29:8081/--/")
    assert config.trusted_origin?("exp://192.168.1.100:8081/--/")
    assert config.trusted_origin?("exp://172.16.0.1:8081/--/")
    refute config.trusted_origin?("exp://203.0.113.0:8081/--/")
  end

  def test_plugin_list_normalization_filters_nil_and_preserves_order
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      plugins: [
        nil,
        {id: "first"},
        false,
        {id: "second"}
      ]
    )

    assert_equal ["first", "second"], config.plugins.map { |plugin| plugin[:id] }
  end

  def test_experimental_joins_option_accepts_camel_and_snake_case
    camel = BetterAuth::Configuration.new(secret: SECRET, experimental: {joins: true})
    snake = BetterAuth::Configuration.new(secret: SECRET, experimental: {joins: false})

    assert_equal({joins: true}, camel.experimental)
    assert_equal({joins: false}, snake.experimental)
  end

  def test_context_exposes_runtime_fields_and_new_session_mutator
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    context = auth.context

    assert_equal "Better Auth", context.app_name
    assert_equal "http://localhost:3000/api/auth", context.base_url
    assert_equal SECRET, context.secret
    assert_equal SECRET, context.secret_config
    assert_equal auth.options, context.options
    assert_nil context.current_session
    assert_nil context.new_session

    session = {id: "test-session", user_id: "user-1"}
    context.set_new_session(session)

    assert_equal session, context.new_session
  end

  private

  def with_env(values)
    previous = values.keys.to_h { |key| [key, ENV[key]] }
    values.each do |key, value|
      if value.nil?
        ENV.delete(key)
      else
        ENV[key] = value
      end
    end

    yield
  ensure
    previous.each do |key, value|
      if value.nil?
        ENV.delete(key)
      else
        ENV[key] = value
      end
    end
  end
end

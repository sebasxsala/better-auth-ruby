# frozen_string_literal: true

require "minitest/autorun"
require "rack/mock"

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../../packages/better_auth/lib", __dir__)

require "better_auth_examples"

class BetterAuthExamplesTest < Minitest::Test
  def test_settings_round_trip_sanitizes_supported_values
    settings = BetterAuthExamples::Settings.normalize(
      "database" => "postgres",
      "rate_adapter" => "redis",
      "rate_window" => "25",
      "rate_max" => "9"
    )

    assert_equal "postgres", settings[:database]
    assert_equal "redis", settings[:rate_adapter]
    assert_equal 25, settings[:rate_window]
    assert_equal 9, settings[:rate_max]

    cookie = BetterAuthExamples::Settings.cookie_value(settings)
    parsed = BetterAuthExamples::Settings.from_cookie(cookie)

    assert_equal settings, parsed
  end

  def test_rate_limit_config_uses_global_custom_rule
    settings = BetterAuthExamples::Settings.normalize(
      database: "memory",
      rate_adapter: "memory",
      rate_window: 2,
      rate_max: 1
    )

    config = BetterAuthExamples::RateLimitSettings.config(settings)

    assert_equal true, config[:enabled]
    assert_equal "memory", config[:storage]
    assert_equal({window: 2, max: 1}, config[:custom_rules].fetch("*"))
  end

  def test_auth_registry_uses_cached_auth_and_can_reset
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://example.test",
      root_path: File.expand_path("tmp", __dir__)
    )
    settings = BetterAuthExamples::Settings.normalize(database: "memory")

    first = registry.auth_for(settings)
    second = registry.auth_for(settings)
    assert_same first, second

    registry.reset!(settings)
    refute_same first, registry.auth_for(settings)
  end

  def test_auth_registry_uses_dynamic_localhost_base_url
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )

    auth = registry.auth_for(BetterAuthExamples::Settings.normalize(database: "memory"))

    assert_equal(
      {
        allowed_hosts: ["localhost:*", "127.0.0.1:*", "[::1]:*"],
        protocol: "http",
        fallback: "http://localhost:3456"
      },
      auth.options.base_url_config
    )
  end

  def test_auth_registry_enables_supported_core_plugins
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )

    auth = registry.auth_for(BetterAuthExamples::Settings.normalize(database: "memory"))
    plugin_ids = auth.context.options.plugins.map(&:id)

    assert_includes plugin_ids, "username"
    assert_includes plugin_ids, "anonymous"
    assert_includes plugin_ids, "custom-session"
    assert_includes plugin_ids, "expo"
    assert_includes plugin_ids, "magic-link"
    assert_includes plugin_ids, "organization"
    assert_includes plugin_ids, "admin"
    assert_includes plugin_ids, "api-key"
    assert_includes plugin_ids, "passkey"
    assert_includes plugin_ids, "oauth-provider"
    assert_includes plugin_ids, "scim"
    assert_includes plugin_ids, "sso"
    assert_includes plugin_ids, "stripe"

    user_fields = auth.context.options.user.fetch(:additional_fields)
    session_fields = auth.context.options.session.fetch(:additional_fields)
    refute user_fields.fetch(:example_role).key?(:default_value)
    refute session_fields.fetch(:device_name).key?(:default_value)
  end

  def test_dashboard_exposes_plugin_metadata
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")

    response = Rack::MockRequest.new(app).get("/example/plugins")
    data = JSON.parse(response.body)

    assert_equal 200, response.status
    username = data.fetch("plugins").find { |plugin| plugin.fetch("id") == "username" }
    api_key = data.fetch("plugins").find { |plugin| plugin.fetch("id") == "api-key" }
    stripe = data.fetch("plugins").find { |plugin| plugin.fetch("id") == "stripe" }
    admin = data.fetch("plugins").find { |plugin| plugin.fetch("id") == "admin" }

    assert_includes username.fetch("description"), "username"
    assert api_key.fetch("examples").any? { |example| example.fetch("label") == "Create API key" }
    assert stripe.fetch("examples").any? { |example| example.fetch("path") == "/api/auth/subscription/list" }
    assert_equal admin.fetch("endpoints").length, admin.fetch("endpoint_actions").length
    assert admin.fetch("endpoint_actions").any? { |action| action.fetch("method") == "GET" && action.fetch("path") == "/api/auth/admin/list-users" }
  end

  def test_memory_database_explorer_uses_plugin_schema
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )

    data = registry.explore(BetterAuthExamples::Settings.normalize(database: "memory"))
    table_names = data.fetch(:tables).map { |table| table.fetch(:name) }

    assert_includes table_names, "organization"
    assert_includes table_names, "twoFactor"
  end

  def test_auth_registry_configures_social_providers_from_env
    with_env(
      "BETTER_AUTH_GOOGLE_CLIENT_ID" => "google-id",
      "BETTER_AUTH_GOOGLE_CLIENT_SECRET" => "google-secret",
      "BETTER_AUTH_GITLAB_CLIENT_ID" => "gitlab-id",
      "BETTER_AUTH_GITLAB_CLIENT_SECRET" => "gitlab-secret",
      "BETTER_AUTH_GITLAB_ISSUER" => "https://gitlab.example"
    ) do
      registry = BetterAuthExamples::AuthRegistry.new(
        app_name: "Test Example",
        base_url: "http://localhost:3456",
        root_path: File.expand_path("tmp", __dir__)
      )

      auth = registry.auth_for(BetterAuthExamples::Settings.normalize(database: "memory"))

      assert_includes auth.context.social_providers.keys, :google
      assert_includes auth.context.social_providers.keys, :gitlab
      assert_equal "https://gitlab.example/oauth/authorize",
        auth.context.social_providers.fetch(:gitlab).fetch(:create_authorization_url).call(
          state: "state",
          redirectURI: "http://localhost:3456/callback/gitlab"
        ).split("?").first
    end
  end

  def test_dashboard_renders_social_provider_buttons
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")

    response = Rack::MockRequest.new(app).get("/")

    assert_equal 200, response.status
    assert_includes response.body, "data-social-provider=\"github\""
    assert_includes response.body, "data-social-provider=\"google\""
    assert_includes response.body, "social-notice"
    assert_includes response.body, "name=\"nickname\""
    assert_includes response.body, "name=\"exampleRole\""
  end

  private

  def with_env(values)
    previous = values.keys.to_h { |key| [key, ENV[key]] }
    values.each { |key, value| ENV[key] = value }
    yield
  ensure
    previous.each do |key, value|
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
  end
end

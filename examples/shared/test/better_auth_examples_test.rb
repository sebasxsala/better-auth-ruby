# frozen_string_literal: true

require "minitest/autorun"
require "fileutils"
require "open3"
require "rack/mock"
require "uri"

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../../packages/better_auth/lib", __dir__)

require "better_auth_examples"

class BetterAuthExamplesTest < Minitest::Test
  def test_examples_serve_watch_wraps_selected_app_with_rerun
    script = File.expand_path("../../bin/serve", __dir__)
    env = {"EXAMPLES_SERVE_DRY_RUN" => "1"}

    stdout, stderr, status = Open3.capture3(env, script, "--watch", "sinatra")

    assert status.success?, stderr
    assert_equal "", stdout
    assert_includes stderr, "Starting sinatra on http://localhost:4567"
    assert_includes stderr, "bundle exec rerun --dir ../../packages --dir ../shared --dir . -- bundle exec ruby app.rb"
  end

  def test_dashboard_uses_dark_product_ui_tokens
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")

    response = Rack::MockRequest.new(app).get("/")

    assert_equal 200, response.status
    assert_includes response.body, "color-scheme: dark"
    assert_includes response.body, "--bg: oklch(0.105 0.004 260)"
    assert_includes response.body, "--accent: oklch(0.665 0.16 275)"
    assert_includes response.body, "background: var(--sidebar)"
    assert_includes response.body, "id=\"database-provider-select\""
    assert_includes response.body, "class=\"grid database-grid\""
    assert_includes response.body, ".row-selector { width: 44px"
    assert_includes response.body, "grid-template-rows: auto auto minmax(0, 1fr)"
    assert_includes response.body, "<div class=\"toolbar-right\">"
    assert_includes response.body, "<div class=\"pager\">"
    assert_includes response.body, "id=\"sidebar-profile\""
    assert_includes response.body, "$(\"#sidebar-profile\").innerHTML = profile"
    assert_includes response.body, "loadDatabase({preserveTable: true, preservePage: true})"
    assert_includes response.body, "`/example/database?${params.toString()}`"
    assert_includes response.body, "function renderPluginSections()"
    assert_includes response.body, "$(\"#plugin-filter\").oninput"
    assert_includes response.body, "data-plugin-toggle"
    assert_includes response.body, "function setPluginEnabled"
    assert_includes response.body, "data-view-button=\"organizations\""
    assert_includes response.body, "id=\"organization-select\""
    assert_includes response.body, "function renderOrganizations()"
  end

  def test_dashboard_routes_restore_view_and_plugin_filters_from_url
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")

    response = Rack::MockRequest.new(app).get("/plugins?plugin=admin&q=email")

    assert_equal 200, response.status
    assert_includes response.body, "const VIEW_PATHS = { home: \"/\", users: \"/users\", organizations: \"/organizations\", sessions: \"/sessions\", social: \"/social\", plugins: \"/plugins\", database: \"/database\", settings: \"/settings\" }"
    assert_includes response.body, "params.get(\"plugin\") || \"all\""
    assert_includes response.body, "params.get(\"q\") || \"\""
    assert_includes response.body, "syncURL(\"plugins\", \"replace\")"
  end

  def test_database_explorer_paginates_loaded_rows
    auth = BetterAuth.auth(
      app_name: "Test Example",
      secret: "better-auth-example-secret-12345678901234567890",
      base_url: "http://localhost:3456",
      database: :memory,
      telemetry: {disabled: true}
    )
    auth.context.adapter.db["user"] = [
      {"id" => "user-1", "email" => "one@example.com"},
      {"id" => "user-2", "email" => "two@example.com"},
      {"id" => "user-3", "email" => "three@example.com"}
    ]

    data = BetterAuthExamples::DatabaseProviders.explore(auth, table: "users", limit: 1, offset: 1)
    users = data.fetch(:tables).find { |table| table.fetch(:name) == "users" }

    assert_equal 1, data.fetch(:limit)
    assert_equal 1, data.fetch(:offset)
    assert_equal 3, users.fetch(:count)
    assert_equal ["user-2"], users.fetch(:rows).map { |row| row.fetch("id") }
  end

  def test_database_explorer_lists_schema_columns_for_empty_memory_tables
    auth = BetterAuth.auth(
      app_name: "Test Example",
      secret: "better-auth-example-secret-12345678901234567890",
      base_url: "http://localhost:3456",
      database: :memory,
      telemetry: {disabled: true}
    )

    data = BetterAuthExamples::DatabaseProviders.explore(auth, table: "users", limit: 1, offset: 0)
    users = data.fetch(:tables).find { |table| table.fetch(:name) == "users" }

    assert_includes users.fetch(:columns), "id"
    assert_includes users.fetch(:columns), "email"
    assert_includes users.fetch(:columns), "created_at"
  end

  def test_database_explorer_deletes_memory_records_from_plural_schema_tables
    auth = BetterAuth.auth(
      app_name: "Test Example",
      secret: "better-auth-example-secret-12345678901234567890",
      base_url: "http://localhost:3456",
      database: :memory,
      telemetry: {disabled: true}
    )
    auth.context.adapter.db["user"] = [
      {"id" => "user-1", "email" => "one@example.com"},
      {"id" => "user-2", "email" => "two@example.com"}
    ]

    result = BetterAuthExamples::DatabaseProviders.delete_records!(auth, "users", ["user-1"])

    assert_equal({deleted: 1}, result)
    assert_equal ["user-2"], auth.context.adapter.db.fetch("user").map { |row| row.fetch("id") }
  end

  def test_dashboard_database_provider_setting_persists_in_cookie
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")
    request = Rack::MockRequest.new(app)

    update = request.post(
      "/example/settings",
      "CONTENT_TYPE" => "application/json",
      :input => JSON.generate(database: "sqlite", rate_adapter: "memory", rate_window: 10, rate_max: 100)
    )
    cookie = update["set-cookie"].to_s.lines.find { |line| line.include?(BetterAuthExamples::Settings::COOKIE_NAME) }
    response = request.get("/example/settings", "HTTP_COOKIE" => cookie.to_s.split(";").first)

    assert_equal 200, update.status
    assert_includes cookie, "database"
    assert_equal "sqlite", JSON.parse(response.body).fetch("settings").fetch("database")
  end

  def test_dashboard_plugin_settings_persist_and_expire_multi_session_cookies
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")
    request = Rack::MockRequest.new(app)

    update = request.post(
      "/example/settings",
      "CONTENT_TYPE" => "application/json",
      "HTTP_COOKIE" => "better-auth.session_token_multi-old=signed",
      :input => JSON.generate(database: "memory", disabled_plugins: ["api-key", "multi-session"])
    )
    cookie = update["set-cookie"].to_s.lines.find { |line| line.include?(BetterAuthExamples::Settings::COOKIE_NAME) }
    response = request.get("/example/plugins", "HTTP_COOKIE" => cookie.to_s.split(";").first)
    data = JSON.parse(response.body)

    assert_equal 200, update.status
    assert_includes update["set-cookie"], "better-auth.session_token_multi-old=; Path=/; Max-Age=0"
    assert_equal ["api-key", "multi-session"], JSON.parse(response.body).fetch("settings").fetch("disabled_plugins")
    refute data.fetch("plugins").any? { |plugin| plugin.fetch("id") == "api-key" }
    assert data.fetch("available").any? { |plugin| plugin.fetch("id") == "api-key" }
    assert_equal ["api-key", "multi-session"], data.fetch("disabled")
  end

  def test_dashboard_does_not_clear_auth_cookies_when_settings_are_unchanged
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")
    request = Rack::MockRequest.new(app)
    settings = {database: "sqlite", rate_adapter: "memory", rate_window: 10, rate_max: 100, disabled_plugins: []}
    cookie = BetterAuthExamples::Settings.set_cookie_header(settings).split(";").first

    update = request.post(
      "/example/settings",
      "CONTENT_TYPE" => "application/json",
      "HTTP_COOKIE" => "#{cookie}; better-auth.session_token=existing.signed",
      :input => JSON.generate(settings)
    )

    assert_equal 200, update.status
    refute_includes update["set-cookie"].to_s, "better-auth.session_token=; Path=/; Max-Age=0"
  end

  def test_dashboard_rate_limit_setting_change_preserves_sqlite_database_and_session_cookie
    root_path = File.expand_path("tmp/sqlite-rate-setting-change", __dir__)
    FileUtils.rm_rf(root_path)
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: root_path
    )
    settings = BetterAuthExamples::Settings.normalize(database: "sqlite", rate_adapter: "memory", rate_window: 10, rate_max: 100)
    auth = registry.auth_for(settings)
    signup = auth.api.sign_up_email(
      body: {email: "sqlite-rate-preserve@example.com", password: "password123", name: "SQLite Preserve", captchaResponse: "example-token"},
      return_headers: true
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")
    request = Rack::MockRequest.new(app)
    settings_cookie = BetterAuthExamples::Settings.set_cookie_header(settings).split(";").first
    session_cookie = cookie_header(signup.fetch(:headers).fetch("set-cookie"))

    update = request.post(
      "/example/settings",
      "CONTENT_TYPE" => "application/json",
      "HTTP_COOKIE" => "#{settings_cookie}; #{session_cookie}",
      :input => JSON.generate(settings.merge(rate_window: 20))
    )
    next_cookie = update["set-cookie"].to_s.lines.find { |line| line.include?(BetterAuthExamples::Settings::COOKIE_NAME) }.to_s.split(";").first
    next_auth = registry.auth_for(settings.merge(rate_window: 20))
    session = next_auth.api.get_session(headers: {"cookie" => session_cookie}, query: {disableCookieCache: true})

    assert_equal 200, update.status
    refute_includes update["set-cookie"].to_s, "better-auth.session_token=; Path=/; Max-Age=0"
    assert_equal "sqlite-rate-preserve@example.com", session.fetch(:user).fetch("email")
    assert_equal 1, next_auth.context.adapter.connection.execute(%(SELECT COUNT(*) AS count FROM users;)).first.fetch("count")
    assert_equal "20", JSON.parse(request.get("/example/settings", "HTTP_COOKIE" => next_cookie).body).fetch("settings").fetch("rate_window").to_s
  end

  def test_dashboard_database_provider_change_does_not_drop_previous_sqlite_database
    root_path = File.expand_path("tmp/sqlite-provider-change", __dir__)
    FileUtils.rm_rf(root_path)
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: root_path
    )
    settings = BetterAuthExamples::Settings.normalize(database: "sqlite", rate_adapter: "memory", rate_window: 10, rate_max: 100)
    auth = registry.auth_for(settings)
    auth.api.sign_up_email(
      body: {email: "sqlite-provider-preserve@example.com", password: "password123", name: "SQLite Provider", captchaResponse: "example-token"},
      return_headers: true
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")
    request = Rack::MockRequest.new(app)
    settings_cookie = BetterAuthExamples::Settings.set_cookie_header(settings).split(";").first

    update = request.post(
      "/example/settings",
      "CONTENT_TYPE" => "application/json",
      "HTTP_COOKIE" => settings_cookie,
      :input => JSON.generate(settings.merge(database: "memory"))
    )
    sqlite_auth = registry.auth_for(settings)

    assert_equal 200, update.status
    assert_includes update["set-cookie"].to_s, "better-auth.session_token=; Path=/; Max-Age=0"
    assert_equal 1, sqlite_auth.context.adapter.connection.execute(%(SELECT COUNT(*) AS count FROM users;)).first.fetch("count")
  end

  def test_dashboard_can_promote_current_user_for_admin_endpoint_testing
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    settings = BetterAuthExamples::Settings.normalize(database: "memory")
    auth = registry.auth_for(settings)
    signup = auth.api.sign_up_email(
      body: {email: "dashboard-admin@example.com", password: "password123", name: "Dashboard Admin", captchaResponse: "example-token"},
      return_headers: true
    )
    cookie = cookie_header(signup.fetch(:headers).fetch("set-cookie"))
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")

    response = Rack::MockRequest.new(app).post("/example/admin/promote-current-user", "HTTP_COOKIE" => cookie)
    user = auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true}).fetch(:user)

    assert_equal 200, response.status
    assert_equal true, JSON.parse(response.body).fetch("ok")
    assert_equal "admin", user.fetch("role")
  end

  def test_dashboard_can_reset_and_seed_example_database
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")
    request = Rack::MockRequest.new(app)

    response = request.post("/example/reset-and-seed", "CONTENT_TYPE" => "application/json", :input => "{}")
    body = JSON.parse(response.body)
    users = JSON.parse(request.get("/example/users").body).fetch("users")

    assert_equal 200, response.status
    assert_equal true, body.fetch("ok")
    assert_operator body.fetch("users").length, :>=, 10
    assert_operator body.fetch("organizations").length, :>=, 3
    assert users.any? { |user| user.fetch("role") == "admin" }
    assert users.any? { |user| user.fetch("organizations").any? { |org| org.fetch("role") == "owner" } }
    assert users.any? { |user| user.fetch("organizations").empty? }

    tables = registry.explore(BetterAuthExamples::Settings.normalize(database: "memory")).fetch(:tables).to_h { |table| [table.fetch(:name), table.fetch(:count)] }
    %w[api_keys device_codes jwks oauth_access_tokens oauth_clients oauth_consents oauth_refresh_tokens passkeys scim_providers sso_providers subscriptions two_factors verifications wallet_addresses].each do |table|
      assert_operator tables.fetch(table), :>=, 1
    end
  end

  def test_dashboard_lists_seeded_organizations_with_members
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")
    request = Rack::MockRequest.new(app)
    request.post("/example/reset-and-seed", "CONTENT_TYPE" => "application/json", :input => "{}")

    response = request.get("/example/organizations")
    organizations = JSON.parse(response.body).fetch("organizations")
    acme = organizations.find { |organization| organization.fetch("slug") == "acme-labs" }

    assert_equal 200, response.status
    assert_operator organizations.length, :>=, 3
    assert_operator acme.fetch("members").length, :>=, 4
    assert acme.fetch("members").any? { |member| member.fetch("email") == "billing@example.test" && member.fetch("role") == "admin" }
  end

  def test_dashboard_can_sign_in_as_seeded_user
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    app = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")
    request = Rack::MockRequest.new(app)
    request.post("/example/reset-and-seed", "CONTENT_TYPE" => "application/json", :input => "{}")
    user = JSON.parse(request.get("/example/users").body).fetch("users").find { |entry| entry.fetch("email") == "admin@example.test" }

    response = request.post(
      "/example/users/sign-in",
      "CONTENT_TYPE" => "application/json",
      :input => JSON.generate(user_id: user.fetch("id"))
    )
    session = registry.auth_for(BetterAuthExamples::Settings.normalize(database: "memory"))
      .api.get_session(headers: {"cookie" => cookie_header(response["set-cookie"])})

    assert_equal 200, response.status
    assert_equal "admin@example.test", session.fetch(:user).fetch("email")
  end

  def test_api_key_create_works_for_signed_in_dashboard_user
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    auth = registry.auth_for(BetterAuthExamples::Settings.normalize(database: "memory"))
    signup = auth.api.sign_up_email(
      body: {email: "dashboard-api-key@example.com", password: "password123", name: "API Key User", captchaResponse: "example-token"},
      return_headers: true
    )
    cookie = cookie_header(signup.fetch(:headers).fetch("set-cookie"))
    app = BetterAuthExamples::DynamicAuth.new(registry)

    response = Rack::MockRequest.new(app).post(
      "/api/auth/api-key/create",
      "HTTP_COOKIE" => cookie,
      "HTTP_ORIGIN" => "http://127.0.0.1:3456",
      "CONTENT_TYPE" => "application/json",
      :input => JSON.generate(name: "Dashboard key")
    )
    body = JSON.parse(response.body)

    assert_equal 200, response.status
    assert_equal "Dashboard key", body.fetch("name")
    assert body.fetch("key")
  end

  def test_settings_round_trip_sanitizes_supported_values
    settings = BetterAuthExamples::Settings.normalize(
      "database" => "postgres",
      "rate_adapter" => "redis",
      "rate_window" => "25",
      "rate_max" => "9",
      "disabled_plugins" => ["multi-session", "api-key", "api-key", ""]
    )

    assert_equal "postgres", settings[:database]
    assert_equal "redis", settings[:rate_adapter]
    assert_equal 25, settings[:rate_window]
    assert_equal 9, settings[:rate_max]
    assert_equal ["api-key", "multi-session"], settings[:disabled_plugins]

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

  def test_auth_registry_excludes_disabled_plugins_from_dynamic_auth
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://example.test",
      root_path: File.expand_path("tmp", __dir__)
    )
    settings = BetterAuthExamples::Settings.normalize(database: "memory", disabled_plugins: ["api-key"])

    auth = registry.auth_for(settings)
    plugin_ids = auth.context.options.plugins.map(&:id)

    refute_includes plugin_ids, "api-key"
    assert_includes plugin_ids, "admin"
  end

  def test_dynamic_auth_removes_disabled_plugin_endpoints
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    settings = BetterAuthExamples::Settings.normalize(database: "memory", disabled_plugins: ["api-key"])
    cookie = BetterAuthExamples::Settings.set_cookie_header(settings).split(";").first
    app = BetterAuthExamples::DynamicAuth.new(registry)

    response = Rack::MockRequest.new(app).post(
      "/api/auth/api-key/create",
      "HTTP_COOKIE" => cookie,
      "HTTP_ORIGIN" => "http://127.0.0.1:3456",
      "CONTENT_TYPE" => "application/json",
      :input => JSON.generate(name: "Disabled key")
    )

    assert_equal 404, response.status
  end

  def test_auth_registry_uses_dynamic_localhost_base_url
    with_env("BETTER_AUTH_URL" => nil) do
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
  end

  def test_auth_registry_keeps_loopback_trusted_origins_when_base_url_env_is_set
    with_env("BETTER_AUTH_URL" => "http://localhost:3456") do
      registry = BetterAuthExamples::AuthRegistry.new(
        app_name: "Test Example",
        base_url: "http://localhost:3456",
        root_path: File.expand_path("tmp", __dir__)
      )

      auth = registry.auth_for(BetterAuthExamples::Settings.normalize(database: "memory"))

      assert auth.options.trusted_origin?("http://127.0.0.1:3456")
      assert auth.options.trusted_origin?("http://localhost:3456")
    end
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
    assert api_key.fetch("examples").any? { |example| example.fetch("label") == "Create key for current user" }
    assert stripe.fetch("examples").any? { |example| example.fetch("path") == "/api/auth/subscription/list" }
    assert_equal admin.fetch("endpoints").length, admin.fetch("endpoint_actions").length
    assert admin.fetch("endpoint_actions").any? { |action| action.fetch("method") == "GET" && action.fetch("path") == "/api/auth/admin/list-users" }
  end

  def test_plugin_sign_up_workflows_include_local_captcha_response
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )
    auth = registry.auth_for(BetterAuthExamples::Settings.normalize(database: "memory"))
    plugins = BetterAuthExamples::PluginCatalog.metadata_for(auth)
    sign_up_examples = plugins.flat_map { |plugin| plugin.fetch(:examples, []) }
      .select { |example| example[:method] == "POST" && example[:path] == "/api/auth/sign-up/email" }

    refute_empty sign_up_examples
    sign_up_examples.each do |example|
      assert_equal "example-token", example.fetch(:body).fetch("captchaResponse")
    end
  end

  def test_memory_database_explorer_uses_plugin_schema
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: File.expand_path("tmp", __dir__)
    )

    data = registry.explore(BetterAuthExamples::Settings.normalize(database: "memory"))
    table_names = data.fetch(:tables).map { |table| table.fetch(:name) }

    assert_includes table_names, "organizations"
    assert_includes table_names, "two_factors"
    assert_includes table_names, "oauth_clients"
    assert_includes table_names, "api_keys"
    refute_includes table_names, "organization"
    refute_includes table_names, "twoFactor"
    refute_includes table_names, "oauthClient"
    refute_includes table_names, "apikey"
  end

  def test_sql_database_explorer_hides_legacy_plugin_table_names
    root_path = File.expand_path("tmp/sql-table-names", __dir__)
    FileUtils.rm_rf(root_path)
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: root_path
    )

    auth = registry.auth_for(BetterAuthExamples::Settings.normalize(database: "sqlite"))
    auth.context.adapter.connection.execute(%(CREATE TABLE IF NOT EXISTS "oauthClient" ("id" text PRIMARY KEY)))
    auth.context.adapter.connection.execute(%(CREATE TABLE IF NOT EXISTS "organization" ("id" text PRIMARY KEY)))

    data = registry.explore(BetterAuthExamples::Settings.normalize(database: "sqlite"))
    table_names = data.fetch(:tables).map { |table| table.fetch(:name) }

    assert_includes table_names, "oauth_clients"
    assert_includes table_names, "organizations"
    refute_includes table_names, "oauthClient"
    refute_includes table_names, "organization"
  end

  def test_sqlite_example_prepare_adds_plugin_columns_to_existing_tables
    root_path = File.expand_path("tmp/sqlite-pending-schema", __dir__)
    FileUtils.rm_rf(root_path)
    FileUtils.mkdir_p(File.join(root_path, "tmp"))
    sqlite_path = File.join(root_path, "tmp", "better_auth_example.sqlite3")

    base_auth = BetterAuth.auth(
      app_name: "Test Example",
      secret: "better-auth-example-secret-12345678901234567890",
      base_url: "http://localhost:3456",
      database: ->(options) { BetterAuth::Adapters::SQLite.new(options, path: sqlite_path) },
      email_and_password: {enabled: true},
      session: {store_session_in_database: true},
      verification: {store_in_database: true},
      telemetry: {disabled: true}
    )
    BetterAuthExamples::DatabaseProviders.prepare!(base_auth, root_path: root_path)

    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: root_path
    )
    auth = registry.auth_for(BetterAuthExamples::Settings.normalize(database: "sqlite", rate_adapter: "memory"))

    result = auth.api.sign_up_email(
      body: {email: "pending-schema@example.com", password: "password123", name: "Pending Schema"},
      return_headers: true
    )
    columns = auth.context.adapter.connection.execute(%(PRAGMA table_info("users");)).map { |row| row["name"] || row[:name] }

    response = result[:response] || result["response"]
    user = response[:user] || response["user"]

    assert_equal "pending-schema@example.com", user.fetch("email")
    assert_includes columns, "example_role"
    assert_includes columns, "nickname"
  end

  def test_mongodb_database_explorer_lists_schema_tables_without_argument_errors
    require "mongo"
    require "better_auth/mongodb"

    root_path = File.expand_path("tmp/mongodb-explorer", __dir__)
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: root_path
    )

    data = registry.explore(BetterAuthExamples::Settings.normalize(database: "mongodb"), table: "accounts")
    accounts = data.fetch(:tables).find { |table| table.fetch(:name) == "accounts" }

    assert_equal "mongodb", data.fetch(:provider)
    assert accounts
    assert_nil accounts[:error]
  rescue LoadError
    skip "MongoDB dependencies are not installed"
  rescue Mongo::Error::NoServerAvailable
    skip "MongoDB test service is not available"
  end

  def test_mongodb_example_provider_serves_social_callback_flow_over_rack
    require "mongo"
    require "better_auth/mongodb"

    database_name = "better_auth_example_social_test_#{Time.now.to_i}_#{rand(10_000)}"
    mongo_url = "mongodb://127.0.0.1:27018/#{database_name}?directConnection=true"
    original_configured = BetterAuthExamples::SocialProviderCatalog.method(:configured)
    BetterAuthExamples::SocialProviderCatalog.define_singleton_method(:configured) do
      {
        github: {
          id: "github",
          create_authorization_url: lambda do |data|
            "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}"
          end,
          validate_authorization_code: ->(_data) { {accessToken: "github-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: 123_456_789,
                email: "mongodb-example-social@example.com",
                name: "MongoDB Example Social",
                emailVerified: true
              }
            }
          }
        }
      }
    end

    with_env(
      "BETTER_AUTH_EXAMPLE_MONGODB_URL" => mongo_url,
      "BETTER_AUTH_URL" => "http://localhost:3456"
    ) do
      registry = BetterAuthExamples::AuthRegistry.new(
        app_name: "Test Example",
        base_url: "http://localhost:3456",
        root_path: File.expand_path("tmp/mongodb-social-example", __dir__)
      )
      dashboard = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Test")
      app = BetterAuthExamples::CompositeApp.new(
        dashboard: dashboard,
        auth: BetterAuthExamples::DynamicAuth.new(registry)
      )
      request = Rack::MockRequest.new(app)
      settings_cookie = BetterAuthExamples::Settings
        .set_cookie_header(BetterAuthExamples::Settings.normalize(database: "mongodb", rate_adapter: "memory"))
        .split(";")
        .first

      sign_in = request.post(
        "/api/auth/sign-in/social",
        "CONTENT_TYPE" => "application/json",
        "HTTP_ORIGIN" => "http://localhost:3456",
        "HTTP_COOKIE" => settings_cookie,
        :input => JSON.generate(provider: "github", callbackURL: "/dashboard", newUserCallbackURL: "/welcome")
      )
      assert_equal 200, sign_in.status, sign_in.body

      sign_in_payload = JSON.parse(sign_in.body)
      state = URI.decode_www_form(URI.parse(sign_in_payload.fetch("url")).query).assoc("state").last
      callback = request.get(
        "/api/auth/callback/github?#{URI.encode_www_form(code: "oauth-code", state: state)}",
        "HTTP_COOKIE" => "#{settings_cookie}; #{cookie_header(sign_in["set-cookie"])}"
      )
      session = request.get(
        "/api/auth/get-session",
        "HTTP_COOKIE" => "#{settings_cookie}; #{cookie_header(callback["set-cookie"])}"
      )
      session_payload = JSON.parse(session.body)

      assert_equal 302, callback.status
      assert_equal "/welcome", callback["location"]
      assert_equal 200, session.status
      assert_equal "mongodb-example-social@example.com", session_payload.fetch("user").fetch("email")
    end
  rescue LoadError
    skip "MongoDB dependencies are not installed"
  rescue Mongo::Error::NoServerAvailable
    skip "MongoDB test service is not available"
  ensure
    BetterAuthExamples::SocialProviderCatalog.define_singleton_method(:configured) { original_configured.call } if original_configured
  end

  def test_mysql_example_provider_prepares_schema_and_serves_auth_flow
    require "mysql2"

    root_path = File.expand_path("tmp/mysql-example-provider", __dir__)
    registry = BetterAuthExamples::AuthRegistry.new(
      app_name: "Test Example",
      base_url: "http://localhost:3456",
      root_path: root_path
    )
    settings = BetterAuthExamples::Settings.normalize(database: "mysql", rate_adapter: "memory")
    auth = registry.auth_for(settings)

    email = "mysql-example-provider-#{Time.now.to_i}-#{rand(10_000)}@example.com"
    signup = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "MySQL Example", captchaResponse: "example-token"},
      return_headers: true
    )
    cookie = cookie_header(signup.fetch(:headers).fetch("set-cookie"))
    session = auth.api.get_session(headers: {"cookie" => cookie})

    assert_equal email, signup.fetch(:response).fetch(:user).fetch("email")
    assert_equal signup.fetch(:response).fetch(:token), session.fetch(:session).fetch("token")
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
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

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end
end

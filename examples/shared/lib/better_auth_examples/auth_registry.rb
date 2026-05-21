# frozen_string_literal: true

require "better_auth"

module BetterAuthExamples
  class AuthRegistry
    attr_reader :app_name, :base_url, :root_path

    def initialize(app_name:, base_url:, root_path:)
      @app_name = app_name
      @base_url = base_url
      @root_path = root_path
      @mutex = Mutex.new
      @auths = {}
    end

    def auth_for(settings)
      settings = Settings.normalize(settings)
      key = cache_key(settings)
      @mutex.synchronize do
        @auths[key] ||= build_auth(settings)
      end
    end

    def reset!(settings)
      settings = Settings.normalize(settings)
      key = cache_key(settings)
      @mutex.synchronize do
        auth = @auths.delete(key) || build_auth(settings, prepare: false)
        DatabaseProviders.reset!(auth, root_path: root_path) if auth
      end
    end

    def reload!(settings)
      settings = Settings.normalize(settings)
      key = cache_key(settings)
      @mutex.synchronize do
        @auths.delete(key)
      end
    end

    def reset_database!(settings)
      settings = Settings.normalize(settings)
      key = cache_key(settings)
      @mutex.synchronize do
        auth = @auths.delete(key) || build_auth(settings, prepare: false)
        DatabaseProviders.reset!(auth, root_path: root_path)
      end
      auth_for(settings)
    end

    def explore(settings, table: nil, limit: nil, offset: nil)
      DatabaseProviders.explore(auth_for(settings), table: table, limit: limit, offset: offset)
    end

    def delete_records!(settings, table_name, ids)
      DatabaseProviders.delete_records!(auth_for(settings), table_name, ids)
    end

    private

    def cache_key(settings)
      [
        settings[:database],
        settings[:rate_adapter],
        settings[:rate_window],
        settings[:rate_max],
        Array(settings[:disabled_plugins]).sort.join(",")
      ].join(":")
    end

    def build_auth(settings, prepare: true)
      auth = BetterAuth.auth(
        app_name: app_name,
        secret: ENV.fetch("BETTER_AUTH_SECRET", "better-auth-example-secret-12345678901234567890"),
        base_url: base_url_config,
        trusted_origins: loopback_trusted_origins,
        database: ->(options) { DatabaseProviders.adapter_for(settings[:database], options, root_path: root_path) },
        email_and_password: {enabled: true},
        session: {store_session_in_database: true},
        verification: {store_in_database: true},
        secondary_storage: RateLimitSettings.secondary_storage(settings),
        rate_limit: RateLimitSettings.config(settings),
        plugins: PluginCatalog.plugins(app_name: app_name, disabled_plugins: settings[:disabled_plugins]),
        social_providers: SocialProviderCatalog.configured,
        telemetry: {disabled: true}
      )
      DatabaseProviders.prepare!(auth, root_path: root_path) if prepare
      auth
    end

    def base_url_config
      return ENV["BETTER_AUTH_URL"] if ENV["BETTER_AUTH_URL"] && !ENV["BETTER_AUTH_URL"].empty?

      {
        allowed_hosts: ["localhost:*", "127.0.0.1:*", "[::1]:*"],
        protocol: "http",
        fallback: base_url
      }
    end

    def loopback_trusted_origins
      ["http://localhost:*", "http://127.0.0.1:*", "http://[::1]:*"]
    end
  end
end

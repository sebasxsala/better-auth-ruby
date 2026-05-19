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
        auth = @auths[key]
        DatabaseProviders.reset!(auth, root_path: root_path) if auth
        @auths.delete(key)
      end
    end

    def reset_database!(settings)
      auth = auth_for(settings)
      @mutex.synchronize do
        DatabaseProviders.reset!(auth, root_path: root_path)
        @auths.delete(cache_key(settings))
      end
      auth_for(settings)
    end

    def explore(settings)
      DatabaseProviders.explore(auth_for(settings))
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
        settings[:rate_max]
      ].join(":")
    end

    def build_auth(settings)
      auth = BetterAuth.auth(
        app_name: app_name,
        secret: ENV.fetch("BETTER_AUTH_SECRET", "better-auth-example-secret-12345678901234567890"),
        base_url: base_url_config,
        database: ->(options) { DatabaseProviders.adapter_for(settings[:database], options, root_path: root_path) },
        email_and_password: {enabled: true},
        session: {store_session_in_database: true},
        verification: {store_in_database: true},
        secondary_storage: RateLimitSettings.secondary_storage(settings),
        rate_limit: RateLimitSettings.config(settings),
        plugins: PluginCatalog.plugins(app_name: app_name),
        social_providers: SocialProviderCatalog.configured,
        telemetry: {disabled: true}
      )
      DatabaseProviders.prepare!(auth, root_path: root_path)
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
  end
end

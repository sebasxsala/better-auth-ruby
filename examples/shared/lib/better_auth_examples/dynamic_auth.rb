# frozen_string_literal: true

require "rack/request"

module BetterAuthExamples
  class DynamicAuth
    attr_reader :registry

    def initialize(registry)
      @registry = registry
    end

    def call(env)
      registry.auth_for(settings_from_env(env)).call(env)
    end

    private

    def settings_from_env(env)
      cookies = BetterAuth::Cookies.parse_cookies(env["HTTP_COOKIE"])
      return Settings.from_cookie(cookies[Settings::COOKIE_NAME]) if cookies.key?(Settings::COOKIE_NAME)

      Settings.from_request(Rack::Request.new(env))
    end
  end
end

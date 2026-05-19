# frozen_string_literal: true

require "better_auth/hanami"
require_relative "../../shared/lib/better_auth_examples"

module HanamiApp
  class Routes < Hanami::Routes
    include BetterAuth::Hanami::Routing

    registry = BetterAuthExamples.registry(
      app_name: "Better Auth Hanami Example",
      base_url: ENV.fetch("BETTER_AUTH_URL", "http://localhost:2300"),
      root_path: File.expand_path("..", __dir__)
    )
    dynamic_auth = BetterAuthExamples::DynamicAuth.new(registry)
    dashboard = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Hanami")

    better_auth auth: dynamic_auth, at: "/api/auth"

    get "/", to: dashboard
    get "/example/settings", to: dashboard
    post "/example/settings", to: dashboard
    get "/example/database", to: dashboard
    post "/example/database/delete", to: dashboard
    get "/example/plugins", to: dashboard
    post "/example/plugins/clear-deliveries", to: dashboard
    get "/example/social-providers", to: dashboard
    post "/example/reset", to: dashboard
  end
end

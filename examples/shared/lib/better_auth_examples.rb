# frozen_string_literal: true

require_relative "better_auth_examples/env_loader"
BetterAuthExamples::EnvLoader.load!

require_relative "better_auth_examples/settings"
require_relative "better_auth_examples/rate_limit_settings"
require_relative "better_auth_examples/database_providers"
require_relative "better_auth_examples/plugin_catalog"
require_relative "better_auth_examples/social_provider_catalog"
require_relative "better_auth_examples/auth_registry"
require_relative "better_auth_examples/dynamic_auth"
require_relative "better_auth_examples/dashboard_app"
require_relative "better_auth_examples/composite_app"

module BetterAuthExamples
  DEFAULT_BASE_PATH = "/api/auth"

  def self.registry(app_name:, base_url:, root_path:)
    AuthRegistry.new(app_name: app_name, base_url: base_url, root_path: root_path)
  end
end

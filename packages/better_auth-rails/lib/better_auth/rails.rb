# frozen_string_literal: true

require "better_auth"
require_relative "rails/version"
require_relative "rails/option_builder"
require_relative "rails/configuration"
require_relative "rails/migration"
require_relative "rails/active_record_adapter"
require_relative "rails/mounted_app"
require_relative "rails/routing"
require_relative "rails/controller_helpers"
require_relative "rails/railtie" if defined?(::Rails::Railtie)

module BetterAuth
  module Rails
    class << self
      def configuration
        @configuration ||= Configuration.new
      end

      def configure
        yield configuration
        @auth = nil
        @mounted_auth = nil
      end

      def auth(overrides = nil)
        options = configuration.to_auth_options
        return @auth ||= BetterAuth.auth(options) if overrides.nil? || overrides.empty?

        BetterAuth.auth(options.merge(overrides))
      end

      def register_auth(auth, mount_path:)
        mounted_auth[normalize_mount_path(mount_path)] = auth
      end

      def auth_for_mount(mount_path = nil)
        return mounted_auth[normalize_mount_path(mount_path)] if mount_path

        mounted_auth[configuration.base_path] || mounted_auth.values.first || auth
      end

      private

      def mounted_auth
        @mounted_auth ||= {}
      end

      def normalize_mount_path(path)
        normalized = path.to_s
        normalized = "/#{normalized}" unless normalized.start_with?("/")
        normalized = normalized.squeeze("/")
        (normalized == "/") ? normalized : normalized.delete_suffix("/")
      end
    end
  end
end

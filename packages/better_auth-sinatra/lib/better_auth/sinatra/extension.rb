# frozen_string_literal: true

module BetterAuth
  module Sinatra
    module Extension
      def self.registered(app)
        app.extend ClassMethods
        app.helpers Helpers
      end

      module ClassMethods
        def better_auth(at: BetterAuth::Configuration::DEFAULT_BASE_PATH, auth: nil, **overrides)
          mount_path = normalize_better_auth_mount_path(at)
          if mount_path == "/"
            raise ArgumentError,
              "better_auth mount path cannot be '/' (it would capture every request). " \
              "Use a prefix such as #{BetterAuth::Configuration::DEFAULT_BASE_PATH.inspect}."
          end
          raise ArgumentError, "better_auth is already configured for this app" if respond_to?(:better_auth_auth)

          config = BetterAuth::Sinatra.configuration.copy
          yield config if block_given?
          config.base_path = mount_path
          options = config.to_auth_options.merge(overrides).merge(base_path: mount_path)
          auth_instance = auth || BetterAuth.auth(options)

          set :better_auth_auth, auth_instance
          set :better_auth_mount_path, mount_path
          use BetterAuth::Sinatra::MountedApp, -> { settings.better_auth_auth }, mount_path: mount_path
        end

        private

        def normalize_better_auth_mount_path(path)
          normalized = path.to_s
          normalized = "/#{normalized}" unless normalized.start_with?("/")
          normalized = normalized.squeeze("/")
          (normalized == "/") ? normalized : normalized.delete_suffix("/")
        end
      end
    end
  end
end

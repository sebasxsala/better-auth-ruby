# frozen_string_literal: true

module BetterAuth
  module Rails
    module Routing
      def better_auth(auth: nil, at: BetterAuth::Configuration::DEFAULT_BASE_PATH)
        mount_path = normalize_better_auth_mount_path(at)
        auth ||= BetterAuth::Rails.auth(base_path: mount_path)
        BetterAuth::Rails.register_auth(auth, mount_path: mount_path)
        mount BetterAuth::Rails::MountedApp.new(auth, mount_path: mount_path), at: mount_path
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

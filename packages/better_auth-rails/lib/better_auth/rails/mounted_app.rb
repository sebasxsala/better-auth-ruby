# frozen_string_literal: true

require "json"

module BetterAuth
  module Rails
    class MountedApp
      def initialize(auth, mount_path:)
        @auth = auth
        @mount_path = normalize_path(mount_path)
      end

      def call(env)
        @auth.call(env.merge("PATH_INFO" => mounted_path_info(env)))
      rescue BetterAuth::APIError, JSON::ParserError
        raise
      rescue => error
        handle_unexpected_error(error, env)
      end

      private

      def mounted_path_info(env)
        path_info = normalize_path(env["PATH_INFO"])
        return path_info if path_info == @mount_path || path_info.start_with?("#{@mount_path}/")

        normalize_path("#{@mount_path}/#{path_info.delete_prefix("/")}")
      end

      def normalize_path(path)
        normalized = path.to_s
        normalized = "/#{normalized}" unless normalized.start_with?("/")
        normalized = normalized.squeeze("/")
        normalized = normalized.delete_suffix("/") unless normalized == "/"
        normalized.empty? ? "/" : normalized
      end

      def handle_unexpected_error(error, env)
        options = @auth.options
        on_api_error = options.on_api_error || {}
        raise error if on_api_error[:throw] || on_api_error["throw"]

        callback = on_api_error[:on_error] || on_api_error[:onError] || on_api_error["on_error"] || on_api_error["onError"]
        callback.call(error, error_context(env)) if callback.respond_to?(:call)

        api_error = BetterAuth::APIError.new("INTERNAL_SERVER_ERROR")
        [
          api_error.status_code,
          {"content-type" => "application/json"},
          [JSON.generate(api_error.to_h)]
        ]
      end

      def error_context(env)
        path = mounted_path_info(env)
        route_path = if path == @mount_path
          "/"
        else
          path.delete_prefix(@mount_path)
        end
        Struct.new(:path, :env).new(normalize_path(route_path), env)
      end
    end
  end
end

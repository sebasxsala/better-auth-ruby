# frozen_string_literal: true

require "json"

module BetterAuth
  module Roda
    class MountedApp
      def initialize(auth, mount_path:)
        @auth = auth
        @mount_path = normalize_path(mount_path)
      end

      def mount_matches?(env)
        return false if @mount_path == "/"

        path_info = normalize_path(env["PATH_INFO"], trim: true)
        return true if path_info == @mount_path || path_info.start_with?("#{@mount_path}/")

        full = full_request_path(env)
        full == @mount_path || full.start_with?("#{@mount_path}/")
      end

      def call(env)
        @auth.call(next_env(env))
      rescue BetterAuth::APIError, JSON::ParserError
        raise
      rescue => error
        handle_unexpected_error(error, env)
      end

      private

      def next_env(env)
        rewritten_path = mounted_path_info(env)
        env.merge("PATH_INFO" => rewritten_path).tap do |next_env|
          next_env["SCRIPT_NAME"] = "" if shared_mount_rewrite?(env, rewritten_path)
        end
      end

      def full_request_path(env)
        script = env.fetch("SCRIPT_NAME", "").to_s
        path = env.fetch("PATH_INFO", "").to_s
        normalize_path("#{script}#{path}", trim: true)
      end

      def mounted_path_info(env)
        path_info = normalize_path(env["PATH_INFO"], trim: false)
        comparable_path = normalize_path(env["PATH_INFO"], trim: true)
        return path_info if comparable_path == @mount_path || comparable_path.start_with?("#{@mount_path}/")

        script_name = normalize_path(env["SCRIPT_NAME"], trim: true)
        prefix = (script_name == "/") ? @mount_path : script_name
        return path_info if comparable_path == prefix || comparable_path.start_with?("#{prefix}/")

        normalize_path("#{prefix}/#{path_info.delete_prefix("/")}", trim: false)
      end

      def shared_mount_rewrite?(env, rewritten_path)
        script_name = normalize_path(env["SCRIPT_NAME"], trim: true)
        original_path = normalize_path(env["PATH_INFO"], trim: true)
        script_name != "/" &&
          !original_path.start_with?("#{@mount_path}/") &&
          rewritten_path.start_with?("#{@mount_path}/")
      end

      def normalize_path(path, trim: true)
        normalized = path.to_s
        normalized = "/#{normalized}" unless normalized.start_with?("/")
        normalized = normalized.squeeze("/")
        normalized = normalized.delete_suffix("/") if trim && normalized != "/"
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

# frozen_string_literal: true

require "json"

class ::Roda
  module RodaPlugins
    module BetterAuthPlugin
      def self.configure(app)
        app.opts[:better_auth_configured] = false unless app.opts.key?(:better_auth_configured)
      end

      module ClassMethods
        def better_auth(at: BetterAuth::Configuration::DEFAULT_BASE_PATH, auth: nil, **overrides)
          mount_path = normalize_better_auth_mount_path(at)
          if mount_path == "/"
            raise ArgumentError,
              "better_auth mount path cannot be '/' (it would capture every request). " \
              "Use a prefix such as #{BetterAuth::Configuration::DEFAULT_BASE_PATH.inspect}."
          end
          if opts[:better_auth_configured] && opts[:better_auth_owner].equal?(self)
            raise ArgumentError, "better_auth is already configured for this app"
          end

          config = BetterAuth::Roda.configuration.copy
          yield config if block_given?
          config.base_path = mount_path
          options = config.to_auth_options.merge(overrides).merge(base_path: mount_path)
          auth_instance = auth || BetterAuth.auth(options)

          opts[:better_auth_auth] = auth_instance
          opts[:better_auth_mount_path] = mount_path
          opts[:better_auth_mounted_app] = BetterAuth::Roda::MountedApp.new(auth_instance, mount_path: mount_path)
          opts[:better_auth_owner] = self
          opts[:better_auth_configured] = true
        end

        private

        def normalize_better_auth_mount_path(path)
          normalized = path.to_s
          normalized = "/#{normalized}" unless normalized.start_with?("/")
          normalized = normalized.squeeze("/")
          (normalized == "/") ? normalized : normalized.delete_suffix("/")
        end
      end

      module RequestMethods
        def better_auth
          app = scope.opts[:better_auth_mounted_app]
          return unless app&.mount_matches?(env)

          halt app.call(env)
        end
      end

      module InstanceMethods
        def current_session
          data = better_auth_session_data
          data&.fetch(:session, nil) || data&.fetch("session", nil)
        end

        def current_user
          data = better_auth_session_data
          data&.fetch(:user, nil) || data&.fetch("user", nil)
        end

        def authenticated?
          !current_user.nil?
        end

        def require_authentication
          return true if authenticated?

          if prefers_json_response?
            error = BetterAuth::APIError.new("UNAUTHORIZED")
            request.halt [
              401,
              {"content-type" => "application/json"},
              [JSON.generate(error.to_h)]
            ]
          end

          request.halt [401, {}, [""]]
        end

        private

        def prefers_json_response?
          accept = request.env["HTTP_ACCEPT"].to_s
          return false if accept.empty? || accept == "*/*"

          preferred = accept.split(",").filter_map do |entry|
            media_type, *params = entry.split(";").map(&:strip)
            next unless media_type == "application/json" || media_type.end_with?("+json") || media_type == "text/html"

            q = params.find { |param| param.start_with?("q=") }&.split("=", 2)&.last&.to_f || 1.0
            [media_type, q]
          end.max_by { |_media_type, q| q }

          if preferred
            media_type, q = preferred
            return q.positive? && (media_type == "application/json" || media_type.end_with?("+json"))
          end

          accept.split(",").any? do |entry|
            media_type = entry.split(";", 2).first.to_s.strip
            media_type == "application/json" || media_type.end_with?("+json")
          end
        end

        def better_auth_session_data
          return request.env["better_auth.session"] if request.env.key?("better_auth.session")

          request.env["better_auth.session"] = resolve_better_auth_session
        end

        def resolve_better_auth_session
          auth = better_auth_auth
          result = auth.api.get_session(
            request: Rack::Request.new(request.env),
            method: "GET",
            as_response: true
          )
          return resolve_better_auth_response(result) if result.respond_to?(:headers) && result.respond_to?(:body)

          apply_better_auth_response_headers(result[:headers] || result["headers"] || {})
          result[:response] || result["response"]
        end

        def resolve_better_auth_response(auth_response)
          apply_better_auth_response_headers(auth_response.headers || {})
          body = auth_response.body.respond_to?(:join) ? auth_response.body.join : auth_response.body.to_s
          payload = body.empty? ? nil : JSON.parse(body)
          raise_better_auth_response_error(auth_response, payload) if auth_response.status.to_i >= 400

          payload
        end

        def raise_better_auth_response_error(auth_response, payload)
          payload = payload.is_a?(Hash) ? payload : {}
          status = BetterAuth::APIError::STATUS_CODES.key(auth_response.status.to_i) || "INTERNAL_SERVER_ERROR"
          raise BetterAuth::APIError.new(
            status,
            message: payload["message"],
            code: payload["code"],
            headers: auth_response.headers || {}
          )
        end

        def apply_better_auth_response_headers(headers)
          set_cookie = headers["set-cookie"] || headers["Set-Cookie"] || headers[:set_cookie]
          return if set_cookie.to_s.empty?

          existing = response.headers["set-cookie"].to_s
          response.headers["set-cookie"] = [existing, set_cookie.to_s].reject(&:empty?).join("\n")
        end

        def better_auth_auth
          opts[:better_auth_auth] || BetterAuth::Roda.auth
        end
      end
    end

    register_plugin(:better_auth, BetterAuthPlugin)
  end
end

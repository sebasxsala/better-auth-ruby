# frozen_string_literal: true

require "json"

module BetterAuth
  module Grape
    module Helpers
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

        error = BetterAuth::APIError.new("UNAUTHORIZED")
        if prefers_json_response?
          error!(error.to_h, 401, {"content-type" => "application/json"})
        else
          error!("", 401)
        end
      end

      private

      def prefers_json_response?
        accept = env["HTTP_ACCEPT"].to_s
        return false if accept.empty? || accept == "*/*"

        accept.split(",").any? do |entry|
          media_type = entry.split(";", 2).first.to_s.strip
          media_type == "application/json" || media_type.end_with?("+json")
        end
      end

      def better_auth_session_data
        return env["better_auth.session"] if env.key?("better_auth.session")

        env["better_auth.session"] = resolve_better_auth_session
      end

      def resolve_better_auth_session
        auth = better_auth_auth
        result = auth.api.get_session(
          request: Rack::Request.new(env),
          method: "GET",
          as_response: true
        )
        return resolve_better_auth_response(result) if result.respond_to?(:headers) && result.respond_to?(:body)

        apply_better_auth_response_headers(result[:headers] || result["headers"] || {})
        result[:response] || result["response"]
      end

      def resolve_better_auth_response(response)
        apply_better_auth_response_headers(response.headers || {})
        body = response.body.respond_to?(:join) ? response.body.join : response.body.to_s
        payload = body.empty? ? nil : JSON.parse(body)
        raise_better_auth_response_error(response, payload) if response.status.to_i >= 400

        payload
      end

      def raise_better_auth_response_error(response, payload)
        payload = payload.is_a?(Hash) ? payload : {}
        status = BetterAuth::APIError::STATUS_CODES.key(response.status.to_i) || "INTERNAL_SERVER_ERROR"
        raise BetterAuth::APIError.new(
          status,
          message: payload["message"],
          code: payload["code"],
          headers: response.headers || {}
        )
      end

      def apply_better_auth_response_headers(headers)
        set_cookie = headers["set-cookie"] || headers["Set-Cookie"] || headers[:set_cookie]
        return if set_cookie.to_s.empty?

        existing = header["Set-Cookie"].to_s
        header "Set-Cookie", [existing, set_cookie.to_s].reject(&:empty?).join("\n")
        env["better_auth.set_cookie"] = [env["better_auth.set_cookie"], set_cookie.to_s].compact.join("\n")
      end

      def better_auth_auth
        self.class.respond_to?(:better_auth_auth) ? self.class.better_auth_auth : BetterAuth::Grape.auth
      end
    end
  end
end

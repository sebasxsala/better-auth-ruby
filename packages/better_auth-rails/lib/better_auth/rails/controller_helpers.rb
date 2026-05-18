# frozen_string_literal: true

module BetterAuth
  module Rails
    module ControllerHelpers
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

        head(:unauthorized) if respond_to?(:head)
        false
      end

      private

      def better_auth_auth
        BetterAuth::Rails.auth_for_mount
      end

      def better_auth_session_data
        return request.env["better_auth.session"] if request.env.key?("better_auth.session")

        request.env["better_auth.session"] = resolve_better_auth_session
      end

      def resolve_better_auth_session
        auth_context = better_auth_auth.context
        auth_context.prepare_for_request!(request) if auth_context.respond_to?(:prepare_for_request!)
        context = BetterAuth::Endpoint::Context.new(
          path: request.path,
          method: request.request_method,
          query: request.query_parameters,
          body: {},
          params: {},
          headers: {"cookie" => request.get_header("HTTP_COOKIE")},
          context: auth_context,
          request: request
        )
        BetterAuth::Session.find_current(context, disable_refresh: true)
      ensure
        copy_better_auth_response_headers(context) if defined?(context) && context
        auth_context.clear_runtime! if defined?(auth_context) && auth_context&.respond_to?(:clear_runtime!)
      end

      def copy_better_auth_response_headers(context)
        return unless respond_to?(:response) && response

        context.response_headers.each do |key, value|
          write_better_auth_response_header(key, value)
        end
      end

      def write_better_auth_response_header(key, value)
        header_name = canonical_response_header(key)
        if response.respond_to?(:set_header)
          response.set_header(header_name, value)
        elsif response.respond_to?(:headers)
          response.headers[header_name] = value
        end
      end

      def canonical_response_header(key)
        return "Set-Cookie" if key.to_s.downcase == "set-cookie"

        key.to_s.split("-").map(&:capitalize).join("-")
      end
    end
  end
end

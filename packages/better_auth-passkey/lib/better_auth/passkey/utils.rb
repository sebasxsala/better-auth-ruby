# frozen_string_literal: true

require "uri"
require "webauthn"

module BetterAuth
  module Passkey
    module Utils
      module_function

      def normalize_hash(value)
        BetterAuth::Passkey::Schema.normalize_hash(value)
      end

      def relying_party(config, ctx, origin: nil)
        WebAuthn::RelyingParty.new(
          id: rp_id(config, ctx),
          name: config[:rp_name] || ctx.context.app_name,
          allowed_origins: allowed_origins(config, ctx, origin: origin)
        )
      end

      def origin(config, ctx)
        config[:origin] || ctx.headers["origin"]
      end

      def allowed_origins(config, ctx, origin: nil)
        _request_origin = origin
        configured = config.key?(:origin) ? config[:origin] : nil
        origins = configured || context_base_url(ctx)
        Array(origins).compact.map { |value| origin_for(value) }
      end

      def rp_id(config, ctx)
        return config[:rp_id] if config[:rp_id]

        base_url = context_base_url(ctx).to_s
        return "localhost" if base_url.empty?

        URI.parse(base_url).host || "localhost"
      rescue URI::InvalidURIError
        raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION")) if strict_base_url?(ctx)

        "localhost"
      end

      def authenticator_selection(config, query)
        selection = normalize_hash(config[:authenticator_selection] || {})
        attachment = query[:authenticator_attachment]
        selection[:authenticator_attachment] = attachment if attachment
        {
          resident_key: selection[:resident_key] || "preferred",
          user_verification: selection[:user_verification] || "preferred",
          authenticator_attachment: selection[:authenticator_attachment]
        }.compact
      end

      def validate_authenticator_attachment!(value)
        return if value.nil? || ["platform", "cross-platform"].include?(value)

        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES.fetch("VALIDATION_ERROR"))
      end

      def require_key!(body, key)
        return if body.key?(key)

        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES.fetch("VALIDATION_ERROR"))
      end

      def require_string!(body, key)
        require_key!(body, key)
        return if body[key].is_a?(String)

        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES.fetch("VALIDATION_ERROR"))
      end

      def resolve_registration_user(config, ctx, query)
        require_session = config.dig(:registration, :require_session) != false
        if require_session
          session = BetterAuth::Routes.current_session(ctx, allow_nil: true, sensitive: true, fresh: true)
          unless session&.dig(:user, "id")
            raise APIError.new("UNAUTHORIZED", message: BetterAuth::Passkey::ErrorCodes::PASSKEY_ERROR_CODES.fetch("SESSION_REQUIRED"))
          end
          user = session.fetch(:user)
          return registration_user_data(
            id: user.fetch("id"),
            name: user["email"] || user["id"],
            display_name: user["email"] || user["id"],
            email: user["email"]
          )
        end

        session = BetterAuth::Routes.current_session(ctx, allow_nil: true)
        if session
          user = session.fetch(:user)
          return registration_user_data(
            id: user.fetch("id"),
            name: user["email"] || user["id"],
            display_name: user["email"] || user["id"],
            email: user["email"]
          )
        end

        resolver = config.dig(:registration, :resolve_user)
        unless resolver.respond_to?(:call)
          raise APIError.new("BAD_REQUEST", message: BetterAuth::Passkey::ErrorCodes::PASSKEY_ERROR_CODES.fetch("RESOLVE_USER_REQUIRED"))
        end

        resolved = normalize_hash(call_callback(resolver, {ctx: ctx, context: query[:context]}) || {})
        unless resolved[:id].to_s != "" && resolved[:name].to_s != ""
          raise APIError.new("BAD_REQUEST", message: BetterAuth::Passkey::ErrorCodes::PASSKEY_ERROR_CODES.fetch("RESOLVED_USER_INVALID"))
        end

        registration_user_data(
          id: resolved[:id],
          name: resolved[:name],
          display_name: resolved[:display_name],
          email: resolved[:email]
        )
      end

      def registration_user_data(id:, name:, display_name: nil, email: nil)
        {
          "id" => id,
          "name" => name,
          "displayName" => display_name,
          "email" => email
        }.compact
      end

      def resolve_extensions(extensions, ctx)
        return nil unless extensions

        normalize_hash(extensions.respond_to?(:call) ? call_callback(extensions, {ctx: ctx}) : extensions)
      end

      def after_registration_verification_user_id(config, ctx, credential, challenge, response, session)
        user_data = challenge.fetch("userData")
        target_user_id = user_data.fetch("id")
        callback = config.dig(:registration, :after_verification)
        return target_user_id unless callback.respond_to?(:call)

        result = normalize_hash(call_callback(callback, {
          ctx: ctx,
          verification: credential,
          user: {
            id: user_data.fetch("id"),
            name: user_data["name"] || user_data.fetch("id"),
            display_name: user_data["displayName"] || user_data["display_name"]
          },
          client_data: response,
          context: challenge["context"]
        }) || {})
        returned_user_id = result[:user_id]
        return target_user_id if returned_user_id.nil? || returned_user_id == ""

        unless returned_user_id.is_a?(String) && returned_user_id.length.positive?
          raise APIError.new("BAD_REQUEST", message: BetterAuth::Passkey::ErrorCodes::PASSKEY_ERROR_CODES.fetch("RESOLVED_USER_INVALID"))
        end

        if session && returned_user_id != session.fetch(:user).fetch("id")
          raise APIError.new("UNAUTHORIZED", message: BetterAuth::Passkey::ErrorCodes::PASSKEY_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"))
        end

        returned_user_id
      end

      def call_callback(callback, data)
        return nil unless callback.respond_to?(:call)

        if callback.parameters.any? { |kind, _name| [:key, :keyreq, :keyrest].include?(kind) }
          callback.call(**data)
        else
          callback.call(data)
        end
      end

      def context_base_url(ctx)
        if ctx.context.respond_to?(:base_url)
          ctx.context.base_url
        else
          ctx.context.options.base_url
        end
      end

      def strict_base_url?(ctx)
        return ctx.context.passkey_strict_base_url? if ctx.context.respond_to?(:passkey_strict_base_url?)

        true
      end

      def origin_for(value)
        uri = URI.parse(value.to_s)
        if uri.scheme && uri.host
          BetterAuth::Configuration.origin_for(uri) || value.to_s
        else
          value.to_s
        end
      rescue URI::InvalidURIError
        value.to_s
      end
    end
  end
end

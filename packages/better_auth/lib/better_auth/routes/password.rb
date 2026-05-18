# frozen_string_literal: true

require "securerandom"
require "uri"

module BetterAuth
  module Routes
    PASSWORD_RESET_MESSAGE = "If this email exists in our system, check your email for the reset link"

    def self.request_password_reset
      Endpoint.new(
        path: "/request-password-reset",
        method: "POST",
        body_schema: request_body_schema(email_strings: %w[email]),
        metadata: {
          openapi: {
            operationId: "requestPasswordReset",
            description: "Request a password reset link",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  email: {type: "string", description: "The email address of the user"},
                  redirectTo: {type: ["string", "null"], description: "The URL to redirect to after reset"}
                },
                required: ["email"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "Password reset request processed",
                OpenAPI.status_response_schema(
                  {
                    message: {type: "string"}
                  },
                  required: ["status", "message"]
                )
              )
            }
          }
        }
      ) do |ctx|
        sender = ctx.context.options.email_and_password[:send_reset_password]
        unless sender.respond_to?(:call)
          raise APIError.new("BAD_REQUEST", code: "RESET_PASSWORD_DISABLED", message: BASE_ERROR_CODES["RESET_PASSWORD_DISABLED"])
        end

        body = normalize_hash(ctx.body)
        email = body["email"].to_s.downcase
        redirect_to = body["redirectTo"] || body["redirect_to"]
        validate_redirect_url!(ctx.context, redirect_to)
        found = ctx.context.internal_adapter.find_user_by_email(email, include_accounts: true)
        unless found
          SecureRandom.hex(12)
          ctx.context.internal_adapter.find_verification_value("dummy-verification-token")
          next ctx.json({status: true, message: PASSWORD_RESET_MESSAGE})
        end

        token = SecureRandom.hex(12)
        expires_in = ctx.context.options.email_and_password[:reset_password_token_expires_in] || 3600
        ctx.context.internal_adapter.create_verification_value(
          identifier: "reset-password:#{token}",
          value: found[:user]["id"],
          expiresAt: Time.now + expires_in.to_i
        )

        callback = redirect_to ? URI.encode_www_form_component(redirect_to) : ""
        url = "#{ctx.context.base_url}/reset-password/#{token}?callbackURL=#{callback}"
        begin
          sender.call({user: found[:user], url: url, token: token}, ctx.request)
        rescue => error
          log(ctx.context, :error, "RESET_PASSWORD_EMAIL_ERROR #{error.message}")
        end
        ctx.json({status: true, message: PASSWORD_RESET_MESSAGE})
      end
    end

    def self.request_password_reset_callback
      Endpoint.new(
        path: "/reset-password/:token",
        method: "GET",
        query_schema: request_query_schema(required_strings: %w[callbackURL]),
        metadata: {
          openapi: {
            operationId: "requestPasswordResetCallback",
            description: "Validate a password reset token and redirect to the callback URL",
            parameters: [
              {
                name: "token",
                in: "path",
                required: true,
                schema: {type: "string"}
              },
              {
                name: "callbackURL",
                in: "query",
                required: true,
                schema: {type: "string"}
              }
            ],
            responses: {
              "302" => {description: "Redirects to callback URL with token or error"}
            }
          }
        }
      ) do |ctx|
        token = ctx.params[:token].to_s
        callback_url = fetch_value(ctx.query, "callbackURL")
        validate_callback_url!(ctx.context, callback_url)
        verification = ctx.context.internal_adapter.find_verification_value("reset-password:#{token}")

        unless verification && !expired_time?(verification["expiresAt"])
          raise ctx.redirect(absolute_callback(ctx.context, callback_url, error: "INVALID_TOKEN"))
        end

        raise ctx.redirect(absolute_callback(ctx.context, callback_url, token: token))
      end
    end

    def self.reset_password
      Endpoint.new(
        path: "/reset-password",
        method: "POST",
        body_schema: request_body_schema(
          required_strings: %w[newPassword],
          optional_strings: %w[token]
        ),
        query_schema: request_query_schema(optional_strings: %w[token]),
        metadata: {
          openapi: {
            operationId: "resetPassword",
            description: "Reset a password using a reset token",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  token: {type: "string", description: "The password reset token"},
                  newPassword: {type: "string", description: "The new password to set"}
                },
                required: ["token", "newPassword"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("Password reset successfully", OpenAPI.status_response_schema)
            }
          }
        }
      ) do |ctx|
        body = normalize_hash(ctx.body)
        token = body["token"] || fetch_value(ctx.query, "token")
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_TOKEN"]) if token.to_s.empty?

        password = body["newPassword"] || body["new_password"]
        validate_password_length!(password, ctx.context.options.email_and_password)

        verification = ctx.context.internal_adapter.find_verification_value("reset-password:#{token}")
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_TOKEN"]) unless verification && !expired_time?(verification["expiresAt"])

        user_id = verification["value"]
        hashed = hash_password(ctx, password)
        account = ctx.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "credential" }
        if account
          ctx.context.internal_adapter.update_password(user_id, hashed)
        else
          ctx.context.internal_adapter.create_account(userId: user_id, providerId: "credential", accountId: user_id, password: hashed)
        end
        ctx.context.internal_adapter.delete_verification_value(verification["id"])

        if (callback = ctx.context.options.email_and_password[:on_password_reset])
          user = ctx.context.internal_adapter.find_user_by_id(user_id)
          callback.call({user: user}, ctx.request) if user
        end
        ctx.context.internal_adapter.delete_sessions(user_id) if ctx.context.options.email_and_password[:revoke_sessions_on_password_reset]

        ctx.json({status: true})
      end
    end

    def self.verify_password
      Endpoint.new(
        path: "/verify-password",
        method: "POST",
        metadata: {
          scope: "server",
          openapi: {
            operationId: "verifyPassword",
            description: "Verify the current user's password",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  password: {type: "string", description: "The password to verify"}
                },
                required: ["password"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("Password verified", OpenAPI.status_response_schema)
            }
          }
        }
      ) do |ctx|
        session = current_session(ctx, sensitive: true)
        password = normalize_hash(ctx.body)["password"].to_s
        account = credential_account(ctx, session[:user]["id"])
        valid = account && account["password"] && verify_password_value(ctx, password, account["password"])
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_PASSWORD"]) unless valid

        ctx.json({status: true})
      end
    end

    def self.validate_password_length!(password, email_config)
      unless password.is_a?(String) && !password.empty?
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_PASSWORD"])
      end
      raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["PASSWORD_TOO_SHORT"]) if password.length < email_config[:min_password_length].to_i
      raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["PASSWORD_TOO_LONG"]) if password.length > email_config[:max_password_length].to_i
    end

    def self.hash_password(ctx, password)
      hasher = ctx.context.options.email_and_password.dig(:password, :hash)
      if hasher.respond_to?(:call)
        return hasher_arity_accepts_context?(hasher) ? hasher.call(password, ctx) : hasher.call(password)
      end

      Password.hash(
        password,
        algorithm: ctx.context.options.password_hasher
      )
    end

    def self.hasher_arity_accepts_context?(hasher)
      arity = hasher.arity
      arity != 1 && arity != -1
    end

    def self.verify_password_value(ctx, password, digest)
      Password.verify(
        password: password,
        hash: digest,
        verifier: ctx.context.options.email_and_password.dig(:password, :verify),
        algorithm: ctx.context.options.password_hasher
      )
    end

    def self.credential_account(ctx, user_id)
      ctx.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "credential" }
    end

    def self.expired_time?(value)
      value && value < Time.now
    end

    def self.fetch_value(hash, key)
      snake_key = key.to_s
        .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
        .tr("-", "_")
        .downcase
      hash[key] ||
        hash[key.to_s] ||
        hash[key.to_sym] ||
        hash[Schema.storage_key(key)] ||
        hash[Schema.storage_key(key).to_sym] ||
        hash[snake_key] ||
        hash[snake_key.to_sym]
    end

    def self.absolute_callback(context, callback_url, params)
      validate_callback_url!(context, callback_url)
      uri = URI.parse(callback_url.to_s)
      origin = Configuration.origin_for(URI.parse(context.base_url))
      url = uri.relative? ? URI.join("#{origin}/", callback_url.to_s.delete_prefix("/")) : uri
      query = URI.decode_www_form(url.query.to_s)
      params.each { |key, value| query << [key.to_s, value] }
      url.query = URI.encode_www_form(query)
      url.to_s
    end

    def self.validate_callback_url!(context, callback_url)
      return if callback_url.nil? || callback_url.to_s.empty?

      value = callback_url.to_s
      if value.start_with?("/")
        return if Configuration.relative_path_allowed?(value)
      else
        uri = Configuration.parse_uri(value)
        base_uri = Configuration.parse_uri(context.base_url.to_s)
        base_origin = base_uri && Configuration.origin_for(base_uri)
        return if uri && Configuration.origin_for(uri) == base_origin
        return if context.trusted_origin?(value)
      end

      raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_CALLBACK_URL"])
    end

    def self.validate_redirect_url!(context, redirect_url)
      validate_callback_url!(context, redirect_url)
    rescue APIError => error
      raise error unless error.message == BASE_ERROR_CODES["INVALID_CALLBACK_URL"]

      raise APIError.new("FORBIDDEN", message: BASE_ERROR_CODES["INVALID_REDIRECT_URL"])
    end
  end
end

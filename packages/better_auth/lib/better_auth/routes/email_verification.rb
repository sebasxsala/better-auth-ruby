# frozen_string_literal: true

require "uri"

module BetterAuth
  module Routes
    def self.send_verification_email
      Endpoint.new(
        path: "/send-verification-email",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "sendVerificationEmail",
            description: "Send an email verification link",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  email: {type: "string", description: "The email address to verify"},
                  callbackURL: {type: ["string", "null"], description: "The URL to redirect to after verification"}
                },
                required: ["email"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("Verification email sent", OpenAPI.status_response_schema)
            }
          }
        }
      ) do |ctx|
        sender = ctx.context.options.email_verification[:send_verification_email]
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VERIFICATION_EMAIL_NOT_ENABLED"]) unless sender.respond_to?(:call)

        body = normalize_hash(ctx.body)
        email = body["email"].to_s.downcase
        session = current_session(ctx, allow_nil: true)

        if session
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["EMAIL_MISMATCH"]) if session[:user]["email"] != email
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["EMAIL_ALREADY_VERIFIED"]) if session[:user]["emailVerified"]

          send_verification_email_payload(ctx, session[:user], body["callbackURL"] || body["callbackUrl"] || body["callback_url"])
          next ctx.json({status: true})
        end

        found = ctx.context.internal_adapter.find_user_by_email(email)
        if found && !found[:user]["emailVerified"]
          send_verification_email_payload(ctx, found[:user], body["callbackURL"] || body["callbackUrl"] || body["callback_url"])
        else
          create_email_verification_token(ctx, email)
        end
        ctx.json({status: true})
      end
    end

    def self.verify_email
      Endpoint.new(
        path: "/verify-email",
        method: "GET",
        metadata: {
          openapi: {
            operationId: "verifyEmail",
            description: "Verify an email address by token",
            parameters: [
              {
                name: "token",
                in: "query",
                required: true,
                schema: {type: "string"}
              },
              {
                name: "callbackURL",
                in: "query",
                required: false,
                schema: {type: "string"}
              }
            ],
            responses: {
              "200" => OpenAPI.json_response(
                "Email verified",
                OpenAPI.object_schema(
                  {
                    status: {type: "boolean"},
                    user: {type: ["object", "null"], "$ref": "#/components/schemas/User"}
                  },
                  required: ["status"]
                )
              )
            }
          }
        }
      ) do |ctx|
        token = fetch_value(ctx.query, "token").to_s
        callback_url = fetch_value(ctx.query, "callbackURL")
        validate_callback_url!(ctx.context, callback_url)
        payload = verify_email_token(ctx, token, callback_url)
        email = payload["email"].to_s.downcase
        update_to = payload["updateTo"] || payload["update_to"]
        user_data = ctx.context.internal_adapter.find_user_by_email(email)
        return redirect_or_error(ctx, callback_url, "user_not_found") unless user_data

        user = user_data[:user]
        if update_to
          session = current_session(ctx, allow_nil: true)
          return redirect_or_error(ctx, callback_url, "invalid_user") if session && session[:user]["email"] != email

          request_type = payload["requestType"] || payload["request_type"]
          case request_type
          when "change-email-confirmation"
            send_change_email_verification_payload(ctx, user, update_to, callback_url)
            next redirect_or_json(ctx, callback_url, {status: true})
          when "change-email-verification"
            updated = ctx.context.internal_adapter.update_user_by_email(email, email: update_to, emailVerified: true)
            updated_user = updated || user.merge("email" => update_to, "emailVerified" => true)
            call_option(ctx.context.options.email_verification[:after_email_verification], updated_user, ctx.request)
            set_verified_session_cookie(ctx, updated_user)
            next redirect_or_json(ctx, callback_url, {status: true, user: Schema.parse_output(ctx.context.options, "user", updated_user)})
          else
            updated = ctx.context.internal_adapter.update_user_by_email(email, email: update_to, emailVerified: false)
            updated_user = updated || user.merge("email" => update_to, "emailVerified" => false)
            send_verification_email_payload(ctx, updated_user, callback_url) if ctx.context.options.email_verification[:send_verification_email].respond_to?(:call)
            set_verified_session_cookie(ctx, updated_user)
            next redirect_or_json(ctx, callback_url, {status: true, user: Schema.parse_output(ctx.context.options, "user", updated)})
          end
        end

        if user["emailVerified"]
          next redirect_or_json(ctx, callback_url, {status: true, user: nil})
        end

        call_option(ctx.context.options.email_verification[:before_email_verification], user, ctx.request)
        call_option(ctx.context.options.email_verification[:on_email_verification], user, ctx.request)
        updated = ctx.context.internal_adapter.update_user_by_email(email, emailVerified: true)
        call_option(ctx.context.options.email_verification[:after_email_verification], updated, ctx.request)
        set_verified_session_cookie(ctx, updated) if ctx.context.options.email_verification[:auto_sign_in_after_verification]
        redirect_or_json(ctx, callback_url, {status: true, user: nil})
      end
    end

    def self.send_verification_email_payload(ctx, user, callback_url)
      token = create_email_verification_token(ctx, user["email"])
      callback = URI.encode_www_form_component(callback_url || "/")
      url = "#{ctx.context.base_url}/verify-email?token=#{URI.encode_www_form_component(token)}&callbackURL=#{callback}"
      ctx.context.options.email_verification[:send_verification_email].call({user: user, url: url, token: token}, ctx.request)
    end

    def self.send_change_email_verification_payload(ctx, user, update_to, callback_url)
      sender = ctx.context.options.email_verification[:send_verification_email]
      return unless sender.respond_to?(:call)

      token = create_email_verification_token(ctx, user["email"], update_to: update_to, extra: {"requestType" => "change-email-verification"})
      callback = URI.encode_www_form_component(callback_url || "/")
      url = "#{ctx.context.base_url}/verify-email?token=#{URI.encode_www_form_component(token)}&callbackURL=#{callback}"
      sender.call({user: user.merge("email" => update_to), url: url, token: token}, ctx.request)
    end

    def self.create_email_verification_token(ctx, email, update_to: nil, extra: {})
      payload = {"email" => email.to_s.downcase}.merge(extra)
      payload["updateTo"] = update_to if update_to
      Crypto.sign_jwt(payload, ctx.context.secret, expires_in: ctx.context.options.email_verification[:expires_in] || 3600)
    end

    def self.verify_email_token(ctx, token, callback_url)
      decoded, = JWT.decode(token.to_s, ctx.context.secret.to_s, true, algorithm: "HS256")
      decoded
    rescue JWT::ExpiredSignature
      redirect_or_error(ctx, callback_url, BASE_ERROR_CODES["TOKEN_EXPIRED"], code: "TOKEN_EXPIRED")
    rescue JWT::DecodeError
      redirect_or_error(ctx, callback_url, BASE_ERROR_CODES["INVALID_TOKEN"], code: "INVALID_TOKEN")
    end

    def self.redirect_or_error(ctx, callback_url, error, code: nil)
      if callback_url
        separator = callback_url.include?("?") ? "&" : "?"
        raise ctx.redirect("#{callback_url}#{separator}error=#{code || error}")
      end
      raise APIError.new("UNAUTHORIZED", code: code, message: error)
    end

    def self.redirect_or_json(ctx, callback_url, data)
      raise ctx.redirect(callback_url) if callback_url

      ctx.json(data)
    end

    def self.set_verified_session_cookie(ctx, user)
      session = current_session(ctx, allow_nil: true)
      session_data = if session && session[:user]["id"] == user["id"]
        session[:session]
      else
        ctx.context.internal_adapter.create_session(user["id"])
      end
      Cookies.set_session_cookie(ctx, {session: session_data, user: user})
    end

    def self.call_option(callback, user, request)
      callback.call(user, request) if callback.respond_to?(:call)
    end
  end
end

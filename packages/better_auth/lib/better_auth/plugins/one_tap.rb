# frozen_string_literal: true

require "net/http"
require "uri"

module BetterAuth
  module Plugins
    module_function

    def one_tap(options = {})
      config = normalize_hash(options)

      Plugin.new(
        id: "one-tap",
        endpoints: {
          one_tap_callback: one_tap_callback_endpoint(config)
        },
        options: config
      )
    end

    def one_tap_callback_endpoint(config)
      Endpoint.new(
        path: "/one-tap/callback",
        method: "POST",
        body_schema: ->(body) {
          data = normalize_hash(body)
          data[:id_token].to_s.empty? ? false : data
        },
        metadata: {
          openapi: {
            operationId: "oneTapCallback",
            summary: "One tap callback",
            description: "Use this endpoint to authenticate with Google One Tap",
            responses: {
              "200" => OpenAPI.json_response("Success", OpenAPI.session_response_schema_pair)
            }
          }
        }
      ) do |ctx|
        body = normalize_hash(ctx.body)
        id_token = body[:id_token].to_s
        payload = one_tap_verify_id_token(ctx, config, id_token)
        email = fetch_value(payload, "email").to_s.downcase

        if email.empty?
          next ctx.json({error: "Email not available in token"})
        end

        user = ctx.context.internal_adapter.find_user_by_email(email)
        if user
          one_tap_link_account_unless_present!(ctx, config, user, payload, id_token)
          session_data = one_tap_create_session(ctx, user[:user])
        else
          raise APIError.new("BAD_GATEWAY", message: "User not found") if config[:disable_signup]

          created = ctx.context.internal_adapter.create_oauth_user(
            {
              email: email,
              emailVerified: one_tap_boolean_value(fetch_value(payload, "email_verified")),
              name: fetch_value(payload, "name").to_s,
              image: fetch_value(payload, "picture")
            },
            {
              providerId: "google",
              accountId: fetch_value(payload, "sub").to_s,
              idToken: id_token
            },
            context: ctx
          )
          raise APIError.new("INTERNAL_SERVER_ERROR", message: "Could not create user") unless created

          session_data = one_tap_create_session(ctx, created[:user])
        end

        Cookies.set_session_cookie(ctx, session_data)
        ctx.json({
          token: session_data[:session]["token"],
          user: Schema.parse_output(ctx.context.options, "user", session_data[:user])
        })
      end
    end

    def one_tap_verify_id_token(ctx, config, id_token)
      verifier = config[:verify_id_token]
      audience = config[:client_id] || ctx.context.options.social_providers.dig(:google, :client_id)
      payload = if verifier.respond_to?(:call)
        verifier.call(id_token, ctx, audience: audience)
      else
        one_tap_verify_google_id_token(id_token, audience)
      end
      one_tap_stringify_payload(payload)
    rescue
      raise APIError.new("BAD_REQUEST", message: "invalid id token")
    end

    def one_tap_verify_google_id_token(id_token, audience)
      jwks = one_tap_google_jwks
      options = {
        algorithms: ["RS256"],
        iss: ["https://accounts.google.com", "accounts.google.com"],
        verify_iss: true
      }
      if audience
        options[:aud] = audience
        options[:verify_aud] = true
      end
      payload, = ::JWT.decode(id_token, nil, true, options.merge(jwks: jwks))
      payload
    end

    def one_tap_google_jwks
      cached = @one_tap_google_jwks_cache
      return cached[:jwks] if cached && cached[:expires_at] > Time.now

      payload = HTTPClient.get_json("https://www.googleapis.com/oauth2/v3/certs")
      raise "Unable to fetch Google JWKS" unless payload

      jwks = ::JWT::JWK::Set.new(payload)
      @one_tap_google_jwks_cache = {jwks: jwks, expires_at: Time.now + 300}
      jwks
    end

    def one_tap_link_account_unless_present!(ctx, _config, user, payload, id_token)
      sub = fetch_value(payload, "sub").to_s
      account = ctx.context.internal_adapter.find_account(sub)
      return if account

      account_linking = ctx.context.options.account[:account_linking] || {}
      trusted = Array(account_linking[:trusted_providers]).map(&:to_s).include?("google")
      enabled = account_linking.fetch(:enabled, true)
      should_link_account = enabled != false && (trusted || one_tap_boolean_value(fetch_value(payload, "email_verified")))
      unless should_link_account
        raise APIError.new("UNAUTHORIZED", message: "Google sub doesn't match")
      end

      ctx.context.internal_adapter.link_account(
        userId: user[:user]["id"],
        providerId: "google",
        accountId: sub,
        scope: "openid,profile,email",
        idToken: id_token
      )
    end

    def one_tap_create_session(ctx, user)
      session = ctx.context.internal_adapter.create_session(user["id"])
      {session: session, user: user}
    end

    def one_tap_stringify_payload(payload)
      raise "Invalid payload" unless payload.is_a?(Hash)

      payload.each_with_object({}) do |(key, value), result|
        result[key.to_s] = value
      end
    end

    def one_tap_boolean_value(value)
      value == true || value.to_s.downcase == "true"
    end
  end
end

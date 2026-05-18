# frozen_string_literal: true

require "net/http"
require "uri"
require "base64"
require "openssl"

module BetterAuth
  module Plugins
    module_function

    GENERIC_OAUTH_ERROR_CODES = {
      "INVALID_OAUTH_CONFIGURATION" => "Invalid OAuth configuration",
      "TOKEN_URL_NOT_FOUND" => "Invalid OAuth configuration. Token URL not found.",
      "PROVIDER_CONFIG_NOT_FOUND" => "No config found for provider",
      "PROVIDER_ID_REQUIRED" => "Provider ID is required",
      "INVALID_OAUTH_CONFIG" => "Invalid OAuth configuration.",
      "SESSION_REQUIRED" => "Session is required",
      "ISSUER_MISMATCH" => "OAuth issuer mismatch. The authorization server issuer does not match the expected value (RFC 9207).",
      "ISSUER_MISSING" => "OAuth issuer parameter missing. The authorization server did not include the required iss parameter (RFC 9207)."
    }.freeze

    def generic_oauth(options = {})
      config = normalize_hash(options)
      providers = Array(config[:config]).map { |provider| normalize_hash(provider) }
      generic_oauth_warn_duplicate_providers(providers)
      config[:config] = providers

      Plugin.new(
        id: "generic-oauth",
        init: ->(context) {
          {
            options: {
              social_providers: generic_oauth_social_providers(config, context).merge(context.social_providers)
            }
          }
        },
        endpoints: {
          sign_in_with_oauth2: sign_in_with_oauth2_endpoint(config),
          o_auth2_callback: o_auth2_callback_endpoint(config),
          o_auth2_link_account: o_auth2_link_account_endpoint(config)
        },
        error_codes: GENERIC_OAUTH_ERROR_CODES,
        options: config
      )
    end

    def auth0(options = {})
      data = normalize_hash(options)
      domain = data.fetch(:domain).to_s.sub(%r{\Ahttps?://}, "")
      generic_oauth_provider_config(
        data,
        provider_id: "auth0",
        discovery_url: "https://#{domain}/.well-known/openid-configuration",
        scopes: ["openid", "profile", "email"]
      )
    end

    def gumroad(options = {})
      data = normalize_hash(options)
      generic_oauth_provider_config(
        data,
        provider_id: "gumroad",
        authorization_url: "https://gumroad.com/oauth/authorize",
        token_url: "https://api.gumroad.com/oauth/token",
        scopes: ["view_profile"],
        get_user_info: ->(tokens) {
          profile = generic_oauth_fetch_json("https://api.gumroad.com/v2/user", authorization: "Bearer #{fetch_value(tokens, "accessToken")}")
          user = fetch_value(profile, "user")
          return nil unless fetch_value(profile, "success") && user

          {
            id: fetch_value(user, "user_id"),
            name: fetch_value(user, "name"),
            email: fetch_value(user, "email"),
            image: fetch_value(user, "profile_url"),
            emailVerified: false
          }
        }
      )
    end

    def hubspot(options = {})
      data = normalize_hash(options)
      generic_oauth_provider_config(
        data,
        provider_id: "hubspot",
        authorization_url: "https://app.hubspot.com/oauth/authorize",
        token_url: "https://api.hubapi.com/oauth/v1/token",
        scopes: ["oauth"],
        authentication: "post",
        get_user_info: ->(tokens) {
          profile = generic_oauth_fetch_json("https://api.hubapi.com/oauth/v1/access-tokens/#{fetch_value(tokens, "accessToken")}", "Content-Type" => "application/json")
          return nil unless profile

          id = fetch_value(profile, "user_id") || fetch_value(fetch_value(profile, "signed_access_token"), "userId")
          return nil if id.to_s.empty?

          {id: id, name: fetch_value(profile, "user"), email: fetch_value(profile, "user"), emailVerified: false}
        }
      )
    end

    def keycloak(options = {})
      data = normalize_hash(options)
      issuer = data.fetch(:issuer).to_s.sub(%r{/\z}, "")
      generic_oidc_helper_provider(data, "keycloak", issuer, "#{issuer}/.well-known/openid-configuration", "#{issuer}/protocol/openid-connect/userinfo")
    end

    def line(options = {})
      data = normalize_hash(options)
      generic_oauth_provider_config(
        data,
        provider_id: data[:provider_id] || "line",
        authorization_url: "https://access.line.me/oauth2/v2.1/authorize",
        token_url: "https://api.line.me/oauth2/v2.1/token",
        user_info_url: "https://api.line.me/oauth2/v2.1/userinfo",
        scopes: ["openid", "profile", "email"],
        get_user_info: ->(tokens) {
          profile = generic_oauth_user_from_id_token(fetch_value(tokens, "idToken"))
          profile ||= generic_oauth_fetch_json("https://api.line.me/oauth2/v2.1/userinfo", authorization: "Bearer #{fetch_value(tokens, "accessToken")}")
          return nil unless profile

          {
            id: fetch_value(profile, "sub") || fetch_value(profile, "id"),
            name: fetch_value(profile, "name"),
            email: fetch_value(profile, "email"),
            image: fetch_value(profile, "picture") || fetch_value(profile, "image"),
            emailVerified: false
          }
        }
      )
    end

    def microsoft_entra_id(options = {})
      data = normalize_hash(options)
      tenant_id = data.fetch(:tenant_id).to_s
      generic_oauth_provider_config(
        data,
        provider_id: "microsoft-entra-id",
        authorization_url: "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/authorize",
        token_url: "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/token",
        user_info_url: "https://graph.microsoft.com/oidc/userinfo",
        scopes: ["openid", "profile", "email"],
        get_user_info: ->(tokens) {
          profile = generic_oauth_fetch_json("https://graph.microsoft.com/oidc/userinfo", authorization: "Bearer #{fetch_value(tokens, "accessToken")}")
          return nil unless profile

          {
            id: fetch_value(profile, "sub"),
            name: fetch_value(profile, "name") || [fetch_value(profile, "given_name"), fetch_value(profile, "family_name")].compact.join(" ").strip,
            email: fetch_value(profile, "email") || fetch_value(profile, "preferred_username"),
            image: fetch_value(profile, "picture"),
            emailVerified: fetch_value(profile, "email_verified") || false
          }
        }
      )
    end

    def okta(options = {})
      data = normalize_hash(options)
      issuer = data.fetch(:issuer).to_s.sub(%r{/\z}, "")
      generic_oidc_helper_provider(data, "okta", issuer, "#{issuer}/.well-known/openid-configuration", "#{issuer}/oauth2/v1/userinfo")
    end

    def patreon(options = {})
      data = normalize_hash(options)
      generic_oauth_provider_config(
        data,
        provider_id: "patreon",
        authorization_url: "https://www.patreon.com/oauth2/authorize",
        token_url: "https://www.patreon.com/api/oauth2/token",
        scopes: ["identity[email]"],
        get_user_info: ->(tokens) {
          profile = generic_oauth_fetch_json("https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url,is_email_verified", authorization: "Bearer #{fetch_value(tokens, "accessToken")}")
          data = fetch_value(profile, "data")
          attributes = fetch_value(data, "attributes")
          return nil unless data && attributes

          {
            id: fetch_value(data, "id"),
            name: fetch_value(attributes, "full_name"),
            email: fetch_value(attributes, "email"),
            image: fetch_value(attributes, "image_url"),
            emailVerified: fetch_value(attributes, "is_email_verified")
          }
        }
      )
    end

    def slack(options = {})
      data = normalize_hash(options)
      generic_oauth_provider_config(
        data,
        provider_id: "slack",
        authorization_url: "https://slack.com/openid/connect/authorize",
        token_url: "https://slack.com/api/openid.connect.token",
        user_info_url: "https://slack.com/api/openid.connect.userInfo",
        scopes: ["openid", "profile", "email"],
        get_user_info: ->(tokens) {
          profile = generic_oauth_fetch_json("https://slack.com/api/openid.connect.userInfo", authorization: "Bearer #{fetch_value(tokens, "accessToken")}")
          return nil unless profile

          {
            id: fetch_value(profile, "https://slack.com/user_id") || fetch_value(profile, "sub"),
            name: fetch_value(profile, "name"),
            email: fetch_value(profile, "email"),
            image: fetch_value(profile, "picture") || fetch_value(profile, "https://slack.com/user_image_512"),
            emailVerified: fetch_value(profile, "email_verified") || false
          }
        }
      )
    end

    def sign_in_with_oauth2_endpoint(config)
      Endpoint.new(
        path: "/sign-in/oauth2",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "signInOAuth2",
            description: "Sign in with OAuth2",
            responses: {
              "200" => OpenAPI.json_response("Sign in with OAuth2", generic_oauth_url_response_schema)
            }
          }
        }
      ) do |ctx|
        body = normalize_hash(ctx.body)
        provider_id = body[:provider_id].to_s
        provider = generic_oauth_provider!(config, provider_id)
        auth_url = generic_oauth_authorization_url(ctx, provider, body, link: nil)
        ctx.json({url: auth_url, redirect: !body[:disable_redirect]})
      end
    end

    def o_auth2_link_account_endpoint(config)
      Endpoint.new(
        path: "/oauth2/link",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "linkOAuth2",
            description: "Link an OAuth2 account to the current user session",
            responses: {
              "200" => OpenAPI.json_response("Authorization URL generated successfully for linking an OAuth2 account", generic_oauth_url_response_schema)
            }
          }
        }
      ) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        provider_id = body[:provider_id].to_s
        provider = generic_oauth_provider(config, provider_id)
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES["PROVIDER_NOT_FOUND"]) unless provider

        auth_url = generic_oauth_authorization_url(
          ctx,
          provider,
          body,
          link: {user_id: session[:user]["id"], email: session[:user]["email"]}
        )
        ctx.json({url: auth_url, redirect: true})
      end
    end

    def o_auth2_callback_endpoint(config)
      Endpoint.new(
        path: "/oauth2/callback/:providerId",
        method: "GET",
        metadata: {
          allowed_media_types: ["application/x-www-form-urlencoded", "application/json"],
          openapi: {
            operationId: "oauth2Callback",
            description: "OAuth2 callback",
            responses: {
              "200" => OpenAPI.json_response(
                "OAuth2 callback",
                OpenAPI.object_schema({url: {type: "string"}}, required: ["url"])
              )
            }
          }
        }
      ) do |ctx|
        query = normalize_hash(ctx.query)
        provider_id = (fetch_value(ctx.params, "providerId") || query[:provider_id]).to_s
        raise APIError.new("BAD_REQUEST", message: GENERIC_OAUTH_ERROR_CODES["PROVIDER_ID_REQUIRED"]) if provider_id.empty?

        provider = generic_oauth_provider!(config, provider_id)
        state_data = generic_oauth_parse_state(ctx, query[:state].to_s)
        error_url = state_data["errorURL"] || state_data["errorCallbackURL"] || "#{ctx.context.base_url}/error"
        redirect_error = ->(error) { raise ctx.redirect(generic_oauth_error_url(error_url, error)) }

        redirect_error.call(query[:error] || "oAuth_code_missing") if query[:error] || query[:code].to_s.empty?
        generic_oauth_validate_issuer!(ctx, provider, query, redirect_error)

        tokens = begin
          generic_oauth_exchange_token(ctx, provider, query[:code].to_s, state_data)
        rescue
          nil
        end
        redirect_error.call("oauth_code_verification_failed") unless tokens
        user_info = generic_oauth_user_info(provider, tokens)
        redirect_error.call("user_info_is_missing") unless user_info

        mapped_user = generic_oauth_map_user(provider, user_info)
        email = fetch_value(mapped_user, "email").to_s.downcase
        name = fetch_value(mapped_user, "name").to_s
        account_id = fetch_value(mapped_user, "id").to_s
        redirect_error.call("email_is_missing") if email.empty?
        redirect_error.call("name_is_missing") if name.empty?

        link = state_data["link"]
        callback_url = state_data["callbackURL"] || "/"
        if link
          generic_oauth_link_account(ctx, provider, tokens, mapped_user, link, redirect_error)
          raise ctx.redirect(callback_url)
        end

        existing = ctx.context.internal_adapter.find_oauth_user(email, account_id, provider_id)
        if !existing && (provider[:disable_sign_up] || (provider[:disable_implicit_sign_up] && !state_data["requestSignUp"]))
          redirect_error.call("signup_disabled")
        end
        if existing && provider[:override_user_info]
          ctx.context.internal_adapter.update_user(
            existing[:user]["id"],
            "name" => name,
            "image" => fetch_value(mapped_user, "image"),
            "emailVerified" => !!fetch_value(mapped_user, "emailVerified")
          )
        end

        session_data = Routes.persist_social_user(
          ctx,
          provider_id,
          mapped_user.merge("email" => email, "name" => name, "id" => account_id),
          generic_oauth_account_info(ctx, provider_id, account_id, tokens)
        )
        generic_oauth_set_account_cookie(ctx, provider_id, account_id, session_data[:user]["id"])
        Cookies.set_session_cookie(ctx, session_data)
        raise ctx.redirect(existing ? callback_url : (state_data["newUserURL"] || state_data["newUserCallbackURL"] || callback_url))
      end
    end

    def generic_oauth_url_response_schema
      OpenAPI.object_schema(
        {
          url: {type: "string"},
          redirect: {type: "boolean"}
        },
        required: ["url", "redirect"]
      )
    end

    def generic_oauth_authorization_url(ctx, provider, body, link:)
      authorization_url = provider[:authorization_url] || generic_oauth_discovery(provider)["authorization_endpoint"]
      token_url = provider[:token_url] || generic_oauth_discovery(provider)["token_endpoint"]
      raise APIError.new("BAD_REQUEST", message: GENERIC_OAUTH_ERROR_CODES["INVALID_OAUTH_CONFIGURATION"]) if authorization_url.to_s.empty? || token_url.to_s.empty?

      code_verifier = Crypto.random_string(43)
      state_data = normalize_hash(body[:additional_data] || body[:additionalData]).transform_keys(&:to_s).merge(
        "callbackURL" => body[:callback_url] || body[:callbackURL] || "/",
        "errorURL" => body[:error_callback_url] || body[:errorCallbackURL],
        "newUserURL" => body[:new_user_callback_url] || body[:newUserCallbackURL],
        "requestSignUp" => body[:request_sign_up] || body[:requestSignUp],
        "codeVerifier" => provider[:pkce] ? code_verifier : nil,
        "link" => link,
        "expiresAt" => Time.now.to_i + 600
      )
      state = generic_oauth_generate_state(ctx, state_data)
      legacy_state = Crypto.sign_jwt(
        {
          "callbackURL" => body[:callback_url] || body[:callbackURL] || "/",
          "errorURL" => body[:error_callback_url] || body[:errorCallbackURL],
          "newUserURL" => body[:new_user_callback_url] || body[:newUserCallbackURL],
          "requestSignUp" => body[:request_sign_up] || body[:requestSignUp],
          "codeVerifier" => code_verifier,
          "link" => link
        },
        ctx.context.secret,
        expires_in: 600
      )
      state ||= legacy_state

      uri = URI.parse(authorization_url.to_s)
      params = URI.decode_www_form(uri.query.to_s)
      params.concat([
        ["client_id", provider[:client_id].to_s],
        ["response_type", provider[:response_type] || "code"],
        ["redirect_uri", generic_oauth_redirect_uri(ctx, provider)],
        ["state", state]
      ])
      scopes = Array(body[:scopes]) + Array(provider[:scopes])
      params << ["scope", scopes.join(" ")] unless scopes.empty?
      if provider[:pkce]
        params << ["code_challenge", generic_oauth_pkce_challenge(code_verifier)]
        params << ["code_challenge_method", "S256"]
      end
      params << ["prompt", provider[:prompt]] if provider[:prompt]
      params << ["access_type", provider[:access_type]] if provider[:access_type]
      params << ["response_mode", provider[:response_mode]] if provider[:response_mode]
      authorization_params = if provider[:authorization_url_params].respond_to?(:call)
        provider[:authorization_url_params].call(ctx)
      else
        provider[:authorization_url_params]
      end
      normalize_hash(authorization_params || {}).each { |key, value| params << [key.to_s, value.to_s] }
      uri.query = URI.encode_www_form(params)
      uri.to_s
    end

    def generic_oauth_generate_state(ctx, state_data)
      strategy = ctx.context.options.account[:store_state_strategy]
      state = Crypto.random_string(32)
      if strategy.to_s == "cookie"
        cookie = ctx.context.create_auth_cookie("oauth_state", max_age: 600)
        encrypted = Crypto.symmetric_encrypt(key: ctx.context.secret_config, data: JSON.generate(state_data.merge("state" => state)))
        ctx.set_cookie(cookie.name, encrypted, cookie.attributes)
        return state
      end

      cookie = ctx.context.create_auth_cookie("state", max_age: 300)
      ctx.set_signed_cookie(cookie.name, state, ctx.context.secret, cookie.attributes)
      ctx.context.internal_adapter.create_verification_value(
        identifier: state,
        value: JSON.generate(state_data),
        expiresAt: Time.now + 600
      )
      state
    rescue
      nil
    end

    def generic_oauth_exchange_token(ctx, provider, code, state_data)
      token_callback = provider[:get_token]
      if token_callback.respond_to?(:call)
        return normalize_hash(token_callback.call(
          code: code,
          redirectURI: generic_oauth_redirect_uri(ctx, provider),
          redirect_uri: generic_oauth_redirect_uri(ctx, provider),
          codeVerifier: provider[:pkce] ? state_data["codeVerifier"] : nil,
          code_verifier: provider[:pkce] ? state_data["codeVerifier"] : nil
        ))
      end

      token_url = provider[:token_url] || generic_oauth_discovery(provider)["token_endpoint"]
      raise APIError.new("BAD_REQUEST", message: GENERIC_OAUTH_ERROR_CODES["TOKEN_URL_NOT_FOUND"]) if token_url.to_s.empty?

      generic_oauth_post_token(ctx, token_url, provider, code, provider[:pkce] ? state_data["codeVerifier"] : nil, generic_oauth_redirect_uri(ctx, provider))
    end

    def generic_oauth_parse_state(ctx, state)
      if state.to_s.empty?
        raise ctx.redirect(generic_oauth_error_url(generic_oauth_state_error_url(ctx), "please_restart_the_process"))
      end

      if ctx.context.options.account[:store_state_strategy].to_s == "cookie"
        cookie = ctx.context.create_auth_cookie("oauth_state")
        encrypted = ctx.get_cookie(cookie.name)
        unless encrypted
          raise ctx.redirect(generic_oauth_error_url(generic_oauth_state_error_url(ctx), "state_mismatch"))
        end

        begin
          decrypted = Crypto.symmetric_decrypt(key: ctx.context.secret_config, data: encrypted)
          unless decrypted
            Cookies.expire_cookie(ctx, cookie)
            raise ctx.redirect(generic_oauth_error_url(generic_oauth_state_error_url(ctx), "please_restart_the_process"))
          end

          parsed = JSON.parse(decrypted)
        rescue JSON::ParserError
          Cookies.expire_cookie(ctx, cookie)
          raise ctx.redirect(generic_oauth_error_url(generic_oauth_state_error_url(ctx), "please_restart_the_process"))
        end

        Cookies.expire_cookie(ctx, cookie)
        if parsed["state"] != state
          raise ctx.redirect(generic_oauth_error_url(generic_oauth_state_error_url(ctx), "state_mismatch"))
        end
        if parsed["expiresAt"].to_i.positive? && parsed["expiresAt"].to_i < Time.now.to_i
          raise ctx.redirect(generic_oauth_error_url(generic_oauth_state_error_url(ctx), "state_mismatch"))
        end
        return parsed
      else
        verification = ctx.context.internal_adapter.find_verification_value(state)
        if verification
          cookie = ctx.context.create_auth_cookie("state")
          cookie_state = ctx.get_signed_cookie(cookie.name, ctx.context.secret)
          if ctx.request && cookie_state != state
            Cookies.expire_cookie(ctx, cookie)
            raise ctx.redirect(generic_oauth_error_url(generic_oauth_state_error_url(ctx), "state_mismatch"))
          elsif !ctx.request && cookie_state && cookie_state != state
            Cookies.expire_cookie(ctx, cookie)
            raise ctx.redirect(generic_oauth_error_url(generic_oauth_state_error_url(ctx), "state_mismatch"))
          end

          parsed = JSON.parse(verification.fetch("value"))
          ctx.context.internal_adapter.delete_verification_value(verification.fetch("id"))
          Cookies.expire_cookie(ctx, cookie) if ctx.request || cookie_state
          return parsed
        end
      end

      Crypto.verify_jwt(state.to_s, ctx.context.secret) || {}
    rescue JSON::ParserError
      {}
    end

    def generic_oauth_state_error_url(ctx)
      ctx.context.options.on_api_error[:error_url] || "#{ctx.context.base_url}/error"
    end

    def generic_oauth_user_info(provider, tokens)
      callback = provider[:get_user_info]
      return normalize_hash(callback.call(tokens)) if callback.respond_to?(:call)

      id_token = tokens[:id_token] || tokens[:idToken]
      return generic_oauth_user_from_id_token(id_token) if id_token

      user_info_url = provider[:user_info_url] || generic_oauth_discovery(provider)["userinfo_endpoint"]
      return nil if user_info_url.to_s.empty?

      uri = URI(user_info_url)
      request = Net::HTTP::Get.new(uri)
      request["authorization"] = "Bearer #{fetch_value(tokens, "accessToken")}"
      response = HTTPClient.request(uri, request)
      return nil unless response.is_a?(Net::HTTPSuccess)

      generic_oauth_normalize_user_info(JSON.parse(response.body))
    rescue
      nil
    end

    def generic_oauth_map_user(provider, user_info)
      mapper = provider[:map_profile_to_user]
      mapped = mapper.respond_to?(:call) ? mapper.call(user_info) : user_info
      normalize_hash(user_info).merge(normalize_hash(mapped || {}))
    end

    def generic_oauth_link_account(ctx, provider, tokens, user_info, link, redirect_error)
      if !ctx.context.options.account.dig(:account_linking, :allow_different_emails) &&
          link["email"].to_s.downcase != fetch_value(user_info, "email").to_s.downcase
        redirect_error.call("email_doesn't_match")
      end

      account_id = fetch_value(user_info, "id").to_s
      existing_account = ctx.context.internal_adapter.find_account_by_provider_id(account_id, provider[:provider_id].to_s)
      account_info = generic_oauth_account_info(ctx, provider[:provider_id].to_s, account_id, tokens).merge("userId" => link["user_id"])
      if existing_account
        redirect_error.call("account_already_linked_to_different_user") if existing_account["userId"] != link["user_id"]
        account = ctx.context.internal_adapter.update_account(existing_account["id"], account_info)
      else
        account = ctx.context.internal_adapter.create_account(account_info)
      end
      Cookies.set_account_cookie(ctx, account) if account
    end

    def generic_oauth_account_info(ctx, provider_id, account_id, tokens)
      data = normalize_hash(tokens || {})
      {
        "providerId" => provider_id,
        "accountId" => account_id,
        "accessToken" => generic_oauth_token_for_storage(ctx, data[:access_token] || data[:accessToken]),
        "refreshToken" => generic_oauth_token_for_storage(ctx, data[:refresh_token] || data[:refreshToken]),
        "idToken" => data[:id_token] || data[:idToken],
        "accessTokenExpiresAt" => data[:access_token_expires_at] || data[:accessTokenExpiresAt],
        "refreshTokenExpiresAt" => data[:refresh_token_expires_at] || data[:refreshTokenExpiresAt],
        "scope" => Array(data[:scopes] || data[:scope]).join(",")
      }
    end

    def generic_oauth_token_for_storage(ctx, token)
      return token if token.to_s.empty?
      return token unless ctx.context.options.account[:encrypt_oauth_tokens]

      Crypto.symmetric_encrypt(key: ctx.context.secret_config, data: token)
    end

    def generic_oauth_set_account_cookie(ctx, provider_id, account_id, user_id)
      account = ctx.context.internal_adapter.find_accounts(user_id).find do |entry|
        entry["providerId"] == provider_id && entry["accountId"] == account_id
      end
      Cookies.set_account_cookie(ctx, account) if account
    end

    def generic_oauth_provider!(config, provider_id)
      provider = generic_oauth_provider(config, provider_id)
      raise APIError.new("BAD_REQUEST", message: "#{GENERIC_OAUTH_ERROR_CODES["PROVIDER_CONFIG_NOT_FOUND"]} #{provider_id}") unless provider

      provider
    end

    def generic_oauth_provider(config, provider_id)
      Array(config[:config]).find { |provider| provider[:provider_id].to_s == provider_id.to_s }
    end

    def generic_oauth_redirect_uri(ctx, provider)
      provider[:redirect_uri] || provider[:redirectURI] || "#{ctx.context.base_url}/oauth2/callback/#{provider[:provider_id]}"
    end

    def generic_oauth_validate_issuer!(ctx, provider, query, redirect_error)
      expected = provider[:issuer] || generic_oauth_discovery(provider)["issuer"]
      return if expected.to_s.empty?
      return if query[:iss].to_s == expected.to_s
      return redirect_error.call("issuer_missing") if query[:iss].to_s.empty? && provider[:require_issuer_validation]
      return if query[:iss].to_s.empty?

      redirect_error.call("issuer_mismatch")
    end

    def generic_oauth_discovery(provider)
      return {} if provider[:discovery_url].to_s.empty?
      return provider[:_discovery] if provider[:_discovery]

      uri = URI(provider[:discovery_url])
      request = Net::HTTP::Get.new(uri)
      normalize_hash(provider[:discovery_headers] || provider[:discoveryHeaders]).each do |key, value|
        request[key.to_s.tr("_", "-")] = value.to_s
      end
      response = HTTPClient.request(uri, request)
      provider[:_discovery] = response.is_a?(Net::HTTPSuccess) ? JSON.parse(response.body) : {}
    rescue
      {}
    end

    def generic_oauth_post_token(ctx, token_url, provider, code, code_verifier, redirect_uri)
      uri = URI(token_url)
      request = Net::HTTP::Post.new(uri)
      normalize_hash(provider[:authorization_headers] || provider[:authorizationHeaders]).each do |key, value|
        request[key.to_s.tr("_", "-")] = value.to_s
      end
      form_data = {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirect_uri
      }.compact
      form_data[:code_verifier] = code_verifier if code_verifier
      authentication = (provider[:authentication] || "post").to_s
      if authentication == "basic"
        request["authorization"] = "Basic #{Base64.strict_encode64("#{provider[:client_id]}:#{provider[:client_secret]}")}"
      else
        form_data[:client_id] = provider[:client_id]
        form_data[:client_secret] = provider[:client_secret] if provider[:client_secret]
      end
      token_url_params = if provider[:token_url_params].respond_to?(:call)
        provider[:token_url_params].call(ctx)
      else
        provider[:token_url_params] || provider[:tokenUrlParams]
      end
      normalize_hash(token_url_params || {}).each do |key, value|
        form_data[key] = value unless form_data.key?(key)
      end
      request.set_form_data(form_data)
      response = HTTPClient.request(uri, request)
      return nil unless response.is_a?(Net::HTTPSuccess)

      generic_oauth_normalize_tokens(JSON.parse(response.body))
    rescue
      nil
    end

    def generic_oauth_user_from_id_token(id_token)
      payload = JWT.decode(id_token, nil, false).first
      normalize_hash(
        id: payload["sub"],
        email: payload["email"],
        emailVerified: payload["email_verified"],
        name: payload["name"],
        image: payload["picture"]
      )
    rescue
      nil
    end

    def generic_oauth_normalize_tokens(data)
      token_data = normalize_hash(data)
      token_data.merge(
        access_token: token_data[:access_token],
        refresh_token: token_data[:refresh_token],
        id_token: token_data[:id_token],
        access_token_expires_at: generic_oauth_expiry_time(token_data[:expires_in]),
        refresh_token_expires_at: generic_oauth_expiry_time(token_data[:refresh_token_expires_in]),
        scopes: generic_oauth_token_scopes(token_data[:scope]),
        raw: token_data
      ).compact
    end

    def generic_oauth_expiry_time(seconds)
      return nil if seconds.to_i <= 0

      Time.now + seconds.to_i
    end

    def generic_oauth_token_scopes(scope)
      return [] unless scope
      return scope if scope.is_a?(Array)

      scope.to_s.split(/\s+/)
    end

    def generic_oauth_pkce_challenge(code_verifier)
      Crypto.base64url_encode(OpenSSL::Digest.digest("SHA256", code_verifier.to_s))
    end

    def generic_oauth_normalize_user_info(data)
      profile = normalize_hash(data)
      profile.merge(
        id: profile[:id] || profile[:sub],
        email_verified: profile[:email_verified] || false,
        emailVerified: profile[:email_verified] || false,
        image: profile[:image] || profile[:picture]
      )
    end

    def generic_oauth_fetch_json(url, headers = {})
      uri = URI(url)
      request = Net::HTTP::Get.new(uri)
      normalize_hash(headers).each { |key, value| request[key.to_s.tr("_", "-")] = value.to_s }
      response = HTTPClient.request(uri, request)
      return nil unless response.is_a?(Net::HTTPSuccess)

      JSON.parse(response.body)
    rescue
      nil
    end

    def generic_oidc_helper_provider(options, provider_id, issuer, discovery_url, _user_info_url)
      generic_oauth_provider_config(
        options,
        provider_id: provider_id,
        discovery_url: discovery_url,
        scopes: ["openid", "profile", "email"]
      )
    end

    def generic_oauth_provider_config(options, defaults)
      data = normalize_hash(options)
      config = defaults.merge(
        client_id: data[:client_id],
        client_secret: data[:client_secret],
        redirect_uri: data[:redirect_uri],
        pkce: data[:pkce],
        disable_implicit_sign_up: data[:disable_implicit_sign_up],
        disable_sign_up: data[:disable_sign_up],
        override_user_info: data[:override_user_info]
      )
      config[:scopes] = data[:scopes] if data[:scopes]
      config.compact
    end

    def generic_oauth_social_providers(config, context)
      Array(config[:config]).each_with_object({}) do |provider, result|
        provider_id = provider[:provider_id].to_s
        result[provider_id.to_sym] = {
          id: provider_id,
          name: provider_id,
          get_user_info: ->(tokens) { generic_oauth_provider_user_info(provider, tokens) },
          refresh_access_token: ->(refresh_token) { generic_oauth_refresh_access_token(context, provider, refresh_token) }
        }
      end
    end

    def generic_oauth_provider_user_info(provider, tokens)
      user_info = generic_oauth_user_info(provider, tokens)
      return nil unless user_info

      {
        user: generic_oauth_map_user(provider, user_info),
        data: user_info
      }
    end

    def generic_oauth_refresh_access_token(ctx, provider, refresh_token)
      token_url = provider[:token_url] || generic_oauth_discovery(provider)["token_endpoint"]
      raise APIError.new("BAD_REQUEST", message: GENERIC_OAUTH_ERROR_CODES["TOKEN_URL_NOT_FOUND"]) if token_url.to_s.empty?

      generic_oauth_post_refresh_token(ctx, token_url, provider, refresh_token)
    end

    def generic_oauth_post_refresh_token(ctx, token_url, provider, refresh_token)
      uri = URI(token_url)
      request = Net::HTTP::Post.new(uri)
      form_data = {grant_type: "refresh_token", refresh_token: refresh_token}
      authentication = (provider[:authentication] || "post").to_s
      if authentication == "basic"
        request["authorization"] = "Basic #{Base64.strict_encode64("#{provider[:client_id]}:#{provider[:client_secret]}")}"
      else
        form_data[:client_id] = provider[:client_id]
        form_data[:client_secret] = provider[:client_secret] if provider[:client_secret]
      end
      token_url_params = provider[:token_url_params] || provider[:tokenUrlParams]
      token_url_params = token_url_params.call(ctx) if token_url_params.respond_to?(:call)
      normalize_hash(token_url_params || {}).each { |key, value| form_data[key] = value }
      request.set_form_data(form_data.compact)
      response = HTTPClient.request(uri, request)
      raise APIError.new("BAD_REQUEST", message: GENERIC_OAUTH_ERROR_CODES["INVALID_OAUTH_CONFIG"]) unless response.is_a?(Net::HTTPSuccess)

      generic_oauth_normalize_tokens(JSON.parse(response.body))
    end

    def generic_oauth_error_url(base_url, error)
      uri = URI.parse(base_url.to_s)
      query = URI.decode_www_form(uri.query.to_s)
      query << ["error", error.to_s]
      uri.query = URI.encode_www_form(query)
      uri.to_s
    end

    def generic_oauth_warn_duplicate_providers(providers)
      duplicates = providers.group_by { |provider| provider[:provider_id].to_s }.select { |id, entries| !id.empty? && entries.length > 1 }.keys
      warn "Duplicate provider IDs found: #{duplicates.join(", ")}" unless duplicates.empty?
    end
  end
end

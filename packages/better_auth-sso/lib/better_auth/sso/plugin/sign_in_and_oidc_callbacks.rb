# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def sso_sign_in_endpoint(config = {})
      Endpoint.new(path: "/sign-in/sso", method: "POST", metadata: sso_openapi_for(:sign_in)) do |ctx|
        body = normalize_hash(ctx.body)
        provider = sso_select_provider(ctx, body, config)
        provider_type = body[:provider_type].to_s
        if provider_type == "oidc" && !provider["oidcConfig"]
          raise APIError.new("BAD_REQUEST", message: "OIDC provider is not configured")
        end
        if provider_type == "saml" && !provider["samlConfig"]
          raise APIError.new("BAD_REQUEST", message: "SAML provider is not configured")
        end
        if config.dig(:domain_verification, :enabled) && !(provider.key?("domainVerified") && provider["domainVerified"])
          raise APIError.new("UNAUTHORIZED", message: "Provider domain has not been verified")
        end

        state_data = {
          providerId: provider.fetch("providerId"),
          callbackURL: body[:callback_url] || "/",
          errorURL: body[:error_callback_url],
          newUserURL: body[:new_user_callback_url],
          requestSignUp: body[:request_sign_up]
        }

        if provider["oidcConfig"] && provider_type != "saml"
          provider = sso_ensure_runtime_oidc_provider(ctx, provider, config)
          pkce = sso_oidc_pkce_state(provider)
          state = BetterAuth::Crypto.sign_jwt(
            state_data.merge({nonce: BetterAuth::Crypto.random_string(32)}).merge(pkce.except(:codeVerifier)),
            ctx.context.secret,
            expires_in: 600
          )
          sso_store_oidc_pkce_verifier(ctx, state, pkce[:codeVerifier]) if pkce[:codeVerifier]
          url = sso_oidc_authorization_url(provider, ctx, state, config, body)
        elsif provider["samlConfig"]
          BetterAuth::SSO.load_saml!
          relay_state = sso_generate_saml_relay_state(ctx, state_data)
          url = sso_saml_authorization_url(provider, relay_state, ctx, config)
          sso_store_saml_authn_request(ctx, provider, url, config)
        else
          raise APIError.new("BAD_REQUEST", message: "OIDC provider is not configured")
        end
        ctx.json({url: url, redirect: true})
      end
    end

    def sso_oidc_callback_endpoint(config = {})
      Endpoint.new(path: "/sso/callback/:providerId", method: "GET") do |ctx|
        sso_handle_oidc_callback(ctx, config, sso_fetch(ctx.params, :provider_id))
      end
    end

    def sso_oidc_shared_callback_endpoint(config = {})
      Endpoint.new(path: "/sso/callback", method: "GET") do |ctx|
        state = sso_verify_state(ctx.query[:state] || ctx.query["state"], ctx.context.secret)
        next ctx.redirect("#{ctx.context.base_url}/error?error=invalid_state") unless state

        sso_handle_oidc_callback(ctx, config, state["providerId"], state: state)
      end
    end

    def sso_handle_oidc_callback(ctx, config, provider_id, state: nil)
      state ||= sso_verify_state(ctx.query[:state] || ctx.query["state"], ctx.context.secret)
      return ctx.redirect("#{ctx.context.base_url}/error?error=invalid_state") unless state

      callback_url = sso_safe_oidc_redirect_url(ctx, state["callbackURL"] || "/")
      error_url = sso_safe_oidc_redirect_url(ctx, state["errorURL"] || callback_url)
      if ctx.query[:error] || ctx.query["error"]
        error = ctx.query[:error] || ctx.query["error"]
        description = ctx.query[:error_description] || ctx.query["error_description"]
        return sso_redirect(ctx, sso_append_error(error_url, error, description))
      end
      state_provider_id = state["providerId"] || state[:providerId]
      if state_provider_id.to_s != provider_id.to_s
        return sso_redirect(ctx, sso_append_error(error_url, "invalid_state", "provider mismatch"))
      end

      provider = sso_callback_provider(ctx, config, provider_id)
      return sso_redirect(ctx, sso_append_error(error_url, "invalid_provider", "provider not found")) unless provider
      if config.dig(:domain_verification, :enabled) && !(provider.key?("domainVerified") && provider["domainVerified"])
        raise APIError.new("UNAUTHORIZED", message: "Provider domain has not been verified")
      end

      provider = sso_ensure_runtime_oidc_provider(ctx, provider, config)
      oidc_config = sso_provider_config_hash(provider["oidcConfig"])
      oidc_config[:issuer] ||= provider["issuer"]
      return sso_redirect(ctx, sso_append_error(error_url, "invalid_provider", "provider not found")) if oidc_config.empty?

      raw_state = ctx.query[:state] || ctx.query["state"]
      tokens = sso_oidc_tokens(ctx, provider, oidc_config, state, config, raw_state: raw_state)
      unless tokens
        return sso_redirect(ctx, sso_append_error(error_url, "invalid_provider", "token_response_not_found"))
      end
      if oidc_config[:user_info_endpoint].to_s.empty? && tokens[:id_token] && oidc_config[:jwks_endpoint].to_s.empty?
        begin
          provider = sso_ensure_runtime_oidc_provider(ctx, provider, config, require_jwks: true)
          oidc_config = sso_provider_config_hash(provider["oidcConfig"])
          oidc_config[:issuer] ||= provider["issuer"]
        rescue APIError
          # Fall through to the upstream callback error when JWKS is still unavailable.
        end
      end
      user_info = sso_oidc_user_info(ctx, oidc_config, tokens, config, expected_nonce: state["nonce"] || state[:nonce])
      if user_info[:_sso_error]
        return sso_redirect(ctx, sso_append_error(error_url, "invalid_provider", user_info[:_sso_error]))
      end
      if user_info[:email].to_s.empty? || user_info[:id].to_s.empty?
        return sso_redirect(ctx, sso_append_error(error_url, "invalid_provider", "missing_user_info"))
      end
      if config[:disable_implicit_sign_up] && !state["requestSignUp"] && !ctx.context.internal_adapter.find_user_by_email(user_info[:email].to_s.downcase)
        return sso_redirect(ctx, sso_append_error(error_url, "signup disabled"))
      end

      result = sso_find_or_create_user_result(ctx, provider, user_info, config)
      return sso_redirect(ctx, sso_append_error(callback_url, result.fetch(:error))) if result[:error]

      if config[:provision_user].respond_to?(:call) && (result.fetch(:created) || config[:provision_user_on_every_login])
        config[:provision_user].call(user: result.fetch(:user), userInfo: user_info, token: tokens, provider: provider)
      end
      session = ctx.context.internal_adapter.create_session(result.fetch(:user).fetch("id"))
      Cookies.set_session_cookie(ctx, {session: session, user: result.fetch(:user)})
      redirect_to = (result.fetch(:created) && state["newUserURL"].to_s != "") ? sso_safe_oidc_redirect_url(ctx, state["newUserURL"]) : callback_url
      sso_redirect(ctx, redirect_to || "/")
    end
  end
end

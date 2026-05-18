# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_consent_endpoint(config)
      Endpoint.new(path: "/oauth2/consent", method: "POST") do |ctx|
        current_session = Routes.current_session(ctx, allow_nil: true)
        body = OAuthProtocol.stringify_keys(ctx.body)
        consent = config[:store][:consents].delete(body["consent_code"].to_s)
        raise APIError.new("BAD_REQUEST", message: "invalid consent_code") unless consent
        raise APIError.new("BAD_REQUEST", message: "expired consent_code") if consent[:expires_at] <= Time.now
        raise APIError.new("UNAUTHORIZED", message: "session required") unless current_session
        unless current_session[:user]["id"].to_s == consent[:session][:user]["id"].to_s
          raise APIError.new("FORBIDDEN", message: "consent session mismatch")
        end

        query = consent[:query]
        if body["accept"] == false || body["accept"].to_s == "false"
          redirect = OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "access_denied", state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)))
          next ctx.json({redirectURI: redirect})
        end

        granted_scopes = OAuthProtocol.parse_scopes(body["scope"] || body["scopes"])
        granted_scopes = consent[:scopes] if granted_scopes.empty?
        unless granted_scopes.all? { |scope| consent[:scopes].include?(scope) }
          raise APIError.new("BAD_REQUEST", message: "invalid_scope")
        end

        reference_id = consent[:reference_id]
        oauth_store_consent(ctx, consent[:client], consent[:session], granted_scopes, reference_id)
        redirect = oauth_authorization_redirect(ctx, config, query, consent[:session], consent[:client], granted_scopes, reference_id: reference_id)
        ctx.json({redirectURI: redirect})
      end
    end

    def oauth_authorization_redirect(ctx, config, query, session, client, scopes, reference_id: nil)
      code = Crypto.random_string(32)
      client_reference_id = OAuthProtocol.stringify_keys(client)["referenceId"]
      OAuthProtocol.store_code(
        config[:store],
        code: code,
        client_id: query["client_id"],
        redirect_uri: query["redirect_uri"],
        session: session,
        scopes: scopes,
        code_challenge: query["code_challenge"],
        code_challenge_method: query["code_challenge_method"],
        nonce: query["nonce"],
        reference_id: reference_id || client_reference_id,
        expires_in: config[:code_expires_in],
        store_tokens: config[:store_tokens]
      )
      OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], code: code, state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)))
    end

    def oauth_redirect_with_code(ctx, config, query, session, client, scopes, reference_id: nil)
      raise ctx.redirect(oauth_authorization_redirect(ctx, config, query, session, client, scopes, reference_id: reference_id))
    end

    def oauth_consent_granted?(ctx, client_id, user_id, scopes, reference_id = nil)
      where = [
        {field: "clientId", value: client_id},
        {field: "userId", value: user_id}
      ]
      where << {field: "referenceId", value: reference_id} if reference_id
      consent = ctx.context.adapter.find_one(
        model: "oauthConsent",
        where: where
      )
      return false unless consent

      granted = OAuthProtocol.parse_scopes(consent["scopes"])
      scopes.all? { |scope| granted.include?(scope) }
    end

    def oauth_store_consent(ctx, client, session, scopes, reference_id = nil)
      client_id = OAuthProtocol.stringify_keys(client)["clientId"]
      user_id = session[:user]["id"]
      where = [
        {field: "clientId", value: client_id},
        {field: "userId", value: user_id}
      ]
      where << {field: "referenceId", value: reference_id} if reference_id
      existing = ctx.context.adapter.find_one(
        model: "oauthConsent",
        where: where
      )
      data = {clientId: client_id, userId: user_id, scopes: scopes}
      data[:referenceId] = reference_id if reference_id
      if existing
        ctx.context.adapter.update(model: "oauthConsent", where: [{field: "id", value: existing.fetch("id")}], update: data)
      else
        ctx.context.adapter.create(model: "oauthConsent", data: data)
      end
    end

    def oauth_consent_reference(config, session, scopes)
      callback = config.dig(:post_login, :consent_reference_id) || config.dig(:post_login, :consentReferenceId)
      return nil unless callback.respond_to?(:call)

      callback.call({user: session[:user], session: session[:session], scopes: scopes})
    end
  end
end

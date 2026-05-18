# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_introspect_endpoint(config)
      Endpoint.new(path: "/oauth2/introspect", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        client = OAuthProtocol.authenticate_client!(ctx, "oauthClient", store_client_secret: config[:store_client_secret], prefix: config[:prefix], require_confidential: true)
        client_id = OAuthProtocol.stringify_keys(client)["clientId"]
        body = OAuthProtocol.stringify_keys(ctx.body)
        token_value = body["token"].to_s.sub(/\ABearer\s+/i, "")
        token = OAuthProtocol.find_token_by_hint(config[:store], token_value, body["token_type_hint"], prefix: config[:prefix])
        active = token && token["clientId"].to_s == client_id.to_s && !token["revoked"] && (!token["expiresAt"] || token["expiresAt"] > Time.now)
        if active
          next ctx.json({
            active: true,
            client_id: token["clientId"],
            scope: OAuthProtocol.scope_string(token["scope"] || token["scopes"]),
            sub: token["subject"] || token.dig("user", "id"),
            iss: token["issuer"],
            iat: token["issuedAt"]&.to_i,
            exp: token["expiresAt"]&.to_i,
            sid: token["sessionId"],
            aud: token["audience"]
          })
        end

        jwt = oauth_introspect_jwt_access_token(ctx, client, token_value)
        ctx.json(jwt || {active: false})
      end
    end

    def oauth_jwt_access_token?(config, audience)
      !!audience && !config[:disable_jwt_plugin] && !config[:disable_jwt_access_tokens]
    end

    def oauth_introspect_jwt_access_token(ctx, client, token)
      payload = OAuthProtocol.verify_oauth_jwt(ctx, token, issuer: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)), hs256_secret: ctx.context.secret)
      client_data = OAuthProtocol.stringify_keys(client)
      return nil unless payload["azp"] == client_data["clientId"]

      {
        active: true,
        client_id: payload["azp"],
        scope: payload["scope"],
        sub: payload["sub"],
        aud: payload["aud"],
        exp: payload["exp"]
      }.compact
    rescue ::JWT::DecodeError
      nil
    end
  end
end

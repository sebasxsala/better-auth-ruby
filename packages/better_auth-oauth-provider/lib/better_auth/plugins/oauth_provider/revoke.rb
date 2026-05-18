# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_revoke_endpoint(config)
      Endpoint.new(path: "/oauth2/revoke", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        client = OAuthProtocol.authenticate_client!(ctx, "oauthClient", store_client_secret: config[:store_client_secret], prefix: config[:prefix], require_confidential: true)
        client_id = OAuthProtocol.stringify_keys(client)["clientId"]
        body = OAuthProtocol.stringify_keys(ctx.body)
        if body["token_type_hint"].to_s == "access_token" && OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, "refresh_token", prefix: config[:prefix])
          raise APIError.new("BAD_REQUEST", message: "invalid_request")
        end
        if body["token_type_hint"].to_s == "refresh_token" && OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, "access_token", prefix: config[:prefix])
          raise APIError.new("BAD_REQUEST", message: "invalid_request")
        end
        if (token = OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, body["token_type_hint"], prefix: config[:prefix])) && token["clientId"].to_s == client_id.to_s
          token["revoked"] = Time.now
          oauth_persist_token_revocation(ctx, config, body, token)
        end
        ctx.json({revoked: true})
      end
    end

    def oauth_persist_token_revocation(ctx, config, body, token)
      return unless token["id"]

      hint = body["token_type_hint"].to_s
      token_value = body["token"].to_s
      access_value = OAuthProtocol.strip_prefix(token_value, config[:prefix], :access_token)
      refresh_value = OAuthProtocol.strip_prefix(token_value, config[:prefix], :refresh_token)
      is_access = hint == "access_token" || (access_value && config[:store][:tokens][access_value].equal?(token))
      is_refresh = hint == "refresh_token" || (refresh_value && config[:store][:refresh_tokens][refresh_value].equal?(token))

      if is_access && OAuthProtocol.schema_model?(ctx, "oauthAccessToken")
        ctx.context.adapter.update(model: "oauthAccessToken", where: [{field: "id", value: token["id"]}], update: {revoked: token["revoked"]})
      end

      if is_refresh && OAuthProtocol.schema_model?(ctx, "oauthRefreshToken")
        ctx.context.adapter.update(model: "oauthRefreshToken", where: [{field: "id", value: token["id"]}], update: {revoked: token["revoked"]})
        oauth_revoke_refresh_access_tokens(ctx, config[:store], token)
      end
    end

    def oauth_revoke_refresh_access_tokens(ctx, store, refresh_token)
      refresh_id = refresh_token["id"]
      return if refresh_id.to_s.empty?

      store[:tokens].each_value do |record|
        record["revoked"] = refresh_token["revoked"] if record["refreshId"].to_s == refresh_id.to_s
      end
      return unless OAuthProtocol.schema_model?(ctx, "oauthAccessToken")

      ctx.context.adapter.update_many(model: "oauthAccessToken", where: [{field: "refreshId", value: refresh_id}], update: {revoked: refresh_token["revoked"]})
    end
  end
end

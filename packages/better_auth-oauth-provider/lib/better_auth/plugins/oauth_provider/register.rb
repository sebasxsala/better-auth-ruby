# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_register_client_endpoint(config)
      Endpoint.new(
        path: "/oauth2/register",
        method: "POST",
        body_schema: ->(value) { value },
        metadata: oauth_openapi_for(:register_client)
      ) do |ctx|
        session = Routes.current_session(ctx, allow_nil: true)
        body = OAuthProtocol.stringify_keys(ctx.body)
        unless config[:allow_dynamic_client_registration]
          raise APIError.new("FORBIDDEN", message: "Client registration is disabled")
        end
        unless session || config[:allow_unauthenticated_client_registration]
          raise APIError.new("UNAUTHORIZED")
        end
        if body.key?("skip_consent") || body.key?("skipConsent")
          raise APIError.new("BAD_REQUEST", message: "skip_consent is not allowed during dynamic client registration")
        end
        body["require_pkce"] = true unless body.key?("require_pkce") || body.key?("requirePKCE")

        client = OAuthProtocol.create_client(
          ctx,
          model: "oauthClient",
          body: body,
          owner_session: session,
          unauthenticated: session.nil?,
          default_scopes: config[:client_registration_default_scopes] || config[:scopes],
          allowed_scopes: config[:client_registration_allowed_scopes] || config[:scopes],
          store_client_secret: config[:store_client_secret],
          prefix: config[:prefix],
          dynamic_registration: true,
          pairwise_secret: config[:pairwise_secret],
          strip_client_metadata: true,
          reference_id: oauth_client_reference(config, session)
        )
        ctx.json(client, status: 201, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
      end
    end
  end
end

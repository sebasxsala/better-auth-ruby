# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_server_metadata_endpoint(config)
      Endpoint.new(path: "/.well-known/oauth-authorization-server", method: "GET", metadata: {hide: true}) do |ctx|
        base = OAuthProtocol.endpoint_base(ctx)
        metadata = {
          issuer: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)),
          authorization_endpoint: "#{base}/oauth2/authorize",
          token_endpoint: "#{base}/oauth2/token",
          introspection_endpoint: "#{base}/oauth2/introspect",
          revocation_endpoint: "#{base}/oauth2/revoke",
          response_types_supported: ["code"],
          response_modes_supported: ["query"],
          grant_types_supported: config[:grant_types],
          token_endpoint_auth_methods_supported: oauth_token_auth_methods(config),
          introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: true,
          scopes_supported: config.dig(:advertised_metadata, :scopes_supported) || config[:scopes]
        }
        metadata[:registration_endpoint] = "#{base}/oauth2/register" if config[:allow_dynamic_client_registration]
        jwks_uri = oauth_jwks_uri(ctx, config)
        metadata[:jwks_uri] = jwks_uri if jwks_uri
        ctx.json(metadata, headers: oauth_metadata_headers)
      end
    end

    def oauth_openid_metadata_endpoint(config)
      Endpoint.new(path: "/.well-known/openid-configuration", method: "GET", metadata: {hide: true}) do |ctx|
        unless OAuthProtocol.parse_scopes(config[:scopes]).include?("openid")
          raise APIError.new("NOT_FOUND", message: "openid is not enabled")
        end

        base = OAuthProtocol.endpoint_base(ctx)
        metadata = {
          issuer: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)),
          authorization_endpoint: "#{base}/oauth2/authorize",
          token_endpoint: "#{base}/oauth2/token",
          introspection_endpoint: "#{base}/oauth2/introspect",
          revocation_endpoint: "#{base}/oauth2/revoke",
          response_types_supported: ["code"],
          response_modes_supported: ["query"],
          grant_types_supported: config[:grant_types],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
          introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: true,
          scopes_supported: config.dig(:advertised_metadata, :scopes_supported) || config[:scopes],
          userinfo_endpoint: "#{base}/oauth2/userinfo",
          subject_types_supported: config[:pairwise_secret] ? ["public", "pairwise"] : ["public"],
          id_token_signing_alg_values_supported: oauth_id_token_signing_algs(ctx, config),
          end_session_endpoint: "#{base}/oauth2/end-session",
          acr_values_supported: ["urn:mace:incommon:iap:bronze"],
          prompt_values_supported: oauth_prompt_values,
          claims_supported: config.dig(:advertised_metadata, :claims_supported) || config[:claims] || []
        }
        metadata[:registration_endpoint] = "#{base}/oauth2/register" if config[:allow_dynamic_client_registration]
        jwks_uri = oauth_jwks_uri(ctx, config)
        metadata[:jwks_uri] = jwks_uri if jwks_uri
        ctx.json(metadata, headers: oauth_metadata_headers)
      end
    end

    def oauth_metadata_headers
      {"Cache-Control" => "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"}
    end

    def oauth_jwks_uri(ctx, config)
      config.dig(:advertised_metadata, :jwks_uri) ||
        config[:jwks_uri] ||
        config.dig(:jwks, :remote_url) ||
        oauth_default_jwks_uri(ctx, config)
    end

    def oauth_default_jwks_uri(ctx, config)
      return nil if config[:disable_jwt_plugin]

      jwt_plugin = ctx.context.options.plugins.find { |plugin| plugin.id == "jwt" }
      return nil unless jwt_plugin

      path = jwt_plugin.options&.dig(:jwks, :jwks_path) || "/jwks"
      "#{OAuthProtocol.endpoint_base(ctx)}#{path}"
    end

    def oauth_token_auth_methods(config)
      methods = ["client_secret_basic", "client_secret_post"]
      methods.unshift("none") if config[:allow_unauthenticated_client_registration]
      methods
    end

    def oauth_id_token_signing_algs(ctx, config)
      return ["HS256"] if config[:disable_jwt_plugin]

      jwt_plugin = ctx.context.options.plugins.find { |plugin| plugin.id == "jwt" }
      return ["HS256"] unless jwt_plugin

      alg = config.dig(:jwt, :jwks, :key_pair_config, :alg) ||
        jwt_plugin&.options&.dig(:jwks, :key_pair_config, :alg)
      alg ? [alg] : ["EdDSA"]
    end

    def oauth_prompt_values
      ["login", "consent", "create", "select_account", "none"]
    end
  end
end

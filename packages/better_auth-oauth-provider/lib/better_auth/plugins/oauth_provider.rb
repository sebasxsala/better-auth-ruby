# frozen_string_literal: true

require "jwt"
require_relative "../oauth_provider/version"
require_relative "oauth_provider/authorize"
require_relative "oauth_provider/client"
require_relative "oauth_provider/client_resource"
require_relative "oauth_provider/continue"
require_relative "oauth_provider/consent"
require_relative "oauth_provider/introspect"
require_relative "oauth_provider/logout"
require_relative "oauth_provider/mcp"
require_relative "oauth_provider/metadata"
require_relative "oauth_provider/middleware/index"
require_relative "oauth_provider/oauth_client/endpoints"
require_relative "oauth_provider/oauth_client/index"
require_relative "oauth_provider/oauth_consent/endpoints"
require_relative "oauth_provider/oauth_consent/index"
require_relative "oauth_provider/register"
require_relative "oauth_provider/revoke"
require_relative "oauth_provider/schema"
require_relative "oauth_provider/token"
require_relative "oauth_provider/types/helpers"
require_relative "oauth_provider/types/index"
require_relative "oauth_provider/types/oauth"
require_relative "oauth_provider/types/zod"
require_relative "oauth_provider/userinfo"
require_relative "oauth_provider/utils/index"
require_relative "oauth_provider/rate_limit"

module BetterAuth
  module Plugins
    module_function

    remove_method :oauth_provider if method_defined?(:oauth_provider) || private_method_defined?(:oauth_provider)
    singleton_class.remove_method(:oauth_provider) if singleton_class.method_defined?(:oauth_provider) || singleton_class.private_method_defined?(:oauth_provider)

    def oauth_provider(options = {})
      raw_options = normalize_hash(options)
      config = {
        login_page: "/login",
        consent_page: "/oauth2/consent",
        scopes: [],
        grant_types: [OAuthProtocol::AUTH_CODE_GRANT, OAuthProtocol::CLIENT_CREDENTIALS_GRANT, OAuthProtocol::REFRESH_GRANT],
        allow_dynamic_client_registration: false,
        allow_unauthenticated_client_registration: false,
        client_registration_default_scopes: nil,
        client_registration_allowed_scopes: nil,
        signup: {},
        select_account: {},
        post_login: {},
        store_client_secret: "hashed",
        store_tokens: "hashed",
        prefix: {},
        code_expires_in: 600,
        id_token_expires_in: 36_000,
        refresh_token_expires_in: 2_592_000,
        access_token_expires_in: 3600,
        m2m_access_token_expires_in: 3600,
        client_credential_grant_default_scopes: nil,
        scope_expirations: {},
        store: OAuthProtocol.stores
      }.merge(raw_options)

      oauth_provider_validate_config!(config, raw_options)

      Plugin.new(
        id: "oauth-provider",
        version: BetterAuth::OAuthProvider::VERSION,
        init: oauth_provider_init(config),
        hooks: oauth_provider_hooks(config),
        endpoints: oauth_provider_endpoints(config),
        schema: oauth_provider_schema,
        rate_limit: oauth_provider_rate_limits(config),
        options: config
      )
    end

    def oauth_provider_validate_config!(config, raw_options = {})
      provider_scopes = OAuthProtocol.parse_scopes(config[:scopes])
      [
        [:client_registration_allowed_scopes, config[:client_registration_allowed_scopes]],
        [:client_registration_default_scopes, config[:client_registration_default_scopes]]
      ].each do |key, value|
        next if value.nil?

        missing = OAuthProtocol.parse_scopes(value) - provider_scopes
        unless missing.empty?
          raise APIError.new("BAD_REQUEST", message: "#{key} #{missing.first} not found in scopes")
        end
      end

      grant_types = Array(config[:grant_types]).map(&:to_s)
      if grant_types.include?(OAuthProtocol::REFRESH_GRANT) && !grant_types.include?(OAuthProtocol::AUTH_CODE_GRANT)
        raise APIError.new("BAD_REQUEST", message: "refresh_token grant requires authorization_code grant")
      end

      store_client_secret = config[:store_client_secret]
      if config[:disable_jwt_plugin] && raw_options.key?(:store_client_secret) && oauth_hashed_secret_storage?(store_client_secret)
        raise APIError.new("BAD_REQUEST", message: "unable to store hashed secrets because id tokens will be signed with client secret")
      end
      if !config[:disable_jwt_plugin] && oauth_encrypted_secret_storage?(store_client_secret)
        raise APIError.new("BAD_REQUEST", message: "encrypted secret storage is not recommended, please use hashed secret storage with the JWT plugin")
      end
    end

    def oauth_hashed_secret_storage?(value)
      mode = value.is_a?(Hash) ? normalize_hash(value) : value.to_s
      mode == "hashed" || (mode.is_a?(Hash) && mode[:hash].respond_to?(:call))
    end

    def oauth_encrypted_secret_storage?(value)
      mode = value.is_a?(Hash) ? normalize_hash(value) : value.to_s
      mode == "encrypted" || (mode.is_a?(Hash) && (mode[:encrypt].respond_to?(:call) || mode[:decrypt].respond_to?(:call)))
    end

    def oauth_provider_hooks(config)
      {
        before: [
          {
            matcher: ->(ctx) { ctx.path.start_with?("/sign-in/", "/sign-up/") && !!oauth_query_from_body(ctx.body) },
            handler: ->(ctx) { oauth_validate_query_hook!(ctx) }
          }
        ],
        after: [
          {
            matcher: ->(ctx) { oauth_resume_after_session_cookie?(ctx) },
            handler: ->(ctx) { oauth_resume_after_session_cookie(ctx, config) }
          }
        ]
      }
    end

    def oauth_validate_query_hook!(ctx)
      oauth_query = oauth_query_from_body(ctx.body)
      return unless oauth_query

      unless OAuthProvider::Utils.verify_oauth_query_params(oauth_query, ctx.context.secret)
        raise APIError.new("BAD_REQUEST", message: "invalid_signature", body: {error: "invalid_signature"})
      end

      nil
    end

    def oauth_resume_after_session_cookie?(ctx)
      return false unless oauth_query_from_body(ctx.body)
      return false unless ctx.path.start_with?("/sign-in/", "/sign-up/")

      ctx.response_headers["set-cookie"].to_s.include?(ctx.context.auth_cookies[:session_token].name)
    end

    def oauth_resume_after_session_cookie(ctx, config)
      query = oauth_verified_query!(ctx, oauth_query_from_body(ctx.body))
      ctx.context.set_current_session(ctx.context.new_session) if ctx.context.respond_to?(:set_current_session) && ctx.context.new_session
      location = oauth_redirect_location { oauth_authorize_flow(ctx, config, query, continue_post_login: true) }
      [302, Endpoint::Result.merge_headers(ctx.response_headers, {"location" => location}), [""]]
    rescue APIError => error
      raise APIError.new(
        error.status,
        message: error.message,
        headers: Endpoint::Result.merge_headers(ctx.response_headers, error.headers),
        code: error.code,
        body: error.body
      )
    end

    def oauth_query_from_body(body)
      return nil unless body.is_a?(Hash)

      data = OAuthProtocol.stringify_keys(body || {})
      data["oauth_query"] || data["oauthQuery"]
    end

    def oauth_provider_init(config)
      lambda do |context|
        advertised_scopes = Array(config.dig(:advertised_metadata, :scopes_supported)).map(&:to_s)
        provider_scopes = OAuthProtocol.parse_scopes(config[:scopes])
        missing_scopes = advertised_scopes - provider_scopes
        unless missing_scopes.empty?
          raise APIError.new("BAD_REQUEST", message: "advertised_metadata.scopes_supported #{missing_scopes.first} not found in scopes")
        end
        if config[:pairwise_secret] && config[:pairwise_secret].to_s.length < 32
          raise APIError.new("BAD_REQUEST", message: "pairwise_secret must be at least 32 characters")
        end
        if context.options.secondary_storage && !context.options.session[:store_session_in_database]
          raise APIError.new("BAD_REQUEST", message: "OAuth Provider requires session.store_session_in_database when using secondary storage")
        end
        nil
      end
    end

    def oauth_provider_endpoints(config)
      {
        get_o_auth_server_config: oauth_server_metadata_endpoint(config),
        get_open_id_config: oauth_openid_metadata_endpoint(config),
        register_o_auth_client: oauth_register_client_endpoint(config),
        create_o_auth_client: oauth_create_client_endpoint(config),
        admin_create_o_auth_client: oauth_admin_create_client_endpoint(config),
        admin_update_o_auth_client: oauth_admin_update_client_endpoint(config),
        get_o_auth_client: oauth_get_client_endpoint(config),
        get_o_auth_client_public: oauth_get_client_public_endpoint(config),
        get_o_auth_client_public_prelogin: oauth_get_client_public_prelogin_endpoint(config),
        get_o_auth_clients: oauth_list_clients_endpoint(config),
        list_o_auth_clients: oauth_list_clients_endpoint(config),
        delete_o_auth_client: oauth_delete_client_endpoint(config),
        update_o_auth_client: oauth_update_client_endpoint(config),
        rotate_o_auth_client_secret: oauth_rotate_client_secret_endpoint(config),
        get_o_auth_consents: oauth_list_consents_endpoint,
        list_o_auth_consents: oauth_list_consents_endpoint,
        get_o_auth_consent: oauth_get_consent_endpoint,
        update_o_auth_consent: oauth_update_consent_endpoint,
        delete_o_auth_consent: oauth_delete_consent_endpoint,
        legacy_get_o_auth_client: oauth_legacy_get_client_endpoint(config),
        legacy_get_o_auth_client_public: oauth_legacy_get_client_public_endpoint(config),
        legacy_list_o_auth_clients: oauth_legacy_list_clients_endpoint(config),
        legacy_update_o_auth_client: oauth_legacy_update_client_endpoint(config),
        legacy_delete_o_auth_client: oauth_legacy_delete_client_endpoint(config),
        legacy_list_o_auth_consents: oauth_legacy_list_consents_endpoint,
        legacy_get_o_auth_consent: oauth_legacy_get_consent_endpoint,
        legacy_update_o_auth_consent: oauth_legacy_update_consent_endpoint,
        legacy_delete_o_auth_consent: oauth_legacy_delete_consent_endpoint,
        o_auth2_authorize: oauth_authorize_endpoint(config),
        o_auth2_continue: oauth_continue_endpoint(config),
        o_auth2_consent: oauth_consent_endpoint(config),
        o_auth2_token: oauth_token_endpoint(config),
        o_auth2_introspect: oauth_introspect_endpoint(config),
        o_auth2_revoke: oauth_revoke_endpoint(config),
        o_auth2_user_info: oauth_userinfo_endpoint(config),
        o_auth2_end_session: oauth_end_session_endpoint
      }
    end

    def oauth_openapi_for(route)
      {
        register_client: oauth_client_registration_openapi("Register a new OAuth2 client", include_secret: true),
        create_client: oauth_client_registration_openapi("Create a new OAuth2 client", include_secret: true),
        public_client_prelogin: oauth_public_client_prelogin_openapi,
        delete_client: oauth_delete_client_openapi,
        update_client: oauth_update_client_openapi,
        rotate_client_secret: oauth_rotate_client_secret_openapi,
        update_consent: oauth_update_consent_openapi,
        delete_consent: oauth_delete_consent_openapi,
        continue: oauth_continue_openapi,
        consent: oauth_consent_openapi,
        token: oauth_token_openapi,
        introspect: oauth_introspect_openapi,
        revoke: oauth_revoke_openapi,
        end_session: oauth_end_session_openapi
      }.fetch(route)
    end

    def oauth_client_registration_openapi(description, include_secret:)
      {
        openapi: {
          description: description,
          requestBody: OpenAPI.json_request_body(oauth_client_registration_schema),
          responses: {
            "201" => OpenAPI.json_response("OAuth2 client created successfully", oauth_client_response_schema(include_secret: include_secret))
          }
        }
      }
    end

    def oauth_public_client_prelogin_openapi
      {
        openapi: {
          description: "Get public OAuth2 client metadata before login",
          requestBody: OpenAPI.json_request_body(
            OpenAPI.object_schema(
              {
                client_id: {type: "string", description: "OAuth2 client ID"},
                oauth_query: {type: "string", description: "Signed OAuth query string"}
              },
              required: ["client_id", "oauth_query"]
            )
          ),
          responses: {
            "200" => OpenAPI.json_response("Public OAuth2 client metadata", oauth_public_client_schema)
          }
        }
      }
    end

    def oauth_delete_client_openapi
      {
        openapi: {
          description: "Delete an OAuth2 client",
          requestBody: OpenAPI.json_request_body(oauth_client_id_body_schema),
          responses: {
            "200" => OpenAPI.json_response("OAuth2 client deleted", OpenAPI.object_schema({deleted: {type: "boolean"}}, required: ["deleted"]))
          }
        }
      }
    end

    def oauth_update_client_openapi
      {
        openapi: {
          description: "Update an OAuth2 client",
          requestBody: OpenAPI.json_request_body(
            OpenAPI.object_schema(
              {
                client_id: {type: "string", description: "OAuth2 client ID"},
                update: oauth_client_registration_schema.merge(description: "Client metadata to update")
              },
              required: ["client_id", "update"]
            )
          ),
          responses: {
            "200" => OpenAPI.json_response("OAuth2 client updated", oauth_client_response_schema(include_secret: false))
          }
        }
      }
    end

    def oauth_rotate_client_secret_openapi
      {
        openapi: {
          description: "Rotate an OAuth2 client secret",
          requestBody: OpenAPI.json_request_body(oauth_client_id_body_schema),
          responses: {
            "200" => OpenAPI.json_response("OAuth2 client secret rotated", oauth_client_response_schema(include_secret: true))
          }
        }
      }
    end

    def oauth_update_consent_openapi
      {
        openapi: {
          description: "Update OAuth2 consent scopes",
          requestBody: OpenAPI.json_request_body(oauth_consent_mutation_schema(required_update: false)),
          responses: {
            "200" => OpenAPI.json_response("OAuth2 consent updated", oauth_consent_response_schema)
          }
        }
      }
    end

    def oauth_delete_consent_openapi
      {
        openapi: {
          description: "Delete OAuth2 consent",
          requestBody: OpenAPI.json_request_body(oauth_consent_identifier_schema),
          responses: {
            "200" => OpenAPI.json_response("OAuth2 consent deleted", OpenAPI.object_schema({deleted: {type: "boolean"}}, required: ["deleted"]))
          }
        }
      }
    end

    def oauth_continue_openapi
      {
        openapi: {
          description: "Continue an OAuth2 authorization interaction",
          requestBody: OpenAPI.json_request_body(
            OpenAPI.object_schema(
              {
                oauth_query: {type: "string", description: "Signed OAuth query string"},
                selected: {type: "boolean", description: "Continue after account selection"},
                created: {type: "boolean", description: "Continue after account creation"},
                postLogin: {type: "boolean", description: "Continue after post-login flow"},
                post_login: {type: "boolean", description: "Continue after post-login flow"}
              },
              required: ["oauth_query"]
            )
          ),
          responses: {
            "200" => OpenAPI.json_response("OAuth2 authorization redirect", oauth_redirect_response_schema)
          }
        }
      }
    end

    def oauth_consent_openapi
      {
        openapi: {
          description: "Submit an OAuth2 consent decision",
          requestBody: OpenAPI.json_request_body(
            OpenAPI.object_schema(
              {
                consent_code: {type: "string", description: "Consent code issued by the authorization flow"},
                accept: {type: "boolean", description: "Whether the user accepted the consent request"},
                scope: {type: "string", description: "Granted scopes as a space-delimited string"},
                scopes: {type: "array", items: {type: "string"}, description: "Granted scopes"}
              },
              required: ["consent_code"]
            )
          ),
          responses: {
            "200" => OpenAPI.json_response("OAuth2 consent redirect", OpenAPI.object_schema({redirectURI: {type: "string"}}, required: ["redirectURI"]))
          }
        }
      }
    end

    def oauth_token_openapi
      {
        openapi: {
          description: "Exchange an OAuth2 grant for tokens",
          requestBody: OpenAPI.json_request_body(
            OpenAPI.object_schema(
              {
                grant_type: {type: "string", enum: [OAuthProtocol::AUTH_CODE_GRANT, OAuthProtocol::CLIENT_CREDENTIALS_GRANT, OAuthProtocol::REFRESH_GRANT]},
                code: {type: "string", description: "Authorization code"},
                redirect_uri: {type: "string", format: "uri"},
                code_verifier: {type: "string"},
                client_id: {type: "string"},
                client_secret: {type: "string"},
                refresh_token: {type: "string"},
                scope: {type: "string"},
                resource: {oneOf: [{type: "string"}, {type: "array", items: {type: "string"}}]}
              },
              required: ["grant_type"]
            )
          ),
          responses: {
            "200" => OpenAPI.json_response("OAuth2 tokens issued", oauth_token_response_schema)
          }
        }
      }
    end

    def oauth_introspect_openapi
      {
        openapi: {
          description: "Introspect an OAuth2 token",
          requestBody: OpenAPI.json_request_body(
            OpenAPI.object_schema(
              {
                token: {type: "string", description: "Token to introspect"},
                token_type_hint: {type: "string", enum: ["access_token", "refresh_token"]}
              },
              required: ["token"]
            )
          ),
          responses: {
            "200" => OpenAPI.json_response("OAuth2 token introspection result", oauth_introspection_response_schema)
          }
        }
      }
    end

    def oauth_revoke_openapi
      {
        openapi: {
          description: "Revoke an OAuth2 token",
          requestBody: OpenAPI.json_request_body(
            OpenAPI.object_schema(
              {
                token: {type: "string", description: "Token to revoke"},
                token_type_hint: {type: "string", enum: ["access_token", "refresh_token"]}
              },
              required: ["token"]
            )
          ),
          responses: {
            "200" => OpenAPI.json_response("OAuth2 token revoked", OpenAPI.object_schema({revoked: {type: "boolean"}}, required: ["revoked"]))
          }
        }
      }
    end

    def oauth_end_session_openapi
      {
        openapi: {
          description: "End an OpenID Connect session",
          parameters: oauth_end_session_parameters,
          requestBody: OpenAPI.json_request_body(oauth_end_session_body_schema, required: false),
          responses: {
            "200" => OpenAPI.json_response("OpenID Connect session ended", OpenAPI.status_response_schema)
          }
        }
      }
    end

    def oauth_client_registration_schema
      OpenAPI.object_schema(
        {
          redirect_uris: {type: "array", items: {type: "string", format: "uri"}, description: "Allowed redirect URIs"},
          post_logout_redirect_uris: {type: "array", items: {type: "string", format: "uri"}, description: "Allowed post logout redirect URIs"},
          client_name: {type: "string", description: "OAuth2 client name"},
          client_uri: {type: "string", format: "uri"},
          logo_uri: {type: "string", format: "uri"},
          contacts: {type: "array", items: {type: "string"}},
          tos_uri: {type: "string", format: "uri"},
          policy_uri: {type: "string", format: "uri"},
          software_id: {type: "string"},
          software_version: {type: "string"},
          software_statement: {type: "string"},
          token_endpoint_auth_method: {type: "string", enum: ["client_secret_basic", "client_secret_post", "none"]},
          grant_types: {type: "array", items: {type: "string", enum: [OAuthProtocol::AUTH_CODE_GRANT, OAuthProtocol::CLIENT_CREDENTIALS_GRANT, OAuthProtocol::REFRESH_GRANT]}},
          response_types: {type: "array", items: {type: "string", enum: ["code"]}},
          scope: {type: "string"},
          scopes: {type: "array", items: {type: "string"}},
          type: {type: "string", enum: ["web", "native", "user-agent-based"]},
          require_pkce: {type: "boolean"},
          requirePKCE: {type: "boolean"},
          subject_type: {type: "string", enum: ["public", "pairwise"]},
          subjectType: {type: "string", enum: ["public", "pairwise"]},
          enable_end_session: {type: "boolean"},
          enableEndSession: {type: "boolean"},
          skip_consent: {type: "boolean"},
          skipConsent: {type: "boolean"},
          metadata: {type: "object", additionalProperties: true}
        },
        required: ["redirect_uris"]
      )
    end

    def oauth_client_id_body_schema
      OpenAPI.object_schema(
        {
          client_id: {type: "string", description: "OAuth2 client ID"}
        },
        required: ["client_id"]
      )
    end

    def oauth_client_response_schema(include_secret:)
      properties = oauth_public_client_schema[:properties].merge(
        redirect_uris: {type: "array", items: {type: "string", format: "uri"}},
        post_logout_redirect_uris: {type: "array", items: {type: "string", format: "uri"}},
        token_endpoint_auth_method: {type: "string"},
        grant_types: {type: "array", items: {type: "string"}},
        response_types: {type: "array", items: {type: "string"}},
        scope: {type: "string"},
        public: {type: "boolean"},
        type: {type: ["string", "null"]},
        user_id: {type: ["string", "null"]},
        reference_id: {type: ["string", "null"]},
        require_pkce: {type: ["boolean", "null"]},
        subject_type: {type: ["string", "null"]},
        metadata: {type: "object", additionalProperties: true},
        client_id_issued_at: {type: "number"},
        client_secret_expires_at: {type: "number"}
      )
      properties[:client_secret] = {type: "string", description: "OAuth2 client secret"} if include_secret
      OpenAPI.object_schema(properties)
    end

    def oauth_public_client_schema
      OpenAPI.object_schema(
        {
          client_id: {type: "string"},
          client_name: {type: "string"},
          client_uri: {type: ["string", "null"], format: "uri"},
          logo_uri: {type: ["string", "null"], format: "uri"},
          contacts: {type: "array", items: {type: "string"}},
          tos_uri: {type: ["string", "null"], format: "uri"},
          policy_uri: {type: ["string", "null"], format: "uri"}
        }
      )
    end

    def oauth_consent_identifier_schema
      OpenAPI.object_schema(
        {
          id: {type: "string", description: "OAuth2 consent ID"},
          client_id: {type: "string", description: "OAuth2 client ID"}
        }
      )
    end

    def oauth_consent_mutation_schema(required_update:)
      OpenAPI.object_schema(
        oauth_consent_identifier_schema[:properties].merge(
          update: OpenAPI.object_schema({scopes: {type: "array", items: {type: "string"}}}),
          scope: {type: "string"},
          scopes: {type: "array", items: {type: "string"}}
        ),
        required: required_update ? ["update"] : []
      )
    end

    def oauth_consent_response_schema
      OpenAPI.object_schema(
        {
          id: {type: "string"},
          clientId: {type: "string"},
          userId: {type: "string"},
          scopes: {type: "array", items: {type: "string"}},
          createdAt: {type: "string", format: "date-time"},
          updatedAt: {type: "string", format: "date-time"}
        }
      )
    end

    def oauth_redirect_response_schema
      OpenAPI.object_schema(
        {
          redirect: {type: "boolean", enum: [true]},
          url: {type: "string", format: "uri"}
        },
        required: ["redirect", "url"]
      )
    end

    def oauth_token_response_schema
      OpenAPI.object_schema(
        {
          access_token: {type: "string"},
          token_type: {type: "string"},
          expires_in: {type: "number"},
          refresh_token: {type: "string"},
          scope: {type: "string"},
          id_token: {type: "string"}
        },
        required: ["access_token", "token_type"]
      )
    end

    def oauth_introspection_response_schema
      OpenAPI.object_schema(
        {
          active: {type: "boolean"},
          client_id: {type: "string"},
          scope: {type: "string"},
          sub: {type: "string"},
          iss: {type: "string"},
          iat: {type: "number"},
          exp: {type: "number"},
          sid: {type: "string"},
          aud: {oneOf: [{type: "string"}, {type: "array", items: {type: "string"}}]}
        },
        required: ["active"]
      )
    end

    def oauth_end_session_parameters
      oauth_end_session_body_schema[:properties].keys.map do |name|
        OpenAPI.query_parameter(name.to_s, required: false, schema: oauth_end_session_body_schema[:properties][name])
      end
    end

    def oauth_end_session_body_schema
      OpenAPI.object_schema(
        {
          id_token_hint: {type: "string"},
          client_id: {type: "string"},
          post_logout_redirect_uri: {type: "string", format: "uri"},
          state: {type: "string"}
        }
      )
    end
  end
end

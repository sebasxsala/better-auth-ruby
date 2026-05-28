# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    remove_method :sso if method_defined?(:sso) || private_method_defined?(:sso)
    singleton_class.remove_method(:sso) if singleton_class.method_defined?(:sso) || singleton_class.private_method_defined?(:sso)

    SSO_ERROR_CODES = {
      "PROVIDER_NOT_FOUND" => "No provider found",
      "INVALID_STATE" => "Invalid state",
      "SAML_RESPONSE_REPLAYED" => "SAML response has already been used",
      "SINGLE_LOGOUT_NOT_ENABLED" => "Single Logout is not enabled",
      "INVALID_LOGOUT_REQUEST" => "Invalid LogoutRequest",
      "INVALID_LOGOUT_RESPONSE" => "Invalid LogoutResponse",
      "LOGOUT_FAILED_AT_IDP" => "Logout failed at IdP",
      "IDP_SLO_NOT_SUPPORTED" => "IdP does not support Single Logout Service"
    }.freeze

    def sso(options = {})
      config = normalize_hash(options)
      BetterAuth::SSO.load_saml! if BetterAuth::SSO.sso_config_needs_saml?(config)
      if BetterAuth::SSO.saml_loaded? && defined?(BetterAuth::SSO::SAMLHooks)
        config = BetterAuth::SSO::SAMLHooks.merge_options(BetterAuth::SSO::SAML.sso_options, config)
      end
      endpoints = BetterAuth::SSO::Routes::SSO.endpoints(config)
      Plugin.new(
        id: "sso",
        init: ->(_ctx) { {options: {advanced: {disable_origin_check: ["/sso/saml2/callback", "/sso/saml2/sp/acs", "/sso/saml2/sp/slo"]}}} },
        schema: BetterAuth::SSO::Routes::Schemas.plugin_schema(config),
        endpoints: endpoints,
        hooks: sso_hooks(config),
        error_codes: SSO_ERROR_CODES,
        options: config
      )
    end

    def sso_hooks(config = {})
      {
        before: [
          {
            matcher: ->(ctx) { ctx.path == "/sign-out" },
            handler: ->(ctx) { sso_before_sign_out(ctx, config) }
          }
        ],
        after: [
          {
            matcher: ->(ctx) { ctx.path.to_s.match?(%r{\A/callback/[^/]+\z}) },
            handler: ->(ctx) { sso_after_generic_callback(ctx, config) }
          }
        ]
      }
    end

    def sso_before_sign_out(ctx, config = {})
      return unless config.dig(:saml, :enable_single_logout)

      token_cookie = ctx.context.auth_cookies[:session_token]
      session_token = ctx.get_signed_cookie(token_cookie.name, ctx.context.secret)
      return if session_token.to_s.empty?

      lookup_key = "#{SSO_SAML_SESSION_BY_ID_KEY_PREFIX}#{session_token}"
      session_lookup = ctx.context.internal_adapter.find_verification_value(lookup_key)
      saml_session_key = session_lookup&.fetch("value", nil)
      ctx.context.internal_adapter.delete_verification_by_identifier(saml_session_key) if saml_session_key
      ctx.context.internal_adapter.delete_verification_by_identifier(lookup_key)
      nil
    rescue
      nil
    end

    def sso_after_generic_callback(ctx, config = {})
      new_session = ctx.context.new_session if ctx.context.respond_to?(:new_session)
      return unless new_session && new_session[:user]
      return unless defined?(BetterAuth::SSO::Linking::OrgAssignment)

      BetterAuth::SSO::Linking::OrgAssignment.assign_organization_by_domain(
        ctx,
        user: new_session.fetch(:user),
        provisioning_options: config[:organization_provisioning],
        domain_verification: config[:domain_verification]
      )
      nil
    end

    def sso_schema(config = {})
      BetterAuth::SSO::Routes::Schemas.plugin_schema(config)
    end

    def sso_openapi_for(route)
      {
        register_provider: sso_register_provider_openapi,
        sign_in: sso_sign_in_openapi,
        saml_callback: sso_saml_callback_openapi,
        saml_acs: sso_saml_acs_openapi,
        saml_slo: sso_saml_slo_openapi,
        initiate_slo: sso_initiate_slo_openapi,
        update_provider: sso_update_provider_openapi,
        delete_provider: sso_delete_provider_openapi
      }.fetch(route)
    end

    def sso_register_provider_openapi
      {
        openapi: {
          description: "Register an SSO provider",
          requestBody: OpenAPI.json_request_body(sso_provider_body_schema(required_fields: ["provider_id", "issuer", "domain"])),
          responses: {
            "200" => OpenAPI.json_response("SSO provider registered", sso_provider_response_schema)
          }
        }
      }
    end

    def sso_sign_in_openapi
      {
        openapi: {
          description: "Start an SSO sign-in flow",
          requestBody: OpenAPI.json_request_body(
            OpenAPI.object_schema(
              {
                provider_id: {type: "string", description: "SSO provider ID"},
                domain: {type: "string", description: "Email domain used to select a provider"},
                provider_type: {type: "string", enum: ["oidc", "saml"], description: "Preferred provider protocol"},
                callback_url: {type: "string", description: "URL to redirect to after successful sign-in"},
                error_callback_url: {type: "string", description: "URL to redirect to on sign-in error"},
                new_user_callback_url: {type: "string", description: "URL to redirect to for new users"},
                request_sign_up: {type: "boolean", description: "Whether the flow is requesting sign-up"}
              }
            )
          ),
          responses: {
            "200" => OpenAPI.json_response("SSO sign-in URL", OpenAPI.object_schema({url: {type: "string"}, redirect: {type: "boolean"}}, required: ["url", "redirect"]))
          }
        }
      }
    end

    def sso_saml_callback_openapi
      {
        openapi: {
          description: "Handle a SAML identity provider callback",
          requestBody: OpenAPI.json_request_body(sso_saml_message_schema, required: false),
          responses: {
            "200" => OpenAPI.json_response("SAML callback handled", {type: "object", additionalProperties: true})
          }
        }
      }
    end

    def sso_saml_acs_openapi
      {
        openapi: {
          description: "Handle a SAML assertion consumer service response",
          requestBody: OpenAPI.json_request_body(sso_saml_message_schema, required: false),
          responses: {
            "200" => OpenAPI.json_response("SAML response handled", {type: "object", additionalProperties: true})
          }
        }
      }
    end

    def sso_saml_slo_openapi
      {
        openapi: {
          description: "Handle SAML single logout",
          requestBody: OpenAPI.json_request_body(sso_saml_message_schema, required: false),
          responses: {
            "200" => OpenAPI.json_response("SAML single logout handled", {type: "object", additionalProperties: true})
          }
        }
      }
    end

    def sso_initiate_slo_openapi
      {
        openapi: {
          description: "Initiate SAML single logout",
          requestBody: OpenAPI.json_request_body(
            OpenAPI.object_schema(
              {
                callback_url: {type: "string", description: "URL to return to after logout"}
              }
            ),
            required: false
          ),
          responses: {
            "200" => OpenAPI.json_response("SAML logout initiated", {type: "object", additionalProperties: true})
          }
        }
      }
    end

    def sso_update_provider_openapi
      {
        openapi: {
          description: "Update an SSO provider",
          requestBody: OpenAPI.json_request_body(sso_provider_body_schema(required_fields: [])),
          responses: {
            "200" => OpenAPI.json_response("SSO provider updated", sso_provider_response_schema)
          }
        }
      }
    end

    def sso_delete_provider_openapi
      {
        openapi: {
          description: "Delete an SSO provider",
          requestBody: OpenAPI.json_request_body(
            OpenAPI.object_schema(
              {
                provider_id: {type: "string", description: "SSO provider ID"}
              }
            )
          ),
          responses: {
            "200" => OpenAPI.json_response("SSO provider deleted", OpenAPI.success_response_schema)
          }
        }
      }
    end

    def sso_provider_body_schema(required_fields:)
      OpenAPI.object_schema(
        {
          provider_id: {type: "string", description: "SSO provider ID"},
          issuer: {type: "string", description: "SSO provider issuer URL"},
          domain: {type: "string", description: "Email domain for the provider"},
          oidc_config: {type: "object", additionalProperties: true, description: "OIDC provider configuration"},
          saml_config: {type: "object", additionalProperties: true, description: "SAML provider configuration"},
          organization_id: {type: "string", description: "Organization ID for this provider"},
          override_user_info: {type: "boolean", description: "Whether to override OIDC user info with ID token claims"}
        },
        required: required_fields
      )
    end

    def sso_provider_response_schema
      OpenAPI.object_schema(
        {
          id: {type: "string"},
          providerId: {type: "string"},
          issuer: {type: "string"},
          domain: {type: "string"},
          oidcConfig: {type: ["object", "null"], additionalProperties: true},
          samlConfig: {type: ["object", "null"], additionalProperties: true},
          userId: {type: "string"},
          organizationId: {type: ["string", "null"]},
          domainVerified: {type: "boolean"},
          redirectURI: {type: "string"},
          domainVerificationToken: {type: "string"}
        }
      )
    end

    def sso_saml_message_schema
      OpenAPI.object_schema(
        {
          SAMLResponse: {type: "string", description: "SAML response"},
          SAMLRequest: {type: "string", description: "SAML logout request"},
          RelayState: {type: "string", description: "SAML relay state"},
          saml_response: {type: "string", description: "SAML response"},
          saml_request: {type: "string", description: "SAML logout request"},
          relay_state: {type: "string", description: "SAML relay state"}
        }
      )
    end
  end
end

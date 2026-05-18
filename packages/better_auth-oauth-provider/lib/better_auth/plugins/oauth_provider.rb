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
      }.merge(normalize_hash(options))

      Plugin.new(
        id: "oauth-provider",
        version: BetterAuth::OAuthProvider::VERSION,
        init: oauth_provider_init(config),
        endpoints: oauth_provider_endpoints(config),
        schema: oauth_provider_schema,
        rate_limit: oauth_provider_rate_limits(config),
        options: config
      )
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
  end
end

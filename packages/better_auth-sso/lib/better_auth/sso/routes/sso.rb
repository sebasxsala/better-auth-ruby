# frozen_string_literal: true

module BetterAuth
  module SSO
    module Routes
      module SSO
        module_function

        def endpoints(config = {})
          normalized = BetterAuth::Plugins.normalize_hash(config || {})
          if BetterAuth::SSO.eager_load_saml? || BetterAuth::SSO.sso_config_needs_saml?(normalized)
            BetterAuth::SSO.load_saml!
          end
          endpoints = {
            register_sso_provider: BetterAuth::Plugins.sso_register_provider_endpoint(normalized),
            sign_in_sso: BetterAuth::Plugins.sso_sign_in_endpoint(normalized),
            callback_sso: BetterAuth::Plugins.sso_oidc_callback_endpoint(normalized),
            callback_sso_shared: BetterAuth::Plugins.sso_oidc_shared_callback_endpoint(normalized),
            list_sso_providers: BetterAuth::Plugins.sso_list_providers_endpoint,
            get_sso_provider: BetterAuth::Plugins.sso_get_provider_endpoint,
            update_sso_provider: BetterAuth::Plugins.sso_update_provider_endpoint(normalized),
            delete_sso_provider: BetterAuth::Plugins.sso_delete_provider_endpoint
          }
          if BetterAuth::SSO.saml_loaded?
            endpoints[:sp_metadata] = BetterAuth::Plugins.sso_sp_metadata_endpoint(normalized)
            endpoints[:callback_sso_saml] = BetterAuth::Plugins.sso_saml_callback_endpoint(normalized)
            endpoints[:acs_endpoint] = BetterAuth::Plugins.sso_saml_acs_endpoint(normalized)
            endpoints[:slo_endpoint] = BetterAuth::Plugins.sso_saml_slo_endpoint(normalized)
            endpoints[:initiate_slo] = BetterAuth::Plugins.sso_initiate_slo_endpoint(normalized)
          end
          if normalized.dig(:domain_verification, :enabled)
            endpoints[:request_domain_verification] = BetterAuth::Plugins.sso_request_domain_verification_endpoint(normalized)
            endpoints[:verify_domain] = BetterAuth::Plugins.sso_verify_domain_endpoint(normalized)
          end
          endpoints
        end

        def oidc_redirect_uri(context, provider_id)
          BetterAuth::Plugins.sso_oidc_redirect_uri(context, provider_id)
        end

        def saml_authorization_url(provider, relay_state, ctx = nil, config = {})
          BetterAuth::Plugins.sso_saml_authorization_url(provider, relay_state, ctx, config)
        end
      end
    end
  end
end

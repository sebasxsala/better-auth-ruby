# frozen_string_literal: true

module BetterAuth
  module SSO
    module SAML
      module ErrorCodes
        SAML_ERROR_CODES = {
          single_logout_not_enabled: "Single Logout is not enabled",
          invalid_logout_response: "Invalid LogoutResponse",
          invalid_logout_request: "Invalid LogoutRequest",
          logout_failed_at_idp: "Logout failed at IdP",
          idp_slo_not_supported: "IdP does not support Single Logout Service",
          saml_provider_not_found: "SAML provider not found"
        }.freeze

        module_function

        def message(code)
          SAML_ERROR_CODES[BetterAuth::Plugins.normalize_key(code)]
        end
      end
    end
  end
end

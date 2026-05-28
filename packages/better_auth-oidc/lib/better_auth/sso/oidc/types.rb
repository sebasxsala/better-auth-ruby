# frozen_string_literal: true

module BetterAuth
  module SSO
    module OIDC
      module Types
        DISCOVERY_ERROR_CODES = %w[
          discovery_timeout
          discovery_not_found
          discovery_invalid_json
          discovery_invalid_url
          discovery_untrusted_origin
          issuer_mismatch
          discovery_incomplete
          unsupported_token_auth_method
          discovery_unexpected_error
        ].freeze

        REQUIRED_DISCOVERY_FIELDS = Discovery::REQUIRED_DISCOVERY_FIELDS

        module_function

        def discovery_error_code?(value)
          DISCOVERY_ERROR_CODES.include?(value.to_s)
        end
      end
    end
  end
end

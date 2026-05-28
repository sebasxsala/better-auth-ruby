# frozen_string_literal: true

module BetterAuth
  module SSO
    module SAML
      module Timestamp
        module_function

        def validate!(conditions, config = {}, now: Time.now.utc)
          BetterAuth::Plugins.sso_validate_saml_timestamp!(conditions, config, now: now)
        end

        def conditions(assertion)
          BetterAuth::Plugins.sso_saml_timestamp_conditions(assertion)
        end
      end
    end
  end
end

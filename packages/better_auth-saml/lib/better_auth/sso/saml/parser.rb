# frozen_string_literal: true

module BetterAuth
  module SSO
    module SAML
      module Parser
        module_function

        def parse_response(value, config = {}, provider = nil, ctx = nil)
          BetterAuth::Plugins.sso_parse_saml_response(value, config, provider, ctx)
        end

        def base64_xml?(value)
          BetterAuth::Plugins.sso_base64_xml?(value)
        end
      end
    end
  end
end

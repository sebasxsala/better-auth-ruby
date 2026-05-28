# frozen_string_literal: true

module BetterAuth
  module SSO
    module SAML
      module Assertions
        module_function

        def validate_single_assertion!(saml_response)
          BetterAuth::Plugins.sso_validate_single_saml_assertion!(saml_response)
        end

        def count(xml)
          assertions = xml.to_s.scan(/<(?:\w+:)?Assertion(?:\s|>|\/)/).length
          encrypted_assertions = xml.to_s.scan(/<(?:\w+:)?EncryptedAssertion(?:\s|>|\/)/).length
          {assertions: assertions, encrypted_assertions: encrypted_assertions, total: assertions + encrypted_assertions}
        end
      end
    end
  end
end

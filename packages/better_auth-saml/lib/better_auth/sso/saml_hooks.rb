# frozen_string_literal: true

module BetterAuth
  module SSO
    module SAMLHooks
      module_function

      def merge_options(sso_options = {}, saml_options = {})
        sso_options = BetterAuth::Plugins.normalize_hash(sso_options || {})
        saml_options = BetterAuth::Plugins.normalize_hash(saml_options || {})
        sso_options.merge(saml_options) do |key, old_value, new_value|
          if key == :saml
            BetterAuth::Plugins.normalize_hash(old_value || {}).merge(BetterAuth::Plugins.normalize_hash(new_value || {}))
          else
            new_value
          end
        end
      end
    end
  end
end

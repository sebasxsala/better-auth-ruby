# frozen_string_literal: true

module BetterAuth
  module SSO
    module_function

    def load_saml!
      return if saml_loaded?

      require "better_auth/saml"
    rescue LoadError
      raise LoadError, 'SAML SSO requires gem "better_auth-saml". Add it to your Gemfile.'
    end

    def saml_loaded?
      defined?(BetterAuth::SSO::SAML) &&
        BetterAuth::SSO::SAML.respond_to?(:validate_config_algorithms)
    end

    def eager_load_saml?
      ENV["BETTER_AUTH_SSO_SAML"] == "1" ||
        Gem.loaded_specs.key?("better_auth-saml")
    end

    def sso_config_needs_saml?(config)
      normalized = BetterAuth::Plugins.normalize_hash(config || {})
      return true if normalized[:saml].is_a?(Hash) && !normalized[:saml].empty?

      default_sso = normalized[:defaultSSO] || normalized[:default_sso]
      if default_sso.is_a?(Hash)
        provider_type = default_sso[:providerType] || default_sso[:provider_type]
        return true if provider_type.to_s == "saml"
      end

      false
    end
  end
end

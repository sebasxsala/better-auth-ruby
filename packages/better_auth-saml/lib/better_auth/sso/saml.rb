# frozen_string_literal: true

require "base64"
require "logger"
require "onelogin/ruby-saml"
require "uri"

module BetterAuth
  module SSO
    module SAML
      module_function

      DEFAULT_ATTRIBUTE_MAP = {
        email: %w[email mail emailAddress Email EmailAddress],
        name: %w[name displayName cn Name DisplayName],
        given_name: %w[givenName firstName FirstName],
        family_name: %w[familyName lastName LastName]
      }.freeze

      def sso_options(**options)
        {
          saml: {
            auth_request_url: auth_request_url(**options),
            parse_response: response_parser(**options)
          }
        }
      end

      def validate_config_algorithms(config = {}, **options)
        Algorithms.validate_config(config, **options)
      end

      def validate_saml_algorithms(xml, **options)
        Algorithms.validate(xml, **options)
      end

      def validate_single_assertion(saml_response)
        Assertions.validate_single_assertion!(saml_response)
      end

      def auth_request_url(settings: nil, request_options: {}, **_options)
        lambda do |provider:, relay_state:, context:|
          config = BetterAuth::Plugins.normalize_hash(provider["samlConfig"] || provider[:samlConfig] || {})
          saml_settings = settings.respond_to?(:call) ? settings.call(provider: provider, context: context, saml_config: config) : build_settings(provider, context, config, settings)
          OneLogin::RubySaml::Authrequest.new.create(saml_settings, {RelayState: relay_state}.merge(request_options))
        end
      end

      def response_parser(settings: nil, response_options: {}, attribute_map: DEFAULT_ATTRIBUTE_MAP, **_options)
        lambda do |raw_response:, provider:, context:|
          config = BetterAuth::Plugins.normalize_hash(provider["samlConfig"] || provider[:samlConfig] || {})
          saml_settings = settings.respond_to?(:call) ? settings.call(provider: provider, context: context, saml_config: config) : build_settings(provider, context, config, settings)
          validate_response_xml!(raw_response, config)
          response = OneLogin::RubySaml::Response.new(raw_response, {settings: saml_settings}.merge(response_options))
          unless response.is_valid?
            raise BetterAuth::APIError.new("BAD_REQUEST", message: "Invalid SAML response")
          end

          attributes = response.attributes
          mapping = BetterAuth::Plugins.normalize_hash(config[:mapping] || {})
          email = mapped_attribute(attributes, mapping[:email]) || first_attribute(attributes, attribute_map.fetch(:email)) || response.nameid
          raise BetterAuth::APIError.new("BAD_REQUEST", message: "Invalid SAML response") if email.to_s.empty?

          given_name = mapped_attribute(attributes, mapping[:first_name]) || first_attribute(attributes, attribute_map.fetch(:given_name))
          family_name = mapped_attribute(attributes, mapping[:last_name]) || first_attribute(attributes, attribute_map.fetch(:family_name))
          name = [given_name, family_name].compact.join(" ").strip
          name = mapped_attribute(attributes, mapping[:name]) || first_attribute(attributes, attribute_map.fetch(:name)) if name.empty?
          extra_fields = mapped_extra_fields(attributes, mapping)
          email_verified = mapping[:email_verified] ? mapped_attribute(attributes, mapping[:email_verified]) : false
          extra_fields.merge(
            email: email.to_s.downcase,
            name: name.to_s.empty? ? email.to_s : name.to_s,
            id: mapped_attribute(attributes, mapping[:id]) || assertion_identifier(response, email),
            name_id: response.nameid,
            session_index: response.sessionindex,
            email_verified: (email_verified == false) ? false : !email_verified.to_s.empty?
          )
        end
      end

      def build_settings(provider, context, config, overrides = nil)
        settings = overrides || OneLogin::RubySaml::Settings.new
        provider_id = provider.fetch("providerId")
        base_url = context.context.base_url
        idp_metadata = BetterAuth::Plugins.respond_to?(:sso_saml_idp_metadata) ? BetterAuth::Plugins.sso_saml_idp_metadata(config) : {}
        sso_service = BetterAuth::Plugins.respond_to?(:sso_saml_preferred_service) ? BetterAuth::Plugins.sso_saml_preferred_service(idp_metadata[:single_sign_on_service]) : nil
        sso_service = BetterAuth::Plugins.normalize_hash(sso_service || {})
        settings.assertion_consumer_service_url = if BetterAuth::Plugins.respond_to?(:sso_saml_acs_url?) && BetterAuth::Plugins.sso_saml_acs_url?(config[:callback_url])
          config[:callback_url]
        else
          "#{base_url}/sso/saml2/sp/acs/#{URI.encode_www_form_component(provider_id)}"
        end
        settings.sp_entity_id = config.dig(:sp_metadata, :entity_id) || config[:audience] || "#{base_url}/sso/saml2/sp/metadata?providerId=#{URI.encode_www_form_component(provider_id)}"
        settings.idp_entity_id = idp_metadata[:entity_id] || provider["issuer"] || provider[:issuer]
        settings.idp_sso_service_url = config[:entry_point] || sso_service[:location]
        settings.idp_cert = config[:cert] || idp_metadata[:cert] unless (config[:cert] || idp_metadata[:cert]).to_s.empty?
        settings.name_identifier_format = config[:identifier_format] unless config[:identifier_format].to_s.empty?
        private_key = config.dig(:sp_metadata, :private_key) || config[:private_key] || config[:sp_private_key]
        authn_requests_signed = config.fetch(:authn_requests_signed, config[:want_authn_requests_signed])
        if authn_requests_signed && private_key.to_s.empty?
          raise BetterAuth::APIError.new("BAD_REQUEST", message: "SAML authnRequestsSigned requires privateKey")
        end
        settings.private_key = private_key unless private_key.to_s.empty?
        certificate = config.dig(:sp_metadata, :certificate) || config[:sp_certificate]
        certificate ||= config[:certificate] if config[:certificate].is_a?(String)
        settings.certificate = certificate unless certificate.to_s.empty?
        settings.security[:want_assertions_signed] = config.fetch(:want_assertions_signed, true)
        settings.security[:want_messages_signed] = config.fetch(:want_messages_signed, false)
        settings.security[:want_assertions_encrypted] = config.fetch(:want_assertions_encrypted, false)
        settings.security[:authn_requests_signed] = !!authn_requests_signed
        settings.security[:strict_audience_validation] = true
        settings.security[:digest_method] = config[:digest_algorithm] || XMLSecurity::Document::SHA256
        settings.security[:signature_method] = if config[:signature_algorithm]
          BetterAuth::Plugins.sso_normalize_saml_signature_algorithm(config[:signature_algorithm])
        else
          XMLSecurity::Document::RSA_SHA256
        end
        settings
      end

      def validate_response_xml!(raw_response, config)
        BetterAuth::Plugins.sso_validate_single_saml_assertion!(raw_response)
        xml = Base64.decode64(raw_response.to_s)
        BetterAuth::Plugins.sso_validate_saml_algorithms!(
          xml,
          on_deprecated: config.fetch(:on_deprecated_algorithm, "reject"),
          allowed_signature_algorithms: config[:allowed_signature_algorithms],
          allowed_digest_algorithms: config[:allowed_digest_algorithms],
          allowed_key_encryption_algorithms: config[:allowed_key_encryption_algorithms],
          allowed_data_encryption_algorithms: config[:allowed_data_encryption_algorithms]
        )
      rescue BetterAuth::APIError
        raise BetterAuth::APIError.new("BAD_REQUEST", message: "Invalid SAML response")
      rescue
        raise BetterAuth::APIError.new("BAD_REQUEST", message: "Invalid SAML response")
      end

      def first_attribute(attributes, names)
        Array(names).each do |name|
          value = attribute_value(attributes, name)
          value = value.first if value.is_a?(Array)
          return value unless value.to_s.empty?
        end
        nil
      end

      def mapped_attribute(attributes, name)
        return nil if name.to_s.empty?

        value = attribute_value(attributes, name)
        value = value.first if value.is_a?(Array)
        value unless value.to_s.empty?
      end

      def mapped_extra_fields(attributes, mapping)
        BetterAuth::Plugins.normalize_hash(mapping[:extra_fields] || {}).each_with_object({}) do |(target, source), result|
          result[target] = mapped_attribute(attributes, source)
        end
      end

      def attribute_value(attributes, name)
        [name, name.to_s, BetterAuth::Plugins.normalize_key(name)].each do |key|
          return attributes[key] if attributes.respond_to?(:key?) && attributes.key?(key)
        end
        attributes[name] || attributes[name.to_s] || attributes[BetterAuth::Plugins.normalize_key(name)]
      end

      def assertion_identifier(response, email)
        response.assertion_id || response.nameid || response.sessionindex || email
      end
    end
  end
end

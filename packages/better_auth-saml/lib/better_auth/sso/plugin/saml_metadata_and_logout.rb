# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def sso_validate_saml_config!(saml_config, plugin_config = {})
      metadata = saml_config[:idp_metadata] || saml_config[:metadata] || saml_config[:idp_metadata_xml]
      idp_metadata = normalize_hash(saml_config[:idp_metadata] || {})
      has_idp_metadata_xml = !idp_metadata[:metadata].to_s.empty? || !saml_config[:metadata].to_s.empty? || !saml_config[:idp_metadata_xml].to_s.empty?
      has_idp_sso_service = !Array(idp_metadata[:single_sign_on_service] || saml_config[:single_sign_on_service]).empty?
      max_metadata_size = plugin_config.dig(:saml, :max_metadata_size) || SSO_DEFAULT_MAX_SAML_METADATA_SIZE
      if metadata.to_s.bytesize > max_metadata_size
        raise APIError.new("BAD_REQUEST", message: "IdP metadata exceeds maximum allowed size (#{max_metadata_size} bytes)")
      end

      if saml_config[:entry_point].to_s.empty? && !has_idp_sso_service && !has_idp_metadata_xml
        raise APIError.new("BAD_REQUEST", message: "SAML configuration requires either idpMetadata.metadata, idpMetadata.singleSignOnService, or a valid entryPoint URL")
      end
      sso_validate_url!(saml_config[:entry_point], "SAML entryPoint must be a valid URL") unless saml_config[:entry_point].to_s.empty?
      unless saml_config[:single_sign_on_service].to_s.empty?
        sso_validate_url!(saml_config[:single_sign_on_service], "SAML singleSignOnService must be a valid URL")
      end
      unless saml_config[:single_logout_service].to_s.empty?
        sso_validate_url!(saml_config[:single_logout_service], "SAML singleLogoutService must be a valid URL")
      end

      config_algorithm_xml = +""
      unless saml_config[:signature_algorithm].to_s.empty?
        config_algorithm_xml << "<ds:SignatureMethod Algorithm=\"#{saml_config[:signature_algorithm]}\"/>"
      end
      unless saml_config[:digest_algorithm].to_s.empty?
        config_algorithm_xml << "<ds:DigestMethod Algorithm=\"#{saml_config[:digest_algorithm]}\"/>"
      end
      sso_validate_saml_algorithms!(
        config_algorithm_xml,
        on_deprecated: plugin_config.dig(:saml, :algorithms, :on_deprecated) || saml_config[:on_deprecated_algorithm] || "warn",
        allowed_signature_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_signature_algorithms) || saml_config[:allowed_signature_algorithms],
        allowed_digest_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_digest_algorithms) || saml_config[:allowed_digest_algorithms],
        allowed_key_encryption_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_key_encryption_algorithms) || saml_config[:allowed_key_encryption_algorithms],
        allowed_data_encryption_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_data_encryption_algorithms) || saml_config[:allowed_data_encryption_algorithms]
      )
      sso_validate_saml_algorithms!(
        metadata.to_s,
        on_deprecated: plugin_config.dig(:saml, :algorithms, :on_deprecated) || saml_config[:on_deprecated_algorithm] || "warn",
        allowed_signature_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_signature_algorithms) || saml_config[:allowed_signature_algorithms],
        allowed_digest_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_digest_algorithms) || saml_config[:allowed_digest_algorithms],
        allowed_key_encryption_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_key_encryption_algorithms) || saml_config[:allowed_key_encryption_algorithms],
        allowed_data_encryption_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_data_encryption_algorithms) || saml_config[:allowed_data_encryption_algorithms]
      )
    end

    def sso_sp_metadata_xml(ctx, provider, config = {})
      provider_id = provider.fetch("providerId")
      saml_config = sso_provider_config_hash(provider["samlConfig"])
      explicit_metadata = saml_config.dig(:sp_metadata, :metadata)
      return explicit_metadata unless explicit_metadata.to_s.empty?

      entity_id = saml_config.dig(:sp_metadata, :entity_id) || saml_config[:audience] || provider["issuer"] || "#{ctx.context.base_url}/sso/saml2/sp/metadata?providerId=#{URI.encode_www_form_component(provider_id)}"
      acs_url = sso_saml_acs_url(ctx, provider)
      authn_requests_signed = !!saml_config[:authn_requests_signed]
      want_assertions_signed = saml_config.key?(:want_assertions_signed) ? !!saml_config[:want_assertions_signed] : true
      escaped_entity_id = CGI.escapeHTML(entity_id.to_s)
      escaped_acs_url = CGI.escapeHTML(acs_url.to_s)
      name_id_format = saml_config[:identifier_format].to_s.empty? ? "" : "<NameIDFormat>#{CGI.escapeHTML(saml_config[:identifier_format].to_s)}</NameIDFormat>"
      slo = if config.dig(:saml, :enable_single_logout)
        location = CGI.escapeHTML("#{ctx.context.base_url}/sso/saml2/sp/slo/#{URI.encode_www_form_component(provider_id)}")
        "<SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"#{location}\" /><SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"#{location}\" />"
      end

      "<EntityDescriptor entityID=\"#{escaped_entity_id}\"><SPSSODescriptor AuthnRequestsSigned=\"#{authn_requests_signed}\" WantAssertionsSigned=\"#{want_assertions_signed}\">#{slo}#{name_id_format}<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"#{escaped_acs_url}\" index=\"0\" /></SPSSODescriptor></EntityDescriptor>"
    end

    def sso_saml_acs_url(ctx, provider)
      provider_id = provider.fetch("providerId")
      base_url = ctx.context.base_url
      configured = sso_provider_config_hash(provider["samlConfig"])[:callback_url].to_s
      return configured if sso_saml_acs_url?(configured)

      "#{base_url}/sso/saml2/sp/acs/#{URI.encode_www_form_component(provider_id)}"
    end

    def sso_saml_acs_url?(url)
      return false if url.to_s.empty?

      URI.parse(url.to_s).path.include?("/sso/saml2/sp/acs")
    rescue
      false
    end

    def sso_saml_idp_metadata(provider_or_config)
      saml_config = if provider_or_config.respond_to?(:key?) && (provider_or_config.key?("samlConfig") || provider_or_config.key?(:samlConfig))
        normalize_hash(provider_or_config["samlConfig"] || provider_or_config[:samlConfig] || {})
      else
        normalize_hash(provider_or_config || {})
      end
      idp_metadata = normalize_hash(saml_config[:idp_metadata] || {})
      xml = idp_metadata[:metadata] || saml_config[:metadata] || saml_config[:idp_metadata_xml]
      parsed = xml.to_s.strip.empty? ? {} : sso_parse_saml_metadata_xml(xml)
      parsed[:entity_id] ||= idp_metadata[:entity_id] || idp_metadata[:entityID] || saml_config[:issuer]
      parsed[:cert] ||= idp_metadata[:cert] || saml_config[:cert]
      parsed[:single_sign_on_service] = sso_saml_metadata_services_from_config(idp_metadata[:single_sign_on_service] || saml_config[:single_sign_on_service]) if parsed[:single_sign_on_service].to_a.empty?
      parsed[:single_logout_service] = sso_saml_metadata_services_from_config(idp_metadata[:single_logout_service] || saml_config[:single_logout_service]) if parsed[:single_logout_service].to_a.empty?
      parsed
    end

    def sso_parse_saml_metadata_xml(xml)
      doc = REXML::Document.new(xml.to_s)
      root = doc.root
      {
        entity_id: root&.attributes&.[]("entityID"),
        cert: sso_saml_normalize_certificate(sso_saml_metadata_first_text(doc, "X509Certificate")),
        single_sign_on_service: sso_saml_metadata_services(doc, "SingleSignOnService"),
        single_logout_service: sso_saml_metadata_services(doc, "SingleLogoutService")
      }.compact
    rescue
      {}
    end

    def sso_saml_metadata_services(doc, element_name)
      services = []
      REXML::XPath.each(doc, "//*") do |element|
        next unless element.name == element_name

        services << {
          binding: element.attributes["Binding"],
          location: element.attributes["Location"]
        }.compact
      end
      services
    end

    def sso_saml_metadata_first_text(doc, element_name)
      REXML::XPath.each(doc, "//*") do |element|
        return element.text.to_s.strip if element.name == element_name && !element.text.to_s.strip.empty?
      end
      nil
    end

    def sso_saml_metadata_services_from_config(value)
      Array(value).filter_map do |entry|
        data = normalize_hash(entry || {})
        next if data[:location].to_s.empty?

        {binding: data[:binding] || data[:Binding], location: data[:location] || data[:Location]}.compact
      end
    end

    def sso_saml_preferred_service(services)
      Array(services).find { |service| normalize_hash(service)[:binding].to_s.include?("HTTP-Redirect") } || Array(services).first
    end

    def sso_saml_normalize_certificate(value)
      cert = value.to_s.strip
      return nil if cert.empty?
      return cert if cert.include?("BEGIN CERTIFICATE")

      "-----BEGIN CERTIFICATE-----\n#{cert.scan(/.{1,64}/).join("\n")}\n-----END CERTIFICATE-----"
    end

    def sso_saml_callback_url(provider)
      saml_config = sso_provider_config_hash(provider["samlConfig"])
      saml_config[:callback_url]
    end

    def sso_saml_logout_destination(provider)
      saml_config = sso_provider_config_hash(provider["samlConfig"])
      direct = saml_config[:single_logout_service] ||
        saml_config[:single_logout_service_url] ||
        saml_config[:idp_slo_service_url] ||
        saml_config[:logout_url]
      return direct unless direct.to_s.empty?

      service = sso_saml_preferred_service(sso_saml_idp_metadata(saml_config)[:single_logout_service])
      normalize_hash(service || {})[:location]
    end

    def sso_store_saml_session(ctx, provider, assertion, session)
      name_id = assertion[:name_id] || assertion[:nameid] || assertion[:email]
      session_index = assertion[:session_index] || assertion[:sessionindex] || assertion[:id]
      return if name_id.to_s.empty? || session_index.to_s.empty?

      record = {
        providerId: provider.fetch("providerId"),
        sessionToken: session.fetch("token"),
        userId: session.fetch("userId"),
        nameId: name_id.to_s,
        sessionIndex: session_index.to_s
      }
      expires_at = session["expiresAt"] || Time.now + (SSO_DEFAULT_ASSERTION_TTL_MS / 1000.0)
      value = JSON.generate(record)
      session_identifier = "#{SSO_SAML_SESSION_KEY_PREFIX}#{provider.fetch("providerId")}:#{name_id}"
      ctx.context.internal_adapter.create_verification_value(
        identifier: session_identifier,
        value: value,
        expiresAt: expires_at
      )
      ctx.context.internal_adapter.create_verification_value(
        identifier: "#{SSO_SAML_SESSION_BY_ID_KEY_PREFIX}#{session.fetch("token")}",
        value: session_identifier,
        expiresAt: expires_at
      )
    end

    def sso_process_saml_logout_request(ctx, provider, raw_request)
      data = sso_parse_saml_logout_request(raw_request)
      return data if data[:name_id].to_s.empty?

      session_identifier = "#{SSO_SAML_SESSION_KEY_PREFIX}#{provider.fetch("providerId")}:#{data[:name_id]}"
      verification = ctx.context.internal_adapter.find_verification_value(session_identifier)
      return data unless verification

      record = JSON.parse(verification.fetch("value"))
      session_token = record["sessionToken"]
      session_index_matches = data[:session_index].to_s.empty? || record["sessionIndex"].to_s.empty? || data[:session_index].to_s == record["sessionIndex"].to_s
      ctx.context.internal_adapter.delete_session(session_token) if session_token && session_index_matches
      ctx.context.internal_adapter.delete_verification_by_identifier(session_identifier)
      ctx.context.internal_adapter.delete_verification_by_identifier("#{SSO_SAML_SESSION_BY_ID_KEY_PREFIX}#{session_token}") if session_token
      data
    rescue
      {}
    end

    def sso_store_saml_logout_request(ctx, provider, request_id, config)
      ttl_ms = (config.dig(:saml, :logout_request_ttl) || SSO_DEFAULT_LOGOUT_REQUEST_TTL_MS).to_i
      ctx.context.internal_adapter.create_verification_value(
        identifier: "#{SSO_SAML_LOGOUT_REQUEST_KEY_PREFIX}#{request_id}",
        value: provider.fetch("providerId"),
        expiresAt: Time.now + (ttl_ms / 1000.0)
      )
    end

    def sso_process_saml_logout_response(ctx, raw_response)
      data = sso_parse_saml_logout_response(raw_response)
      status_code = data[:status_code]
      if status_code && status_code != SSO_SAML_STATUS_SUCCESS
        raise APIError.new("BAD_REQUEST", message: "Logout failed at IdP")
      end

      in_response_to = data[:in_response_to]
      return if in_response_to.to_s.empty?

      ctx.context.internal_adapter.delete_verification_by_identifier("#{SSO_SAML_LOGOUT_REQUEST_KEY_PREFIX}#{in_response_to}")
    end

    def sso_parse_saml_logout_request(raw_request)
      xml = Base64.decode64(raw_request.to_s.gsub(/\s+/, ""))
      {
        id: xml[/\bID=['"]([^'"]+)['"]/, 1],
        name_id: xml[%r{<(?:\w+:)?NameID[^>]*>([^<]+)</(?:\w+:)?NameID>}, 1],
        session_index: xml[%r{<(?:\w+:)?SessionIndex[^>]*>([^<]+)</(?:\w+:)?SessionIndex>}, 1]
      }
    rescue
      {}
    end

    def sso_validate_saml_slo_signature!(ctx, raw_message, error_message)
      signature = sso_fetch(ctx.body, :signature) || sso_fetch(ctx.query, :signature)
      sig_alg = sso_fetch(ctx.body, :sig_alg) || sso_fetch(ctx.query, :sig_alg)
      if !signature.to_s.empty? && !sig_alg.to_s.empty?
        return true if sso_validate_saml_redirect_signature(ctx, raw_message, signature, sig_alg)

        raise APIError.new("BAD_REQUEST", message: error_message)
      end

      xml = Base64.decode64(raw_message.to_s.gsub(/\s+/, ""))
      return true if xml.include?("<Signature") || xml.include?(":Signature")

      raise APIError.new("BAD_REQUEST", message: error_message)
    rescue APIError
      raise
    rescue
      raise APIError.new("BAD_REQUEST", message: error_message)
    end

    def sso_validate_saml_redirect_signature(ctx, raw_message, signature, sig_alg)
      provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
      cert = sso_saml_idp_metadata(provider)[:cert]
      certificate = OpenSSL::X509::Certificate.new(cert.to_s)
      has_saml_request = sso_fetch(ctx.body, :saml_request) || sso_fetch(ctx.query, :saml_request)
      saml_param = has_saml_request ? "SAMLRequest" : "SAMLResponse"
      relay_state = sso_fetch(ctx.body, :relay_state) || sso_fetch(ctx.query, :relay_state)
      payload = [[saml_param, raw_message]]
      payload << ["RelayState", relay_state] unless relay_state.to_s.empty?
      payload << ["SigAlg", sig_alg]
      certificate.public_key.verify(sso_saml_signature_digest(sig_alg), Base64.decode64(signature.to_s), URI.encode_www_form(payload))
    rescue
      false
    end

    def sso_parse_saml_logout_response(raw_response)
      xml = Base64.decode64(raw_response.to_s.gsub(/\s+/, ""))
      {
        in_response_to: xml[/\bInResponseTo=['"]([^'"]+)['"]/, 1],
        status_code: xml[/<(?:\w+:)?StatusCode\b[^>]*\bValue=['"]([^'"]+)['"]/, 1]
      }
    rescue
      {}
    end

    def sso_safe_slo_redirect_url(ctx, url, provider_id)
      app_origin = ctx.context.base_url
      callback_path = URI.parse("#{ctx.context.base_url}/sso/saml2/sp/slo/#{URI.encode_www_form_component(provider_id)}").path
      value = url.to_s
      return app_origin if value.empty?

      if value.start_with?("/") && !value.start_with?("//")
        parsed = URI.parse(value)
        return app_origin if parsed.path == callback_path
        return value
      end

      return app_origin unless ctx.context.trusted_origin?(value, allow_relative_paths: false)

      parsed = URI.parse(value)
      return app_origin if parsed.path == callback_path

      value
    rescue
      app_origin
    end

    def sso_safe_saml_callback_url(ctx, url, provider_id)
      app_origin = ctx.context.base_url
      callback_path = URI.parse("#{ctx.context.base_url}/sso/saml2/callback/#{URI.encode_www_form_component(provider_id)}").path
      acs_path = URI.parse("#{ctx.context.base_url}/sso/saml2/sp/acs/#{URI.encode_www_form_component(provider_id)}").path
      value = url.to_s
      return app_origin if value.empty?

      if value.start_with?("/") && !value.start_with?("//")
        parsed = URI.parse(value)
        return app_origin if [callback_path, acs_path].include?(parsed.path)
        return value
      end

      return app_origin unless ctx.context.trusted_origin?(value, allow_relative_paths: false)

      parsed = URI.parse(value)
      return app_origin if [callback_path, acs_path].include?(parsed.path)

      value
    rescue
      app_origin
    end

    def sso_signed_saml_redirect_query(provider, query)
      saml_config = sso_provider_config_hash(provider["samlConfig"])
      private_key = saml_config.dig(:sp_metadata, :private_key) || saml_config[:private_key] || saml_config[:sp_private_key]
      raise APIError.new("BAD_REQUEST", message: "SAML Redirect signing requires privateKey") if private_key.to_s.empty?

      sig_alg = saml_config[:signature_algorithm] ? sso_normalize_saml_signature_algorithm(saml_config[:signature_algorithm]) : XMLSecurity::Document::RSA_SHA256
      signed = query.compact.merge(SigAlg: sig_alg)
      signed_payload = signed.keys.map(&:to_s).select { |key| %w[SAMLRequest SAMLResponse RelayState SigAlg].include?(key) }.map { |key| [key, signed[key.to_sym] || signed[key]] }.reject { |_key, value| value.nil? }
      signature_input = URI.encode_www_form(signed_payload)
      signed[:Signature] = Base64.strict_encode64(OpenSSL::PKey.read(private_key).sign(sso_saml_signature_digest(sig_alg), signature_input))
      signed
    end

    def sso_saml_signature_digest(signature_algorithm)
      case signature_algorithm.to_s
      when /sha512/i
        OpenSSL::Digest.new("SHA512")
      when /sha384/i
        OpenSSL::Digest.new("SHA384")
      when /sha1/i
        OpenSSL::Digest.new("SHA1")
      else
        OpenSSL::Digest.new("SHA256")
      end
    end

    def sso_saml_post_form(action, saml_param, saml_value, relay_state = nil)
      relay_input = relay_state.to_s.empty? ? "" : "<input type=\"hidden\" name=\"RelayState\" value=\"#{CGI.escapeHTML(relay_state.to_s)}\" />"
      html = "<!DOCTYPE html><html><body onload=\"document.forms[0].submit();\"><form method=\"POST\" action=\"#{CGI.escapeHTML(action.to_s)}\"><input type=\"hidden\" name=\"#{CGI.escapeHTML(saml_param.to_s)}\" value=\"#{CGI.escapeHTML(saml_value.to_s)}\" />#{relay_input}<noscript><input type=\"submit\" value=\"Continue\" /></noscript></form></body></html>"
      [200, {"content-type" => "text/html"}, [html]]
    end
  end
end

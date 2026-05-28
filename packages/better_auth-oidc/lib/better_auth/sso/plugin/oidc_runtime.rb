# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def sso_verify_state(value, secret)
      BetterAuth::Crypto.verify_jwt(value.to_s, secret)
    rescue
      nil
    end

    def sso_oidc_authorization_url(provider, ctx, state, plugin_config = {}, body = {})
      config = sso_provider_config_hash(provider["oidcConfig"])
      endpoint = config[:authorization_endpoint] || config[:authorization_url]
      raise APIError.new("BAD_REQUEST", message: "Invalid OIDC configuration. Authorization URL not found.") if endpoint.to_s.empty?

      scopes = Array(body[:scopes] || config[:scopes] || config[:scope] || ["openid", "email", "profile", "offline_access"])
      query = {
        client_id: config[:client_id],
        response_type: "code",
        redirect_uri: sso_oidc_redirect_uri(ctx.context, provider.fetch("providerId")),
        scope: scopes.join(" "),
        state: state
      }.compact
      decoded_state = sso_decode_state(state, ctx.context.secret)
      nonce = decoded_state&.fetch("nonce", nil)
      query[:nonce] = nonce if nonce && !nonce.to_s.empty?
      login_hint = body[:login_hint] || body[:email]
      query[:login_hint] = login_hint if login_hint
      code_challenge = decoded_state&.fetch("codeChallenge", nil)
      if code_challenge
        query[:code_challenge] = code_challenge
        query[:code_challenge_method] = "S256"
      end
      "#{endpoint}?#{URI.encode_www_form(query)}"
    end

    def sso_saml_authorization_url(provider, relay_state, ctx = nil, config = {})
      auth_request_url = config.dig(:saml, :auth_request_url)
      if auth_request_url.respond_to?(:call)
        return auth_request_url.call(provider: provider, relay_state: relay_state, context: ctx)
      end

      config = sso_provider_config_hash(provider["samlConfig"])
      metadata = sso_saml_idp_metadata(config)
      entry_point = config[:entry_point] || normalize_hash(sso_saml_preferred_service(metadata[:single_sign_on_service]) || {})[:location]
      query = {
        SAMLRequest: Base64.strict_encode64(JSON.generate({providerId: provider.fetch("providerId")})),
        RelayState: relay_state
      }
      "#{entry_point}?#{URI.encode_www_form(query)}"
    end

    def sso_store_saml_authn_request(ctx, provider, url, config)
      return if config.dig(:saml, :enable_in_response_to_validation) == false

      request_id = sso_extract_saml_request_id(url)
      return if request_id.to_s.empty?

      ttl_ms = (config.dig(:saml, :request_ttl) || SSO_DEFAULT_AUTHN_REQUEST_TTL_MS).to_i
      now_ms = (Time.now.to_f * 1000).to_i
      expires_at_ms = now_ms + ttl_ms
      record = {
        id: request_id,
        providerId: provider.fetch("providerId"),
        createdAt: now_ms,
        expiresAt: expires_at_ms
      }
      ctx.context.internal_adapter.create_verification_value(
        identifier: "#{SSO_SAML_AUTHN_REQUEST_KEY_PREFIX}#{request_id}",
        value: JSON.generate(record),
        expiresAt: Time.at(expires_at_ms / 1000.0)
      )
    end

    def sso_extract_saml_request_id(url)
      query = URI.decode_www_form(URI.parse(url.to_s).query.to_s).to_h
      encoded = query["SAMLRequest"]
      return nil if encoded.to_s.empty?

      xml = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(Base64.decode64(encoded))
      xml[/\bID=['"]([^'"]+)['"]/, 1]
    rescue
      nil
    end

    def sso_validate_saml_in_response_to(ctx, config, provider, raw_response, state)
      return nil if config.dig(:saml, :enable_in_response_to_validation) == false

      in_response_to = sso_extract_saml_in_response_to(raw_response)
      if in_response_to && !in_response_to.empty?
        identifier = "#{SSO_SAML_AUTHN_REQUEST_KEY_PREFIX}#{in_response_to}"
        verification = ctx.context.internal_adapter.find_verification_value(identifier)
        record = sso_parse_saml_authn_request_record(verification&.fetch("value", nil))
        if !record || record["expiresAt"].to_i < (Time.now.to_f * 1000).to_i
          return sso_redirect(ctx, sso_append_error(state["callbackURL"] || "/", "invalid_saml_response", "Unknown or expired request ID"))
        end

        if record["providerId"] != provider.fetch("providerId")
          ctx.context.internal_adapter.delete_verification_by_identifier(identifier)
          return sso_redirect(ctx, sso_append_error(state["callbackURL"] || "/", "invalid_saml_response", "Provider mismatch"))
        end

        return {identifier: identifier}
      elsif config.dig(:saml, :allow_idp_initiated) == false
        return sso_redirect(ctx, sso_append_error(state["callbackURL"] || "/", "unsolicited_response", "IdP-initiated SSO not allowed"))
      end

      nil
    end

    def sso_consume_saml_in_response_to(ctx, result)
      identifier = result.is_a?(Hash) ? result[:identifier] : nil
      ctx.context.internal_adapter.delete_verification_by_identifier(identifier) unless identifier.to_s.empty?
    end

    def sso_parse_saml_authn_request_record(value)
      JSON.parse(value.to_s)
    rescue
      nil
    end

    def sso_saml_assertion_replay_expires_at(assertion, config = {})
      timestamp = sso_saml_timestamp_conditions(assertion)[:not_on_or_after]
      parsed = Time.parse(timestamp.to_s) if timestamp
      clock_skew_seconds = ((config.dig(:saml, :clock_skew) || SSO_DEFAULT_CLOCK_SKEW_MS).to_f / 1000.0)
      return parsed + clock_skew_seconds if parsed && parsed + clock_skew_seconds > Time.now

      ttl_ms = (config.dig(:saml, :assertion_ttl) || SSO_DEFAULT_ASSERTION_TTL_MS).to_i
      Time.now + (ttl_ms / 1000.0)
    rescue
      Time.now + (SSO_DEFAULT_ASSERTION_TTL_MS / 1000.0)
    end

    def sso_extract_saml_in_response_to(raw_response)
      xml = Base64.decode64(raw_response.to_s.gsub(/\s+/, ""))
      xml[/\bInResponseTo=['"]([^'"]+)['"]/, 1]
    rescue
      nil
    end

    def sso_select_provider(ctx, body, config = {})
      provider_id = body[:provider_id].to_s
      issuer = body[:issuer].to_s
      organization_slug = body[:organization_slug].to_s
      domain = (body[:domain] || body[:email].to_s.split("@").last).to_s.downcase
      if config[:default_sso]
        provider = sso_default_provider(config, provider_id: provider_id, domain: domain)
        return provider if provider
      end

      providers = ctx.context.adapter.find_many(model: "ssoProvider")
      provider = if !provider_id.empty?
        providers.find { |entry| entry["providerId"] == provider_id }
      elsif !issuer.empty?
        providers.find { |entry| entry["issuer"] == issuer }
      elsif !organization_slug.empty?
        organization = ctx.context.adapter.find_one(model: "organization", where: [{field: "slug", value: organization_slug}])
        providers.find { |entry| entry["organizationId"] == organization&.fetch("id", nil) }
      elsif !domain.empty?
        providers.find { |entry| entry["domain"].to_s.downcase == domain } ||
          providers.find { |entry| sso_email_domain_matches?(domain, entry["domain"]) }
      end
      raise APIError.new("NOT_FOUND", message: SSO_ERROR_CODES.fetch("PROVIDER_NOT_FOUND")) unless provider

      provider
    end

    def sso_callback_provider(ctx, config, provider_id)
      if config[:default_sso]
        provider = sso_default_provider(config, provider_id: provider_id.to_s, domain: "")
        return provider if provider
      end

      ctx.context.adapter.find_one(model: "ssoProvider", where: [{field: "providerId", value: provider_id.to_s}])
    end

    def sso_oidc_tokens(ctx, provider, oidc_config, state, plugin_config, raw_state: nil)
      code_verifier = sso_oidc_code_verifier(ctx, raw_state || state["state"] || state[:state])
      token_callback = oidc_config[:get_token]
      if token_callback.respond_to?(:call)
        return normalize_hash(token_callback.call(
          code: ctx.query[:code] || ctx.query["code"],
          codeVerifier: code_verifier,
          redirectURI: sso_oidc_redirect_uri(ctx.context, provider.fetch("providerId")),
          provider: provider,
          context: ctx
        ))
      end

      token_endpoint = oidc_config[:token_endpoint]
      return nil if token_endpoint.to_s.empty?

      sso_exchange_oidc_code(
        token_endpoint: token_endpoint,
        code: ctx.query[:code] || ctx.query["code"],
        code_verifier: code_verifier,
        redirect_uri: sso_oidc_redirect_uri(ctx.context, provider.fetch("providerId")),
        client_id: oidc_config[:client_id],
        client_secret: oidc_config[:client_secret],
        authentication: oidc_config[:token_endpoint_authentication],
        timeout: plugin_config[:oidc_http_timeout],
        max_body_size: plugin_config[:oidc_http_max_body_size]
      )
    rescue
      nil
    end

    def sso_exchange_oidc_code(token_endpoint:, code:, code_verifier:, redirect_uri:, client_id:, client_secret:, authentication:, timeout: nil, max_body_size: nil)
      uri = URI(token_endpoint.to_s)
      request = Net::HTTP::Post.new(uri)
      form = {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirect_uri,
        client_id: client_id,
        code_verifier: code_verifier
      }.compact
      if authentication.to_s == "client_secret_post"
        form[:client_secret] = client_secret
      elsif client_secret.to_s != ""
        request.basic_auth(client_id.to_s, client_secret.to_s)
      end
      request.set_form_data(form)
      response = Net::HTTP.start(
        uri.hostname,
        uri.port,
        use_ssl: uri.scheme == "https",
        open_timeout: sso_oidc_http_timeout(timeout),
        read_timeout: sso_oidc_http_timeout(timeout)
      ) { |http| http.request(request) }
      return nil unless response.is_a?(Net::HTTPSuccess)
      return nil if response.body.to_s.bytesize > sso_oidc_http_max_body_size(max_body_size)

      normalize_hash(JSON.parse(response.body))
    end

    def sso_oidc_user_info(ctx, oidc_config, tokens, plugin_config, expected_nonce: nil)
      user_callback = oidc_config[:get_user_info]
      raw = if user_callback.respond_to?(:call)
        user_callback.call(tokens)
      elsif oidc_config[:user_info_endpoint]
        sso_fetch_oidc_user_info(oidc_config[:user_info_endpoint], tokens[:access_token], timeout: plugin_config[:oidc_http_timeout], max_body_size: plugin_config[:oidc_http_max_body_size])
      elsif tokens[:id_token]
        return {_sso_error: "jwks_endpoint_not_found"} if oidc_config[:jwks_endpoint].to_s.empty?

        sso_validate_oidc_id_token(
          tokens[:id_token],
          jwks_endpoint: oidc_config[:jwks_endpoint],
          audience: oidc_config[:client_id],
          issuer: oidc_config[:issuer],
          fetch: plugin_config[:oidc_jwks_fetch],
          expected_nonce: expected_nonce
        ) || {_sso_error: "token_not_verified"}
      else
        {}
      end
      raw = normalize_hash(raw || {})
      return raw if raw[:_sso_error]

      mapping = normalize_hash(oidc_config[:mapping] || {})
      extra_fields = normalize_hash(mapping[:extra_fields] || {}).each_with_object({}) do |(target, source), result|
        result[target] = raw[normalize_key(source)] || raw[source.to_s]
      end
      extra_fields.merge(
        id: raw[normalize_key(mapping[:id] || "sub")] || raw[:id],
        email: raw[normalize_key(mapping[:email] || "email")],
        email_verified: plugin_config[:trust_email_verified] ? raw[normalize_key(mapping[:email_verified] || "email_verified")] : false,
        name: raw[normalize_key(mapping[:name] || "name")],
        image: raw[normalize_key(mapping[:image] || "picture")]
      )
    end

    def sso_fetch_oidc_user_info(endpoint, access_token, timeout: nil, max_body_size: nil)
      uri = URI(endpoint.to_s)
      request = Net::HTTP::Get.new(uri)
      request["authorization"] = "Bearer #{access_token}"
      response = Net::HTTP.start(
        uri.hostname,
        uri.port,
        use_ssl: uri.scheme == "https",
        open_timeout: sso_oidc_http_timeout(timeout),
        read_timeout: sso_oidc_http_timeout(timeout)
      ) { |http| http.request(request) }
      return {} unless response.is_a?(Net::HTTPSuccess)
      return {} if response.body.to_s.bytesize > sso_oidc_http_max_body_size(max_body_size)

      JSON.parse(response.body)
    rescue
      {}
    end

    def sso_validate_oidc_id_token(token, jwks_endpoint:, audience:, issuer:, fetch: nil, expected_nonce: nil)
      jwks = sso_fetch_oidc_jwks(jwks_endpoint, fetch: fetch)
      payload, = ::JWT.decode(
        token.to_s,
        nil,
        true,
        algorithms: %w[RS256 RS384 RS512 ES256 ES384 ES512],
        jwks: jwks,
        aud: audience,
        verify_aud: true,
        iss: issuer,
        verify_iss: true
      )
      if expected_nonce && !expected_nonce.to_s.empty?
        token_nonce = payload["nonce"] || payload[:nonce]
        return nil if token_nonce.to_s.empty?
        return nil unless BetterAuth::Crypto.constant_time_compare(token_nonce.to_s, expected_nonce.to_s)
      end
      payload
    rescue
      nil
    end

    def sso_fetch_oidc_jwks(jwks_endpoint, fetch: nil)
      if fetch.respond_to?(:call)
        return normalize_hash(fetch.call(jwks_endpoint))
      end

      uri = URI(jwks_endpoint.to_s)
      response = Net::HTTP.start(
        uri.hostname,
        uri.port,
        use_ssl: uri.scheme == "https",
        open_timeout: SSO_DEFAULT_OIDC_HTTP_TIMEOUT,
        read_timeout: SSO_DEFAULT_OIDC_HTTP_TIMEOUT
      ) { |http| http.get(uri.request_uri) }
      return {} unless response.is_a?(Net::HTTPSuccess)
      return {} if response.body.to_s.bytesize > SSO_DEFAULT_OIDC_HTTP_MAX_BODY_SIZE

      normalize_hash(JSON.parse(response.body))
    rescue
      {}
    end

    def sso_decode_jwt_payload(token)
      payload = token.to_s.split(".")[1]
      return {} unless payload

      JSON.parse(Base64.urlsafe_decode64(payload.ljust((payload.length + 3) & ~3, "=")))
    rescue
      {}
    end

    def sso_append_error(url, error, description = nil)
      separator = url.to_s.include?("?") ? "&" : "?"
      query = {error: error, error_description: description}.compact
      "#{url}#{separator}#{URI.encode_www_form(query)}"
    end

    def sso_default_provider(config, provider_id:, domain:)
      Array(config[:default_sso]).each do |raw_provider|
        default_provider = normalize_hash(raw_provider)
        next if !provider_id.empty? && default_provider[:provider_id].to_s != provider_id
        next if provider_id.empty? && default_provider[:domain].to_s.downcase != domain

        oidc_config = default_provider[:oidc_config] ? sso_storage_config(default_provider[:oidc_config]) : nil
        saml_config = default_provider[:saml_config] ? sso_storage_config(default_provider[:saml_config]) : nil
        return {
          "issuer" => default_provider[:issuer] || default_provider.dig(:oidc_config, :issuer) || default_provider.dig(:saml_config, :issuer) || "",
          "providerId" => default_provider.fetch(:provider_id),
          "userId" => "default",
          "domain" => default_provider[:domain],
          "domainVerified" => true,
          "oidcConfig" => oidc_config,
          "samlConfig" => saml_config
        }.compact
      end
      nil
    end

    def sso_oidc_pkce_state(provider)
      return {} unless sso_provider_config_hash(provider["oidcConfig"])[:pkce]

      verifier = BetterAuth::Crypto.random_string(128)
      {
        codeVerifier: verifier,
        codeChallenge: sso_base64_urlsafe(OpenSSL::Digest::SHA256.digest(verifier))
      }
    end

    def sso_store_oidc_pkce_verifier(ctx, state, verifier)
      ctx.context.internal_adapter.create_verification_value(
        identifier: "#{SSO_OIDC_PKCE_VERIFIER_KEY_PREFIX}#{state}",
        value: verifier,
        expiresAt: Time.now + 600
      )
    end

    def sso_oidc_code_verifier(ctx, state)
      return nil if state.to_s.empty?

      identifier = "#{SSO_OIDC_PKCE_VERIFIER_KEY_PREFIX}#{state}"
      verification = ctx.context.internal_adapter.find_verification_value(identifier)
      ctx.context.internal_adapter.delete_verification_by_identifier(identifier) if verification
      verification&.fetch("value", nil)
    end

    def sso_oidc_http_timeout(value)
      timeout = value || SSO_DEFAULT_OIDC_HTTP_TIMEOUT
      timeout.to_f.positive? ? timeout.to_f : SSO_DEFAULT_OIDC_HTTP_TIMEOUT
    end

    def sso_oidc_http_max_body_size(value)
      size = value || SSO_DEFAULT_OIDC_HTTP_MAX_BODY_SIZE
      size.to_i.positive? ? size.to_i : SSO_DEFAULT_OIDC_HTTP_MAX_BODY_SIZE
    end

    def sso_decode_state(state, secret)
      BetterAuth::Crypto.verify_jwt(state.to_s, secret)
    rescue
      nil
    end

    def sso_base64_urlsafe(value)
      Base64.strict_encode64(value).tr("+/", "-_").delete("=")
    end

    def sso_storage_config(config)
      normalize_hash(config || {}).each_with_object({}) do |(key, value), result|
        result[Schema.storage_key(key)] = value unless value.respond_to?(:call)
      end
    end

    def sso_provider_limit(user, config)
      limit = config[:providers_limit]
      limit = 10 if limit.nil?
      limit.respond_to?(:call) ? limit.call(user) : limit
    end

    def sso_validate_url!(value, message)
      uri = URI(value.to_s)
      unless uri.is_a?(URI::HTTP) && !uri.host.to_s.empty?
        raise APIError.new("BAD_REQUEST", message: message)
      end
    rescue URI::InvalidURIError
      raise APIError.new("BAD_REQUEST", message: message)
    end

    def sso_validate_organization_membership!(ctx, user_id, organization_id)
      member = ctx.context.adapter.find_one(
        model: "member",
        where: [{field: "userId", value: user_id}, {field: "organizationId", value: organization_id}]
      )
      raise APIError.new("BAD_REQUEST", message: "You are not a member of the organization") unless member
    end

    def sso_hydrate_oidc_config(issuer, oidc_config, ctx)
      existing = oidc_config.merge(issuer: issuer)
      discovered = sso_discover_oidc_config(
        issuer: issuer,
        existing_config: existing,
        fetch: ctx.context.options.plugins.find { |plugin| plugin.id == "sso" }&.options&.fetch(:oidc_discovery_fetch, nil),
        trusted_origin: ->(url) { ctx.context.trusted_origin?(url, allow_relative_paths: false) },
        timeout: ctx.context.options.plugins.find { |plugin| plugin.id == "sso" }&.options&.fetch(:oidc_http_timeout, nil)
      )
      existing.merge(discovered)
    end

    def sso_oidc_needs_runtime_discovery?(oidc_config)
      config = normalize_hash(oidc_config || {})
      config[:authorization_endpoint].to_s.empty? ||
        config[:token_endpoint].to_s.empty?
    end

    def sso_ensure_runtime_oidc_provider(ctx, provider, plugin_config, require_jwks: false)
      oidc_config = sso_provider_config_hash(provider["oidcConfig"])
      needs_discovery = sso_oidc_needs_runtime_discovery?(oidc_config) || (require_jwks && oidc_config[:jwks_endpoint].to_s.empty?)
      return provider if !needs_discovery

      discovered = sso_discover_oidc_config(
        issuer: provider.fetch("issuer"),
        existing_config: oidc_config.merge(issuer: provider.fetch("issuer")),
        fetch: plugin_config[:oidc_discovery_fetch],
        trusted_origin: ->(url) { ctx.context.trusted_origin?(url, allow_relative_paths: false) },
        timeout: plugin_config[:oidc_http_timeout]
      )
      provider.merge("oidcConfig" => oidc_config.merge(discovered))
    end

    def sso_validate_oidc_endpoint_origins!(ctx, oidc_config)
      return unless sso_oidc_trusted_origin_enforced?(ctx)

      config = normalize_hash(oidc_config || {})
      %i[authorization_endpoint token_endpoint jwks_endpoint user_info_endpoint discovery_endpoint].each do |field|
        url = config[field]
        next if url.to_s.empty?

        sso_validate_url!(url, "OIDC #{Schema.storage_key(field)} must be a valid URL")
        next if ctx.context.trusted_origin?(url.to_s, allow_relative_paths: false)

        raise APIError.new("BAD_REQUEST", message: "OIDC #{Schema.storage_key(field)} is not trusted")
      end
    end

    def sso_oidc_trusted_origin_enforced?(ctx)
      Array(ctx.context.trusted_origins).map(&:to_s).uniq.length > 1
    end
  end
end

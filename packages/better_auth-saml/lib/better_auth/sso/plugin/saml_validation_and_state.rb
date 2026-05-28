# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def sso_parse_saml_response(value, config = {}, provider = nil, ctx = nil)
      parser = config.dig(:saml, :parse_response)
      if parser.respond_to?(:call)
        sso_validate_single_saml_assertion!(value) if sso_base64_xml?(value)
        parsed = parser.call(raw_response: value.to_s, provider: provider, context: ctx)
        return normalize_hash(parsed)
      end

      JSON.parse(Base64.decode64(value.to_s), symbolize_names: true)
    rescue APIError
      raise APIError.new("BAD_REQUEST", message: "Invalid SAML response")
    rescue
      raise APIError.new("BAD_REQUEST", message: "Invalid SAML response")
    end

    def sso_validate_single_saml_assertion!(saml_response)
      xml = Base64.decode64(saml_response.to_s)
      raise APIError.new("BAD_REQUEST", message: "Invalid base64-encoded SAML response") unless xml.include?("<")

      assertions = xml.scan(/<(?:\w+:)?Assertion(?:\s|>|\/)/).length
      encrypted_assertions = xml.scan(/<(?:\w+:)?EncryptedAssertion(?:\s|>|\/)/).length
      total = assertions + encrypted_assertions
      raise APIError.new("BAD_REQUEST", message: "SAML response contains no assertions") if total.zero?
      if total > 1
        raise APIError.new("BAD_REQUEST", message: "SAML response contains #{total} assertions, expected exactly 1")
      end

      true
    rescue APIError
      raise
    rescue
      raise APIError.new("BAD_REQUEST", message: "Invalid base64-encoded SAML response")
    end

    def sso_validate_saml_timestamp!(conditions, config = {}, now: Time.now.utc)
      conditions = normalize_hash(conditions || {})
      not_before = conditions[:not_before] || conditions[:notBefore]
      not_on_or_after = conditions[:not_on_or_after] || conditions[:notOnOrAfter]
      if not_before.to_s.empty? && not_on_or_after.to_s.empty?
        raise APIError.new("BAD_REQUEST", message: "SAML assertion missing required timestamp conditions") if config.dig(:saml, :require_timestamps)

        return true
      end

      clock_skew_seconds = ((config.dig(:saml, :clock_skew) || SSO_DEFAULT_CLOCK_SKEW_MS).to_f / 1000.0)
      parsed_not_before = sso_parse_saml_timestamp(not_before, "SAML assertion has invalid NotBefore timestamp") unless not_before.to_s.empty?
      parsed_not_on_or_after = sso_parse_saml_timestamp(not_on_or_after, "SAML assertion has invalid NotOnOrAfter timestamp") unless not_on_or_after.to_s.empty?

      raise APIError.new("BAD_REQUEST", message: "SAML assertion is not yet valid") if parsed_not_before && now < (parsed_not_before - clock_skew_seconds)
      raise APIError.new("BAD_REQUEST", message: "SAML assertion has expired") if parsed_not_on_or_after && now > (parsed_not_on_or_after + clock_skew_seconds)

      true
    end

    def sso_parse_saml_timestamp(value, error_message)
      Time.parse(value.to_s).utc
    rescue
      raise APIError.new("BAD_REQUEST", message: error_message)
    end

    def sso_saml_timestamp_conditions(assertion)
      assertion = normalize_hash(assertion || {})
      conditions = normalize_hash(assertion[:conditions] || {})
      conditions[:not_before] ||= assertion[:not_before] || assertion[:notBefore]
      conditions[:not_on_or_after] ||= assertion[:not_on_or_after] || assertion[:notOnOrAfter]
      conditions
    end

    def sso_base64_xml?(value)
      Base64.decode64(value.to_s).lstrip.start_with?("<")
    rescue
      false
    end

    def sso_validate_saml_algorithms!(xml, options = {})
      on_deprecated = (options[:on_deprecated] || "warn").to_s
      signature_algorithms = xml.to_s.scan(/SignatureMethod[^>]+Algorithm=["']([^"']+)["']/).flatten.map { |algorithm| sso_normalize_saml_signature_algorithm(algorithm) }
      digest_algorithms = xml.to_s.scan(/DigestMethod[^>]+Algorithm=["']([^"']+)["']/).flatten.map { |algorithm| sso_normalize_saml_digest_algorithm(algorithm) }
      key_encryption_algorithms = xml.to_s.scan(/<[^\/>]*EncryptedKey\b[\s\S]*?EncryptionMethod[^>]+Algorithm=["']([^"']+)["']/).flatten
      data_encryption_algorithms = xml.to_s.scan(/<[^\/>]*EncryptedData\b[\s\S]*?EncryptionMethod[^>]+Algorithm=["']([^"']+)["']/).flatten

      sso_validate_saml_algorithm_group!(
        signature_algorithms,
        allowed: options[:allowed_signature_algorithms]&.map { |algorithm| sso_normalize_saml_signature_algorithm(algorithm) },
        secure: SSO_SAML_SECURE_SIGNATURE_ALGORITHMS,
        deprecated: ["http://www.w3.org/2000/09/xmldsig#rsa-sha1"],
        on_deprecated: on_deprecated,
        label: "signature"
      )
      sso_validate_saml_algorithm_group!(
        digest_algorithms,
        allowed: options[:allowed_digest_algorithms]&.map { |algorithm| sso_normalize_saml_digest_algorithm(algorithm) },
        secure: SSO_SAML_SECURE_DIGEST_ALGORITHMS,
        deprecated: ["http://www.w3.org/2000/09/xmldsig#sha1"],
        on_deprecated: on_deprecated,
        label: "digest"
      )
      sso_validate_saml_algorithm_group!(
        key_encryption_algorithms,
        allowed: options[:allowed_key_encryption_algorithms],
        secure: SSO_SAML_SECURE_KEY_ENCRYPTION_ALGORITHMS,
        deprecated: ["http://www.w3.org/2001/04/xmlenc#rsa-1_5"],
        on_deprecated: on_deprecated,
        label: "key encryption"
      )
      sso_validate_saml_algorithm_group!(
        data_encryption_algorithms,
        allowed: options[:allowed_data_encryption_algorithms],
        secure: SSO_SAML_SECURE_DATA_ENCRYPTION_ALGORITHMS,
        deprecated: ["http://www.w3.org/2001/04/xmlenc#tripledes-cbc"],
        on_deprecated: on_deprecated,
        label: "data encryption"
      )

      true
    end

    def sso_normalize_saml_signature_algorithm(algorithm)
      SSO_SAML_SIGNATURE_ALGORITHMS.fetch(algorithm.to_s.downcase, algorithm.to_s)
    end

    def sso_normalize_saml_digest_algorithm(algorithm)
      SSO_SAML_DIGEST_ALGORITHMS.fetch(algorithm.to_s.downcase, algorithm.to_s)
    end

    def sso_validate_saml_algorithm_group!(algorithms, allowed:, secure:, deprecated:, on_deprecated:, label:)
      algorithms.each do |algorithm|
        if allowed
          next if allowed.include?(algorithm)

          raise APIError.new("BAD_REQUEST", message: "SAML #{label} algorithm not in allow-list: #{algorithm}")
        end

        if deprecated.include?(algorithm)
          raise APIError.new("BAD_REQUEST", message: "SAML response uses deprecated #{label} algorithm: #{algorithm}") if on_deprecated == "reject"
          next
        end
        next if secure.include?(algorithm)

        raise APIError.new("BAD_REQUEST", message: "SAML #{label} algorithm not recognized: #{algorithm}")
      end
    end

    def sso_generate_saml_relay_state(ctx, state_data)
      ttl_ms = 10 * 60 * 1000
      relay_state = BetterAuth::Crypto.random_string(32)
      now_ms = (Time.now.to_f * 1000).to_i
      stored = state_data.each_with_object({}) { |(key, value), result| result[key.to_s] = value }.merge(
        "codeVerifier" => BetterAuth::Crypto.random_string(128),
        "expiresAt" => now_ms + ttl_ms
      )
      ctx.context.internal_adapter.create_verification_value(
        identifier: "#{SSO_SAML_RELAY_STATE_KEY_PREFIX}#{relay_state}",
        value: JSON.generate(stored),
        expiresAt: Time.at((now_ms + ttl_ms) / 1000.0)
      )
      ctx.set_signed_cookie("relay_state", relay_state, ctx.context.secret, path: "/", max_age: ttl_ms / 1000, http_only: true, same_site: "lax")
      relay_state
    end

    def sso_parse_saml_relay_state(ctx, relay_state)
      state = sso_verify_state(relay_state, ctx.context.secret)
      return state if state

      verification = ctx.context.internal_adapter.find_verification_value("#{SSO_SAML_RELAY_STATE_KEY_PREFIX}#{relay_state}")
      return nil unless verification
      return nil unless sso_future_time?(verification.fetch("expiresAt"))

      parsed = JSON.parse(verification.fetch("value"))
      return nil if parsed["expiresAt"].to_i <= (Time.now.to_f * 1000).to_i

      parsed
    rescue
      nil
    end
  end
end

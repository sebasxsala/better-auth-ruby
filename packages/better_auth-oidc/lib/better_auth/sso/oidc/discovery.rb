# frozen_string_literal: true

require "uri"
require "json"
require "net/http"

module BetterAuth
  module SSO
    module OIDC
      module Discovery
        module_function

        REQUIRED_DISCOVERY_FIELDS = %i[issuer authorization_endpoint token_endpoint jwks_uri].freeze
        DISCOVERY_URL_FIELDS = %i[
          token_endpoint
          authorization_endpoint
          jwks_uri
          userinfo_endpoint
          revocation_endpoint
          end_session_endpoint
          introspection_endpoint
        ].freeze

        def compute_discovery_url(issuer)
          "#{issuer.to_s.sub(%r{/+\z}, "")}/.well-known/openid-configuration"
        end

        def validate_discovery_url(url, trusted_origin = nil)
          uri = parse_http_url!(url, "discoveryEndpoint", details: {url: url})
          return true unless trusted_origin && !trusted_origin.call(uri.to_s)

          raise DiscoveryError.new(
            "discovery_untrusted_origin",
            "The main discovery endpoint \"#{uri}\" is not trusted by your trusted origins configuration.",
            details: {url: uri.to_s}
          )
        end

        def validate_discovery_document(document, issuer)
          doc = BetterAuth::Plugins.normalize_hash(document || {})
          missing = REQUIRED_DISCOVERY_FIELDS.select { |field| doc[field].to_s.empty? }
          unless missing.empty?
            raise DiscoveryError.new(
              "discovery_incomplete",
              "OIDC discovery document is missing required fields: #{missing.join(", ")}",
              details: {missingFields: missing.map(&:to_s)}
            )
          end

          discovered = doc[:issuer].to_s.sub(%r{/+\z}, "")
          configured = issuer.to_s.sub(%r{/+\z}, "")
          return true if discovered == configured

          raise DiscoveryError.new(
            "issuer_mismatch",
            "OIDC discovery issuer does not match configured issuer",
            details: {discovered: doc[:issuer], configured: issuer}
          )
        end

        def normalize_discovery_urls(document, issuer, trusted_origin = nil)
          doc = BetterAuth::Plugins.normalize_hash(document || {}).dup
          DISCOVERY_URL_FIELDS.each do |field|
            next if doc[field].to_s.empty?

            doc[field] = normalize_url(field.to_s, doc[field], issuer, trusted_origin)
          end
          doc
        end

        def fetch_discovery_document(url, timeout: nil, fetch: nil)
          response = if fetch
            fetch.call(url, timeout: timeout)
          else
            uri = URI(url)
            Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", read_timeout: timeout) do |http|
              http.get(uri.request_uri)
            end
          end
          parse_discovery_fetch_response(response)
        rescue DiscoveryError
          raise
        rescue Timeout::Error
          raise DiscoveryError.new("discovery_timeout", "OIDC discovery request timed out", details: {url: url})
        rescue => exception
          if exception.message.match?(/aborted/i)
            raise DiscoveryError.new("discovery_timeout", "OIDC discovery request timed out", details: {url: url})
          end

          raise DiscoveryError.new("discovery_unexpected_error", "OIDC discovery request failed", details: {url: url, error: exception.message})
        end

        def discover_oidc_config(issuer:, fetch: nil, existing_config: nil, discovery_endpoint: nil, trusted_origin: nil, is_trusted_origin: nil, timeout: nil)
          existing = BetterAuth::Plugins.normalize_hash(existing_config || {})
          origin_check = trusted_origin || is_trusted_origin
          discovery_url = discovery_endpoint || existing[:discovery_endpoint] || compute_discovery_url(issuer)
          validate_discovery_url(discovery_url, origin_check)

          document = fetch_discovery_document(discovery_url, timeout: timeout, fetch: fetch)
          validate_discovery_document(document, issuer)
          normalized_document = normalize_discovery_urls(document, issuer, origin_check)

          {
            issuer: existing[:issuer] || normalized_document[:issuer],
            discovery_endpoint: existing[:discovery_endpoint] || discovery_url,
            client_id: existing[:client_id],
            client_secret: existing[:client_secret],
            authorization_endpoint: existing[:authorization_endpoint] || normalized_document[:authorization_endpoint],
            token_endpoint: existing[:token_endpoint] || normalized_document[:token_endpoint],
            jwks_endpoint: existing[:jwks_endpoint] || normalized_document[:jwks_uri],
            user_info_endpoint: existing[:user_info_endpoint] || normalized_document[:userinfo_endpoint],
            token_endpoint_authentication: select_token_endpoint_auth_method(normalized_document, existing[:token_endpoint_authentication]),
            scopes_supported: existing[:scopes_supported] || normalized_document[:scopes_supported],
            pkce: existing[:pkce],
            override_user_info: existing[:override_user_info],
            mapping: existing[:mapping]
          }.compact
        end

        def normalize_url(name_or_value, value_or_issuer, issuer = nil, trusted_origin = nil)
          name = issuer.nil? ? "url" : name_or_value.to_s
          value = issuer.nil? ? name_or_value : value_or_issuer
          issuer_value = issuer.nil? ? value_or_issuer : issuer
          normalized = normalize_endpoint_url(name, value, issuer_value)

          if trusted_origin && !trusted_origin.call(normalized)
            raise DiscoveryError.new(
              "discovery_untrusted_origin",
              "The #{name} \"#{normalized}\" is not trusted by your trusted origins configuration.",
              details: {endpoint: name, url: normalized}
            )
          end

          normalized
        end

        def needs_runtime_discovery?(oidc_config)
          config = BetterAuth::Plugins.normalize_hash(oidc_config || {})
          config[:authorization_endpoint].to_s.empty? ||
            config[:token_endpoint].to_s.empty? ||
            config[:jwks_endpoint].to_s.empty?
        end

        def ensure_runtime_discovery(config, issuer, trusted_origin, fetch: nil, timeout: nil)
          normalized = BetterAuth::Plugins.normalize_hash(config || {})
          return config unless needs_runtime_discovery?(normalized)

          discovered = discover_oidc_config(
            issuer: issuer,
            existing_config: normalized,
            trusted_origin: trusted_origin,
            fetch: fetch,
            timeout: timeout
          )
          normalized.merge(
            authorization_endpoint: discovered[:authorization_endpoint],
            token_endpoint: discovered[:token_endpoint],
            token_endpoint_authentication: discovered[:token_endpoint_authentication],
            user_info_endpoint: discovered[:user_info_endpoint],
            jwks_endpoint: discovered[:jwks_endpoint]
          ).compact
        end

        def select_token_endpoint_auth_method(document_or_config = {}, existing_method = nil)
          return existing_method if existing_method

          config = BetterAuth::Plugins.normalize_hash(document_or_config || {})
          return config[:token_endpoint_authentication] if config[:token_endpoint_authentication]

          methods = config[:token_endpoint_auth_methods_supported] || config[:methods] || []
          return "client_secret_post" if Array(methods).include?("client_secret_post") && !Array(methods).include?("client_secret_basic")

          "client_secret_basic"
        end

        def parse_http_url!(url, name, details: {})
          uri = URI.parse(url.to_s)
          raise URI::InvalidURIError if uri.scheme.to_s.empty? || uri.host.to_s.empty?
          unless %w[http https].include?(uri.scheme)
            raise DiscoveryError.new(
              "discovery_invalid_url",
              "The url \"#{name}\" must use the http or https supported protocols",
              details: details.merge(protocol: "#{uri.scheme}:")
            )
          end

          uri
        rescue URI::InvalidURIError
          raise DiscoveryError.new(
            "discovery_invalid_url",
            "The url \"#{name}\" must be valid",
            details: details
          )
        end

        def normalize_endpoint_url(name, endpoint, issuer)
          raw = endpoint.to_s
          if raw.match?(%r{\Ahttps?://}i)
            uri = parse_http_url!(raw, name, details: {endpoint: name, url: raw})
            return uri.to_s
          end

          issuer_uri = parse_http_url!(issuer, name, details: {endpoint: name, url: raw})
          issuer_base = issuer_uri.to_s.sub(%r{/+\z}, "")
          endpoint_path = raw.sub(%r{\A/+}, "")
          normalized = "#{issuer_base}/#{endpoint_path}"
          parse_http_url!(normalized, name, details: {endpoint: name, url: normalized}).to_s
        end

        def parse_discovery_fetch_response(response)
          if response.respond_to?(:code) && response.respond_to?(:body)
            status = response.code.to_i
            body = response.body
            return parse_discovery_body(body) if status.between?(200, 299)

            raise_discovery_http_error(status, response.message.to_s)
          end

          normalized = response.is_a?(Hash) ? BetterAuth::Plugins.normalize_hash(response) : {data: response}
          error = normalized[:error]
          if error
            error_hash = BetterAuth::Plugins.normalize_hash(error)
            raise_discovery_http_error(error_hash[:status].to_i, error_hash[:message].to_s)
          end

          data = normalized.key?(:data) ? normalized[:data] : normalized
          parse_discovery_body(data)
        end

        def parse_discovery_body(data)
          raise DiscoveryError.new("discovery_invalid_json", "OIDC discovery response was empty") if data.nil?
          return BetterAuth::Plugins.normalize_hash(data) if data.is_a?(Hash)

          parsed = JSON.parse(data.to_s)
          raise JSON::ParserError if !parsed.is_a?(Hash)

          BetterAuth::Plugins.normalize_hash(parsed)
        rescue JSON::ParserError
          raise DiscoveryError.new(
            "discovery_invalid_json",
            "OIDC discovery response was not valid JSON",
            details: {bodyPreview: data.to_s[0, 200]}
          )
        end

        def raise_discovery_http_error(status, message)
          case status
          when 404
            raise DiscoveryError.new("discovery_not_found", "OIDC discovery endpoint was not found", details: {status: status, message: message})
          when 408
            raise DiscoveryError.new("discovery_timeout", "OIDC discovery request timed out", details: {status: status, message: message})
          else
            raise DiscoveryError.new("discovery_unexpected_error", "OIDC discovery request failed", details: {status: status, message: message})
          end
        end
      end
    end
  end
end

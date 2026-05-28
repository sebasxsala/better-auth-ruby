# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def sso_discover_oidc_config(issuer:, fetch: nil, existing_config: nil, discovery_endpoint: nil, trusted_origin: nil, timeout: nil)
      wrapped_fetch = sso_oidc_discovery_fetcher(fetch)
      BetterAuth::SSO::OIDC::Discovery.discover_oidc_config(
        issuer: issuer,
        fetch: wrapped_fetch,
        existing_config: existing_config,
        discovery_endpoint: discovery_endpoint,
        trusted_origin: trusted_origin,
        timeout: timeout || SSO_DEFAULT_OIDC_HTTP_TIMEOUT
      )
    rescue BetterAuth::SSO::OIDC::DiscoveryError => error
      raise BetterAuth::SSO::OIDC::Errors.api_error(error)
    end

    def sso_oidc_discovery_fetcher(fetch)
      return nil unless fetch

      ->(url, timeout: nil) do
        accepts_keywords = fetch.parameters.any? { |kind, name| kind == :keyrest || (kind == :key && name == :timeout) }
        accepts_keywords ? fetch.call(url, timeout: timeout) : fetch.call(url)
      end
    end

    def sso_normalize_discovery_url(value, issuer, trusted_origin)
      BetterAuth::SSO::OIDC::Discovery.normalize_url("url", value, issuer, trusted_origin)
    rescue BetterAuth::SSO::OIDC::DiscoveryError => error
      raise BetterAuth::SSO::OIDC::Errors.api_error(error)
    end
  end
end

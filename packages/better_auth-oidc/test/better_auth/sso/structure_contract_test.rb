# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthOIDCStructureContractTest < Minitest::Test
  OIDC = BetterAuth::SSO::OIDC
  Discovery = BetterAuth::SSO::OIDC::Discovery
  OIDCTypes = BetterAuth::SSO::OIDC::Types
  Errors = BetterAuth::SSO::OIDC::Errors
  DiscoveryError = BetterAuth::SSO::OIDC::DiscoveryError

  def test_oidc_public_wrapper_exposes_discovery_contract
    result = OIDC.discover_config(
      issuer: "https://idp.example.com",
      fetch: ->(_url, **_options) {
        {
          issuer: "https://idp.example.com",
          authorization_endpoint: "/authorize",
          token_endpoint: "/token",
          jwks_uri: "/jwks",
          token_endpoint_auth_methods_supported: ["client_secret_post"]
        }
      },
      trusted_origin: ->(url) { url.start_with?("https://idp.example.com/") },
      existing_config: {
        client_id: "client-id",
        client_secret: "client-secret"
      }
    )

    assert_equal "https://idp.example.com/.well-known/openid-configuration", result.fetch(:discovery_endpoint)
    assert_equal "https://idp.example.com/authorize", result.fetch(:authorization_endpoint)
    assert_equal "https://idp.example.com/token", result.fetch(:token_endpoint)
    assert_equal "https://idp.example.com/jwks", result.fetch(:jwks_endpoint)
    assert_equal "client_secret_post", result.fetch(:token_endpoint_authentication)
    assert_equal "client-id", result.fetch(:client_id)
    assert_equal "client-secret", result.fetch(:client_secret)

    assert OIDC.needs_runtime_discovery?(authorization_endpoint: "https://idp.example.com/authorize")
    refute OIDC.needs_runtime_discovery?(
      authorization_endpoint: "https://idp.example.com/authorize",
      token_endpoint: "https://idp.example.com/token",
      jwks_endpoint: "https://idp.example.com/jwks"
    )
  end

  def test_oidc_error_surface_preserves_discovery_metadata_and_maps_api_errors
    discovery_error = DiscoveryError.new(
      "discovery_invalid_url",
      "The url \"discoveryEndpoint\" must be valid",
      details: {url: "not-a-url"}
    )

    assert_equal "discovery_invalid_url", discovery_error.code
    assert_equal({url: "not-a-url"}, discovery_error.details)

    api_error = Errors.api_error(discovery_error)
    assert_instance_of BetterAuth::APIError, api_error
    assert_equal "BAD_REQUEST", api_error.status
    assert_equal 400, api_error.status_code
    assert_equal discovery_error.message, api_error.message

    existing_api_error = BetterAuth::APIError.new("BAD_GATEWAY", message: "upstream failed")
    assert_same existing_api_error, Errors.api_error(existing_api_error)
  end

  def test_discovery_required_field_constants_match_upstream_oidc_types
    assert_equal %i[issuer authorization_endpoint token_endpoint jwks_uri], Discovery::REQUIRED_DISCOVERY_FIELDS
    assert Discovery::REQUIRED_DISCOVERY_FIELDS.frozen?
    assert_equal Discovery::REQUIRED_DISCOVERY_FIELDS, OIDCTypes::REQUIRED_DISCOVERY_FIELDS
    assert_includes OIDCTypes::DISCOVERY_ERROR_CODES, "discovery_timeout"
    assert_includes OIDCTypes::DISCOVERY_ERROR_CODES, "unsupported_token_auth_method"
    assert OIDCTypes.discovery_error_code?("issuer_mismatch")
    refute OIDCTypes.discovery_error_code?("unknown")
  end
end

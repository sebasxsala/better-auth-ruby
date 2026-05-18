# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderMetadataTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_authorization_server_metadata_matches_upstream_endpoints_and_cache_headers
    auth = build_auth(scopes: ["openid", "profile", "email"])

    response = auth.api.get_o_auth_server_config(as_response: true)
    body = JSON.parse(response.body.join, symbolize_names: true)

    assert_equal 200, response.status
    assert_equal "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400", response.headers["cache-control"]
    assert_equal "http://localhost:3000", body[:issuer]
    assert_equal "http://localhost:3000/api/auth/oauth2/authorize", body[:authorization_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/token", body[:token_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/register", body[:registration_endpoint]
    assert_equal ["code"], body[:response_types_supported]
  end

  def test_authorization_server_metadata_omits_registration_endpoint_when_dcr_disabled
    auth = build_auth(scopes: ["openid"], allow_dynamic_client_registration: false)

    response = auth.api.get_o_auth_server_config(as_response: true)
    body = JSON.parse(response.body.join, symbolize_names: true)

    assert_equal 200, response.status
    refute body.key?(:registration_endpoint)
  end

  def test_openid_metadata_omits_registration_endpoint_when_dcr_disabled
    auth = build_auth(scopes: ["openid"], allow_dynamic_client_registration: false)

    response = auth.api.get_open_id_config(as_response: true)
    body = JSON.parse(response.body.join, symbolize_names: true)

    assert_equal 200, response.status
    refute body.key?(:registration_endpoint)
  end

  def test_metadata_includes_default_jwks_uri_when_jwt_plugin_is_active
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: OAuthProviderFlowHelpers::SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.jwt(jwks: {key_pair_config: {alg: "EdDSA"}}),
        BetterAuth::Plugins.oauth_provider(scopes: ["openid"])
      ]
    )

    metadata = auth.api.get_open_id_config

    assert_equal "http://localhost:3000/api/auth/jwks", metadata[:jwks_uri]
    assert_equal ["EdDSA"], metadata[:id_token_signing_alg_values_supported]
  end
end

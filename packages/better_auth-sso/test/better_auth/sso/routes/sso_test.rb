# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthSSORoutesSSOTest < Minitest::Test
  ROUTES = BetterAuth::SSO::Routes::SSO

  def test_endpoints_builds_core_sso_route_map
    endpoints = ROUTES.endpoints

    expected = %i[
      sp_metadata
      register_sso_provider
      sign_in_sso
      callback_sso
      callback_sso_shared
      callback_sso_saml
      acs_endpoint
      slo_endpoint
      initiate_slo
      list_sso_providers
      get_sso_provider
      update_sso_provider
      delete_sso_provider
    ]
    assert_equal expected.sort, endpoints.keys.sort
    endpoints.each_value { |endpoint| assert_instance_of BetterAuth::Endpoint, endpoint }
  end

  def test_endpoints_include_domain_verification_routes_when_enabled
    endpoints = ROUTES.endpoints(domainVerification: {enabled: true})

    assert_includes endpoints.keys, :request_domain_verification
    assert_includes endpoints.keys, :verify_domain
    assert_instance_of BetterAuth::Endpoint, endpoints.fetch(:request_domain_verification)
    assert_instance_of BetterAuth::Endpoint, endpoints.fetch(:verify_domain)
  end

  def test_oidc_redirect_uri_delegates_to_plugins
    context = Object.new
    calls = []

    BetterAuth::Plugins.stub(:sso_oidc_redirect_uri, ->(*args) {
      calls << args
      "https://app.example.com/sso/callback/provider"
    }) do
      assert_equal(
        "https://app.example.com/sso/callback/provider",
        ROUTES.oidc_redirect_uri(context, "provider")
      )
    end

    assert_equal [[context, "provider"]], calls
  end

  def test_saml_authorization_url_delegates_to_plugins_with_defaults
    provider = {"providerId" => "saml-provider"}
    calls = []

    BetterAuth::Plugins.stub(:sso_saml_authorization_url, ->(*args) {
      calls << args
      "https://idp.example.com/sso?SAMLRequest=encoded"
    }) do
      assert_equal(
        "https://idp.example.com/sso?SAMLRequest=encoded",
        ROUTES.saml_authorization_url(provider, "relay-state")
      )
    end

    assert_equal [[provider, "relay-state", nil, {}]], calls
  end
end

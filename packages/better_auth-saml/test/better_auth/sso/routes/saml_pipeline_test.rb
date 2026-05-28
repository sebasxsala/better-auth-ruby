# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthSSORoutesSAMLPipelineTest < Minitest::Test
  ROUTES = BetterAuth::SSO::Routes::SAMLPipeline

  def test_process_response_delegates_to_plugins_with_defaults
    ctx = Object.new
    response = Object.new
    calls = []

    BetterAuth::Plugins.stub(:sso_handle_saml_response, ->(*args) {
      calls << args
      response
    }) do
      assert_same response, ROUTES.process_response(ctx)
    end

    assert_equal [[ctx, {}]], calls
  end

  def test_safe_redirect_url_delegates_to_plugins
    ctx = Object.new
    calls = []

    BetterAuth::Plugins.stub(:sso_safe_slo_redirect_url, ->(*args) {
      calls << args
      "https://app.example.com/dashboard"
    }) do
      assert_equal(
        "https://app.example.com/dashboard",
        ROUTES.safe_redirect_url(ctx, "https://app.example.com/dashboard", "saml-provider")
      )
    end

    assert_equal [[ctx, "https://app.example.com/dashboard", "saml-provider"]], calls
  end
end

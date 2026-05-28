# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthSSOSAMLConfigValidationTest < Minitest::Test
  def test_single_sign_on_service_uses_sso_error_message
    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_config!(
        {single_sign_on_service: "not-a-url", entry_point: "https://idp.example.com/sso"},
        {}
      )
    end

    assert_includes error.message, "singleSignOnService"
    refute_includes error.message, "singleLogoutService"
  end

  def test_single_logout_service_validated_when_present
    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_config!(
        {single_logout_service: ":::bad", entry_point: "https://idp.example.com/sso"},
        {}
      )
    end

    assert_equal "BAD_REQUEST", error.status
    assert_includes error.message, "singleLogoutService"
  end
end

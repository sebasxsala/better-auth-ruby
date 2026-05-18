# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderRegisterTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_dynamic_registration_defaults_to_pkce_and_strips_unknown_metadata
    auth = build_auth(scopes: ["openid", "profile"])
    cookie = sign_up_cookie(auth)

    client = register_client(
      auth,
      cookie,
      scope: "openid",
      metadata: {trusted: true, software_id: "software-1"}
    )

    assert_equal true, client[:require_pkce]
    assert_equal "software-1", client[:metadata]["software_id"]
    refute client[:metadata].key?("trusted")
  end

  def test_dynamic_registration_rejects_scalar_metadata
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)

    error = assert_raises(BetterAuth::APIError) do
      register_client(auth, cookie, scope: "openid", metadata: "not-an-object")
    end

    assert_equal 400, error.status_code
    assert_match(/metadata/i, error.message)
  end
end

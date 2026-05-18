# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderIntrospectTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_introspect_reports_active_opaque_access_token
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access")

    response = auth.api.o_auth2_introspect(body: introspect_body(client, tokens[:access_token]))

    assert_equal true, response[:active]
    assert_equal client[:client_id], response[:client_id]
    assert_equal "openid offline_access", response[:scope]
    assert_equal "http://localhost:3000", response[:iss]
  end

  def test_introspect_strips_bearer_prefix
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    response = auth.api.o_auth2_introspect(body: introspect_body(client, "Bearer #{tokens[:access_token]}"))

    assert_equal true, response[:active]
    assert_equal client[:client_id], response[:client_id]
  end

  def test_introspect_does_not_expose_tokens_to_other_clients
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    owner = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)
    other = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, owner, scope: "openid offline_access")

    access = auth.api.o_auth2_introspect(body: introspect_body(other, tokens[:access_token], hint: "access_token"))
    refresh = auth.api.o_auth2_introspect(body: introspect_body(other, tokens[:refresh_token], hint: "refresh_token"))

    assert_equal false, access[:active]
    assert_equal false, refresh[:active]
  end

  def test_public_clients_cannot_authenticate_to_introspection
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    public_client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["com.example.app:/callback"],
        token_endpoint_auth_method: "none",
        type: "native",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid",
        skip_consent: true
      }
    )
    tokens = issue_authorization_code_tokens(
      auth,
      cookie,
      public_client,
      scope: "openid",
      redirect_uri: "com.example.app:/callback"
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_introspect(body: {client_id: public_client[:client_id], token: tokens[:access_token], token_type_hint: "access_token"})
    end

    assert_equal 401, error.status_code
    assert_match(/invalid_client/, error.message)
  end
end

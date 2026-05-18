# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderRevokeTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_revoke_access_token_makes_introspection_inactive
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    assert_equal({revoked: true}, auth.api.o_auth2_revoke(body: revoke_body(client, tokens[:access_token], hint: "access_token")))

    inactive = auth.api.o_auth2_introspect(body: introspect_body(client, tokens[:access_token], hint: "access_token"))
    assert_equal false, inactive[:active]
  end

  def test_revoke_access_token_persists_revoked_timestamp
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    auth.api.o_auth2_revoke(body: revoke_body(client, tokens[:access_token], hint: "access_token"))

    record = auth.context.adapter.find_many(model: "oauthAccessToken", where: [{field: "clientId", value: client[:client_id]}]).first
    assert record["revoked"]
  end

  def test_revoke_does_not_revoke_tokens_owned_by_another_client
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    owner = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)
    other = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, owner, scope: "openid offline_access")

    assert_equal({revoked: true}, auth.api.o_auth2_revoke(body: revoke_body(other, tokens[:access_token], hint: "access_token")))
    assert_equal({revoked: true}, auth.api.o_auth2_revoke(body: revoke_body(other, tokens[:refresh_token], hint: "refresh_token")))

    access = auth.api.o_auth2_introspect(body: introspect_body(owner, tokens[:access_token], hint: "access_token"))
    refresh = auth.api.o_auth2_introspect(body: introspect_body(owner, tokens[:refresh_token], hint: "refresh_token"))
    assert_equal true, access[:active]
    assert_equal true, refresh[:active]
  end

  def test_revoke_refresh_token_makes_associated_access_token_inactive
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access")

    assert_equal({revoked: true}, auth.api.o_auth2_revoke(body: revoke_body(client, tokens[:refresh_token], hint: "refresh_token")))

    access = auth.api.o_auth2_introspect(body: introspect_body(client, tokens[:access_token], hint: "access_token"))
    refresh = auth.api.o_auth2_introspect(body: introspect_body(client, tokens[:refresh_token], hint: "refresh_token"))
    assert_equal false, access[:active]
    assert_equal false, refresh[:active]
  end
end

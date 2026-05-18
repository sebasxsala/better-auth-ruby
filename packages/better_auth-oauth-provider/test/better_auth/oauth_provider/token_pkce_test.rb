# frozen_string_literal: true

require "jwt"
require_relative "../../test_helper"

class OAuthProviderTokenPkceTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_authorization_code_scope_response_matrix_matches_upstream
    auth = build_auth(
      scopes: ["openid", "profile", "email", "offline_access"],
      valid_audiences: ["https://myapi.example.com"]
    )
    cookie = sign_up_cookie(auth)
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        scope: "openid profile email offline_access",
        skip_consent: true
      }
    )

    openid = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")
    openid_payload = decode_id_token(openid[:id_token], client)
    assert openid[:access_token]
    assert openid[:id_token]
    assert_kind_of Integer, openid[:expires_at]
    assert_nil openid[:refresh_token]
    assert_equal "openid", openid[:scope]
    assert openid_payload["sub"]
    refute openid_payload.key?("name")
    refute openid_payload.key?("email")

    profile = issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile")
    profile_payload = decode_id_token(profile[:id_token], client)
    assert_equal "openid profile", profile[:scope]
    assert_equal "OAuth Owner", profile_payload["name"]
    refute profile_payload.key?("email")

    email = issue_authorization_code_tokens(auth, cookie, client, scope: "openid email")
    email_payload = decode_id_token(email[:id_token], client)
    assert_equal "openid email", email[:scope]
    assert_equal "oauth-provider@example.com", email_payload["email"]
    assert_equal false, email_payload["email_verified"]
    refute email_payload.key?("name")

    offline = issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access")
    assert offline[:access_token]
    assert offline[:id_token]
    assert offline[:refresh_token]
    assert_equal "openid offline_access", offline[:scope]

    resource = issue_authorization_code_tokens(
      auth,
      cookie,
      client,
      scope: "openid offline_access",
      resource: "https://myapi.example.com"
    )
    access_payload = JWT.decode(resource[:access_token], SECRET, true, algorithm: "HS256").first
    assert resource[:id_token]
    assert resource[:refresh_token]
    assert_equal ["https://myapi.example.com", "http://localhost:3000/api/auth/oauth2/userinfo"], resource[:audience]
    assert_equal ["https://myapi.example.com", "http://localhost:3000/api/auth/oauth2/userinfo"], access_payload["aud"]
    assert_equal client[:client_id], access_payload["azp"]
    assert_equal "openid offline_access", access_payload["scope"]
    assert_equal resource[:expires_at], access_payload["exp"]
  end

  def test_authorization_code_exchange_allows_omitted_state
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)
    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "openid",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    params = extract_redirect_params(headers)
    code = params.fetch("code")
    refute params.key?("state")

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://resource.example/callback",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        code_verifier: pkce_verifier
      }
    )

    assert tokens[:access_token]
    assert tokens[:id_token]
  end

  def test_refresh_token_scope_matrix_matches_upstream
    auth = build_auth(
      scopes: ["openid", "profile", "email", "offline_access"],
      valid_audiences: ["https://myapi.example.com"]
    )
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid profile email offline_access", skip_consent: true)

    same_source = issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile offline_access")
    same = auth.api.o_auth2_token(body: refresh_grant_body(client, same_source[:refresh_token]))
    assert same[:access_token]
    assert same[:id_token]
    assert same[:refresh_token]
    refute_equal same_source[:refresh_token], same[:refresh_token]
    assert_equal "openid profile offline_access", same[:scope]
    assert_kind_of Integer, same[:expires_at]

    lesser_source = issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile offline_access")
    lesser = auth.api.o_auth2_token(body: refresh_grant_body(client, lesser_source[:refresh_token], scope: "openid"))
    assert lesser[:access_token]
    assert lesser[:id_token]
    assert lesser[:refresh_token]
    assert_equal "openid", lesser[:scope]

    without_offline_source = issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile offline_access")
    without_offline = auth.api.o_auth2_token(body: refresh_grant_body(client, without_offline_source[:refresh_token], scope: "openid"))
    assert without_offline[:refresh_token]
    assert_equal "openid", without_offline[:scope]

    more_source = issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile offline_access")
    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(body: refresh_grant_body(client, more_source[:refresh_token], scope: "openid email offline_access"))
    end
    assert_equal 400, error.status_code
    assert_match(/invalid_scope/i, error.message)

    jwt_source = issue_authorization_code_tokens(
      auth,
      cookie,
      client,
      scope: "openid offline_access",
      resource: "https://myapi.example.com"
    )
    jwt_refresh = auth.api.o_auth2_token(
      body: refresh_grant_body(client, jwt_source[:refresh_token], resource: "https://myapi.example.com")
    )
    payload = JWT.decode(jwt_refresh[:access_token], SECRET, true, algorithm: "HS256").first
    assert_equal ["https://myapi.example.com", "http://localhost:3000/api/auth/oauth2/userinfo"], jwt_refresh[:audience]
    assert_equal ["https://myapi.example.com", "http://localhost:3000/api/auth/oauth2/userinfo"], payload["aud"]
    assert_equal "openid offline_access", payload["scope"]
    assert_equal jwt_refresh[:expires_at], payload["exp"]
  end

  def test_client_credentials_token_matrix_matches_upstream
    auth = build_auth(
      scopes: ["read", "write"],
      valid_audiences: ["https://myapi.example.com"]
    )
    cookie = sign_up_cookie(auth)
    client = create_client(
      auth,
      cookie,
      grant_types: ["client_credentials"],
      response_types: [],
      scope: "read write"
    )

    opaque = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read"
      }
    )
    assert opaque[:access_token].start_with?("ba_at_")
    assert_equal "Bearer", opaque[:token_type]
    assert_equal "read", opaque[:scope]
    assert_kind_of Integer, opaque[:expires_at]
    assert_nil opaque[:refresh_token]
    assert_nil opaque[:id_token]

    all_scopes = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal "read write", all_scopes[:scope]

    jwt = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read",
        resource: "https://myapi.example.com"
      }
    )
    payload = JWT.decode(jwt[:access_token], SECRET, true, algorithm: "HS256").first
    assert_equal "https://myapi.example.com", jwt[:audience]
    assert_equal "https://myapi.example.com", payload["aud"]
    assert_equal client[:client_id], payload["azp"]
    assert_equal "read", payload["scope"]
    assert_equal jwt[:expires_at], payload["exp"]
  end

  def test_confidential_client_with_require_pkce_false_can_exchange_without_pkce
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid",
        skip_consent: true,
        require_pkce: false
      }
    )

    code = authorization_code_for(auth, cookie, client, scope: "openid", verifier: nil)
    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://resource.example/callback",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )

    assert tokens[:access_token]
    assert tokens[:id_token]
  end

  def test_public_client_cannot_opt_out_of_pkce
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["com.example.app:/callback"],
        token_endpoint_auth_method: "none",
        type: "native",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid",
        skip_consent: true,
        require_pkce: false
      }
    )

    status, headers, = authorize_response(
      auth,
      cookie,
      client,
      scope: "openid",
      redirect_uri: "com.example.app:/callback",
      verifier: nil
    )

    assert_equal 302, status
    params = extract_redirect_params(headers)
    assert_equal "invalid_request", params.fetch("error")
    assert_match(/pkce/i, params.fetch("error_description"))
  end

  def test_token_exchange_rejects_code_verifier_when_authorize_did_not_use_pkce
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid",
        skip_consent: true,
        require_pkce: false
      }
    )
    code = authorization_code_for(auth, cookie, client, scope: "openid", verifier: nil)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "authorization_code",
          code: code,
          redirect_uri: "https://resource.example/callback",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          code_verifier: pkce_verifier
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/invalid_grant/i, error.message)
  end

  def test_offline_access_requires_pkce_even_when_client_opted_out
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope: "openid offline_access",
        skip_consent: true,
        require_pkce: false
      }
    )

    status, headers, = authorize_response(auth, cookie, client, scope: "openid offline_access", verifier: nil)

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "invalid_request", params.fetch("error")
    assert_match(/pkce/i, params.fetch("error_description"))
  end

  def test_mismatched_pkce_challenge_fails_token_exchange
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)
    code = authorization_code_for(auth, cookie, client, scope: "openid", verifier: pkce_verifier)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "authorization_code",
          code: code,
          redirect_uri: "https://resource.example/callback",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          code_verifier: alternate_pkce_verifier
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/invalid_grant/i, error.message)
  end

  def test_loopback_redirect_uri_matching_ignores_port_for_ip_literals_only
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    loopback = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["http://127.0.0.1:3000/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid",
        skip_consent: true
      }
    )
    ipv6 = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["http://[::1]:3000/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid",
        skip_consent: true
      }
    )
    web = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example:3000/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid",
        skip_consent: true
      }
    )

    assert authorization_code_for(auth, cookie, loopback, scope: "openid", redirect_uri: "http://127.0.0.1:4567/callback")
    assert authorization_code_for(auth, cookie, ipv6, scope: "openid", redirect_uri: "http://[::1]:4567/callback")

    web_status, = authorize_response(auth, cookie, web, scope: "openid", redirect_uri: "https://resource.example:4567/callback")
    path_status, = authorize_response(auth, cookie, loopback, scope: "openid", redirect_uri: "http://127.0.0.1:4567/other")

    assert_equal 400, web_status
    assert_equal 400, path_status
  end

  def test_custom_token_response_fields_cannot_override_standard_oauth_fields
    auth = build_auth(
      scopes: ["openid"],
      custom_token_response_fields: ->(_info) {
        {
          access_token: "attacker-token",
          token_type: "mac",
          expires_in: 1,
          scope: "admin",
          tenant: "acme"
        }
      }
    )
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    refute_equal "attacker-token", tokens[:access_token]
    assert_equal "Bearer", tokens[:token_type]
    assert_equal 3600, tokens[:expires_in]
    assert_equal "openid", tokens[:scope]
    assert_equal "acme", tokens[:tenant]
  end

  def test_custom_id_token_claims_can_override_profile_but_not_pinned_claims
    auth = build_auth(
      scopes: ["openid", "profile", "email"],
      custom_id_token_claims: ->(_info) {
        {
          name: "Custom Name",
          email: "custom@example.com",
          acr: "custom-acr",
          auth_time: 12_345,
          sub: "attacker-sub",
          iss: "https://evil.example",
          aud: "evil-audience",
          nonce: "evil-nonce"
        }
      }
    )
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid profile email", skip_consent: true)

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile email", nonce: "real-nonce")
    payload = decode_id_token(tokens[:id_token], client)

    assert_equal "Custom Name", payload["name"]
    assert_equal "custom@example.com", payload["email"]
    assert_equal "custom-acr", payload["acr"]
    assert_equal 12_345, payload["auth_time"]
    refute_equal "attacker-sub", payload["sub"]
    assert_equal "http://localhost:3000", payload["iss"]
    assert_equal client[:client_id], payload["aud"]
    assert_equal "real-nonce", payload["nonce"]
  end

  def test_scope_expirations_use_lowest_matching_scope_for_all_token_grants
    auth = build_auth(
      scopes: ["openid", "offline_access", "read:payments", "write:payments"],
      valid_audiences: ["https://api.example"],
      access_token_expires_in: 7200,
      m2m_access_token_expires_in: 7200,
      scope_expirations: {
        "read:payments" => "30m",
        "write:payments" => "5m"
      }
    )
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid offline_access read:payments write:payments", skip_consent: true)

    machine = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read:payments write:payments",
        resource: "https://api.example"
      }
    )
    assert_equal 300, machine[:expires_in]

    auth_code = issue_authorization_code_tokens(
      auth,
      cookie,
      client,
      scope: "openid offline_access read:payments",
      resource: "https://api.example"
    )
    assert_equal 1800, auth_code[:expires_in]

    refreshed = auth.api.o_auth2_token(
      body: refresh_grant_body(client, auth_code[:refresh_token], resource: "https://api.example")
    )
    assert_equal 1800, refreshed[:expires_in]
  end
end

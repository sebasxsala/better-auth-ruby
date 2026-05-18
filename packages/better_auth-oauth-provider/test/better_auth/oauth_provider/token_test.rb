# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderTokenTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_client_secret_basic_authorization_code_exchange_uses_authenticated_client_id
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, token_endpoint_auth_method: "client_secret_basic", scope: "openid", skip_consent: true)
    code = authorization_code_for(auth, cookie, client, scope: "openid")
    credentials = Base64.strict_encode64("#{client[:client_id]}:#{client[:client_secret]}")

    tokens = auth.api.o_auth2_token(
      headers: {"authorization" => "Basic #{credentials}"},
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://resource.example/callback",
        code_verifier: pkce_verifier
      }
    )

    assert tokens[:access_token]
    assert tokens[:id_token]
  end

  def test_token_endpoint_enforces_registered_client_auth_method
    auth = build_auth(scopes: ["read"])
    cookie = sign_up_cookie(auth)
    basic = create_client(auth, cookie, token_endpoint_auth_method: "client_secret_basic", grant_types: ["client_credentials"], response_types: [], scope: "read")
    post = create_client(auth, cookie, token_endpoint_auth_method: "client_secret_post", grant_types: ["client_credentials"], response_types: [], scope: "read")
    credentials = Base64.strict_encode64("#{post[:client_id]}:#{post[:client_secret]}")

    body_error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "client_credentials",
          client_id: basic[:client_id],
          client_secret: basic[:client_secret],
          scope: "read"
        }
      )
    end
    basic_error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        headers: {"authorization" => "Basic #{credentials}"},
        body: {
          grant_type: "client_credentials",
          scope: "read"
        }
      )
    end

    assert_equal 401, body_error.status_code
    assert_match(/invalid_client/, body_error.message)
    assert_equal 401, basic_error.status_code
    assert_match(/invalid_client/, basic_error.message)
  end

  def test_public_client_rejects_secret_credentials
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
        skip_consent: true
      }
    )
    code = authorization_code_for(auth, cookie, client, scope: "openid", redirect_uri: "com.example.app:/callback")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "authorization_code",
          code: code,
          redirect_uri: "com.example.app:/callback",
          client_id: client[:client_id],
          client_secret: "unexpected-secret",
          code_verifier: pkce_verifier
        }
      )
    end

    assert_equal 401, error.status_code
    assert_match(/invalid_client/, error.message)
  end

  def test_token_endpoint_rejects_expired_client_secret
    auth = build_auth(scopes: ["read"])
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        scope: "read",
        client_secret_expires_at: Time.now.to_i - 60
      }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          scope: "read"
        }
      )
    end

    assert_equal 401, error.status_code
    assert_match(/invalid_client/, error.message)
  end

  def test_malformed_basic_authorization_returns_oauth_error
    auth = build_auth(scopes: ["read"])

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        headers: {"authorization" => "Basic #{Base64.strict_encode64("missing-colon")}"},
        body: {grant_type: "client_credentials", scope: "read"}
      )
    end

    assert_equal 400, error.status_code
    assert_match(/invalid authorization header format/, error.message)
  end

  def test_token_responses_are_not_cacheable
    auth = build_auth(scopes: ["read"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["client_credentials"], response_types: [], scope: "read")

    status, headers, = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read"
      },
      as_response: true
    )

    assert_equal 200, status
    assert_equal "no-store", headers.fetch("cache-control")
    assert_equal "no-cache", headers.fetch("pragma")
  end

  def test_authorization_code_exchange_rejects_deleted_session
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)
    session = auth.api.get_session(headers: {"cookie" => cookie})
    code = authorization_code_for(auth, cookie, client, scope: "openid")
    auth.context.adapter.delete(model: "session", where: [{field: "id", value: session.fetch(:session).fetch("id")}])

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
    assert_match(/session/i, error.message)
  end

  def test_authorization_code_exchange_rejects_expired_session
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)
    session = auth.api.get_session(headers: {"cookie" => cookie})
    code = authorization_code_for(auth, cookie, client, scope: "openid")
    auth.context.adapter.update(model: "session", where: [{field: "id", value: session.fetch(:session).fetch("id")}], update: {expiresAt: Time.now - 60})

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
    assert_match(/session/i, error.message)
  end

  def test_authorization_code_exchange_rejects_redirect_and_client_mismatch
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)
    other = create_client(auth, cookie, scope: "openid", skip_consent: true)
    redirect_code = authorization_code_for(auth, cookie, client, scope: "openid")
    client_code = authorization_code_for(auth, cookie, client, scope: "openid")

    redirect_error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "authorization_code",
          code: redirect_code,
          redirect_uri: "https://resource.example/other-callback",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          code_verifier: pkce_verifier
        }
      )
    end
    client_error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "authorization_code",
          code: client_code,
          redirect_uri: "https://resource.example/callback",
          client_id: other[:client_id],
          client_secret: other[:client_secret],
          code_verifier: pkce_verifier
        }
      )
    end

    assert_equal 400, redirect_error.status_code
    assert_match(/invalid_grant/, redirect_error.message)
    assert_equal 400, client_error.status_code
    assert_match(/invalid_grant/, client_error.message)
  end

  def test_token_endpoint_rejects_missing_authorization_code_params_and_disabled_client
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)

    missing_code = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "authorization_code",
          redirect_uri: "https://resource.example/callback",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          code_verifier: pkce_verifier
        }
      )
    end
    missing_grant = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          client_id: client[:client_id],
          client_secret: client[:client_secret]
        }
      )
    end
    auth.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: client[:client_id]}], update: {disabled: true})
    disabled = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          scope: "read"
        }
      )
    end

    assert_equal 400, missing_code.status_code
    assert_match(/invalid_grant/, missing_code.message)
    assert_equal 400, missing_grant.status_code
    assert_match(/unsupported_grant_type/, missing_grant.message)
    assert_equal 401, disabled.status_code
    assert_match(/invalid_client/, disabled.message)
  end

  def test_refresh_token_requires_offline_access_even_when_client_allows_refresh_grant
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    assert tokens[:access_token]
    assert_nil tokens[:refresh_token]
  end

  def test_default_storage_hashes_client_secrets_and_opaque_tokens
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access")

    stored_client = auth.context.adapter.find_one(model: "oauthClient", where: [{field: "clientId", value: client[:client_id]}])
    access_token_value = BetterAuth::Plugins::OAuthProtocol.strip_prefix(tokens[:access_token], {}, :access_token)
    refresh_token_value = BetterAuth::Plugins::OAuthProtocol.strip_prefix(tokens[:refresh_token], {}, :refresh_token)
    access_records = auth.context.adapter.find_many(model: "oauthAccessToken", where: [{field: "clientId", value: client[:client_id]}])
    refresh_records = auth.context.adapter.find_many(model: "oauthRefreshToken", where: [{field: "clientId", value: client[:client_id]}])

    refute_equal client[:client_secret], stored_client.fetch("clientSecret")
    refute access_records.any? { |record| record["token"] == access_token_value }
    refute refresh_records.any? { |record| record["token"] == refresh_token_value }
  end

  def test_custom_store_tokens_hash_callback_is_used_for_persisted_tokens
    auth = build_auth(
      scopes: ["openid", "offline_access"],
      store_tokens: {
        hash: ->(token, type) { "#{type}:#{token.reverse}" }
      }
    )
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)
    issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access")

    access_record = auth.context.adapter.find_many(model: "oauthAccessToken", where: [{field: "clientId", value: client[:client_id]}]).first
    refresh_record = auth.context.adapter.find_many(model: "oauthRefreshToken", where: [{field: "clientId", value: client[:client_id]}]).first

    assert_match(/\Aaccess_token:/, access_record.fetch("token"))
    assert_match(/\Arefresh_token:/, refresh_record.fetch("token"))
  end

  def test_non_hash_token_body_returns_expected_error
    auth = build_auth(scopes: ["read"])

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(body: ["not", "an", "object"])
    end

    assert_equal 400, error.status_code
    assert_match(/request body/i, error.message)
  end

  def test_token_endpoint_rejects_unsupported_grant_type
    auth = build_auth(scopes: ["read"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "read")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "password",
          client_id: client[:client_id],
          client_secret: client[:client_secret]
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/unsupported_grant_type/, error.message)
  end

  def test_client_credentials_rejects_oidc_user_scopes
    auth = build_auth(scopes: ["openid", "profile", "email", "offline_access", "read"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["client_credentials"], response_types: [], scope: "openid profile email offline_access read")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          scope: "openid read"
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/invalid_scope/, error.message)
  end

  def test_client_credentials_uses_configured_default_scopes_when_client_has_none
    auth = build_auth(scopes: ["read", "write"], client_credential_grant_default_scopes: ["read"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["client_credentials"], response_types: [], scope: "read write")
    auth.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: client[:client_id]}], update: {scopes: nil})

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )

    assert_equal "read", tokens[:scope]
  end

  def test_client_credentials_preserves_explicit_empty_client_scopes
    auth = build_auth(scopes: ["read", "write"], client_credential_grant_default_scopes: ["read"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["client_credentials"], response_types: [], scope: "read write")
    auth.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: client[:client_id]}], update: {scopes: []})

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )

    assert_equal "", tokens[:scope]
  end

  def test_resource_defaults_to_base_url_audience_allow_list
    auth = build_auth(scopes: ["read"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["client_credentials"], response_types: [], scope: "read")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          scope: "read",
          resource: "https://evil.example"
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/requested resource invalid/, error.message)
  end

  def test_openid_resource_allows_userinfo_audience
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)

    tokens = issue_authorization_code_tokens(
      auth,
      cookie,
      client,
      scope: "openid",
      resource: "http://localhost:3000/api/auth/oauth2/userinfo"
    )

    assert_equal "http://localhost:3000/api/auth/oauth2/userinfo", tokens[:audience]
  end

  def test_jwt_plugin_signs_jwt_access_tokens_and_introspection_verifies_them
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.jwt(jwks: {key_pair_config: {alg: "EdDSA"}}),
        BetterAuth::Plugins.oauth_provider(scopes: ["read"], allow_dynamic_client_registration: true)
      ]
    )
    cookie = sign_up_cookie(auth, email: "jwt-access@example.com")
    client = create_client(auth, cookie, grant_types: ["client_credentials"], response_types: [], scope: "read")

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read",
        resource: "http://localhost:3000"
      }
    )
    _payload, header = JWT.decode(tokens[:access_token], nil, false)
    active = auth.api.o_auth2_introspect(body: introspect_body(client, tokens[:access_token], hint: "access_token"))

    assert_equal "EdDSA", header["alg"]
    assert_equal true, active[:active]
    assert_equal client[:client_id], active[:client_id]
    assert_equal "read", active[:scope]
  end

  def test_id_token_expiration_is_configurable_in_hs256_fallback
    auth = build_auth(scopes: ["openid"], disable_jwt_plugin: true, id_token_expires_in: 1234)
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")
    payload = decode_id_token(tokens[:id_token], client)

    assert_equal 1234, payload.fetch("exp") - payload.fetch("iat")
  end
end

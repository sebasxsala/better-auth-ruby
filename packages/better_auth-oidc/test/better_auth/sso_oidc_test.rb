# frozen_string_literal: true

require "better_auth/sso"
require "json"
require "jwt"
require "openssl"
require "rack/mock"
require_relative "../test_helper"

class BetterAuthPluginsSSOOIDCTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_oidc_discovery_normalizes_and_validates_document
    discovery = BetterAuth::Plugins.sso_discover_oidc_config(
      issuer: "https://idp.example.com",
      fetch: ->(_url) {
        {
          issuer: "https://idp.example.com",
          authorization_endpoint: "https://idp.example.com/authorize",
          token_endpoint: "https://idp.example.com/token",
          userinfo_endpoint: "https://idp.example.com/userinfo",
          jwks_uri: "https://idp.example.com/jwks"
        }
      }
    )

    assert_equal "https://idp.example.com/authorize", discovery.fetch(:authorization_endpoint)
    assert_equal "https://idp.example.com/token", discovery.fetch(:token_endpoint)

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_discover_oidc_config(
        issuer: "https://idp.example.com",
        fetch: ->(_url) { {issuer: "https://wrong.example.com"} }
      )
    end
    assert_equal 400, error.status_code
    assert_equal "OIDC discovery document is missing required fields: authorization_endpoint, token_endpoint, jwks_uri", error.message
  end

  def test_oidc_discovery_hydrates_relative_urls_and_selects_auth_method
    discovery = BetterAuth::Plugins.sso_discover_oidc_config(
      issuer: "https://idp.example.com/tenant",
      existing_config: {clientId: "configured", tokenEndpointAuthentication: "client_secret_post"},
      trusted_origin: ->(url) { url.start_with?("https://idp.example.com") },
      fetch: ->(url) {
        assert_equal "https://idp.example.com/tenant/.well-known/openid-configuration", url
        {
          issuer: "https://idp.example.com/tenant",
          authorization_endpoint: "authorize",
          token_endpoint: "token",
          jwks_uri: "jwks",
          userinfo_endpoint: "userinfo",
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          scopes_supported: ["openid", "email"]
        }
      }
    )

    assert_equal "configured", discovery.fetch(:client_id)
    assert_equal "client_secret_post", discovery.fetch(:token_endpoint_authentication)
    assert_equal "https://idp.example.com/tenant/authorize", discovery.fetch(:authorization_endpoint)
    assert_equal "https://idp.example.com/tenant/jwks", discovery.fetch(:jwks_endpoint)
    assert_equal ["openid", "email"], discovery.fetch(:scopes_supported)
  end

  def test_oidc_discovery_preserves_issuer_base_path_for_relative_endpoint_urls
    discovery = BetterAuth::Plugins.sso_discover_oidc_config(
      issuer: "https://idp.example.com/base",
      trusted_origin: ->(url) { url.start_with?("https://idp.example.com") },
      fetch: ->(_url) {
        {
          issuer: "https://idp.example.com/base",
          authorization_endpoint: "oauth2/authorize",
          token_endpoint: "oauth2/token",
          jwks_uri: "oauth2/jwks"
        }
      }
    )

    assert_equal "https://idp.example.com/base/oauth2/authorize", discovery.fetch(:authorization_endpoint)
    assert_equal "https://idp.example.com/base/oauth2/token", discovery.fetch(:token_endpoint)
    assert_equal "https://idp.example.com/base/oauth2/jwks", discovery.fetch(:jwks_endpoint)
  end

  def test_oidc_discovery_rejects_untrusted_discovered_urls
    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_discover_oidc_config(
        issuer: "https://idp.example.com",
        trusted_origin: ->(url) { url.start_with?("https://idp.example.com") },
        fetch: ->(_url) {
          {
            issuer: "https://idp.example.com",
            authorization_endpoint: "https://evil.example.com/authorize",
            token_endpoint: "https://idp.example.com/token",
            jwks_uri: "https://idp.example.com/jwks"
          }
        }
      )
    end

    assert_equal 400, error.status_code
    assert_equal "The authorization_endpoint \"https://evil.example.com/authorize\" is not trusted by your trusted origins configuration.", error.message
  end

  def test_oidc_sign_in_hydrates_partial_config_with_runtime_discovery
    discovery_calls = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      trusted_origins: ["https://idp.example.com"],
      plugins: [
        BetterAuth::Plugins.sso(
          oidc_discovery_fetch: ->(url) {
            discovery_calls << url
            {
              issuer: "https://idp.example.com",
              authorization_endpoint: "authorize",
              token_endpoint: "token",
              jwks_uri: "jwks"
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true
        }
      }
    )

    result = auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})
    uri = URI.parse(result.fetch(:url))
    params = Rack::Utils.parse_query(uri.query)

    assert_equal ["https://idp.example.com/.well-known/openid-configuration"], discovery_calls
    assert_equal "https://idp.example.com", "#{uri.scheme}://#{uri.host}"
    assert_equal "/authorize", uri.path
    assert_equal "client-id", params.fetch("client_id")
    assert params.fetch("nonce")
  end

  def test_oidc_callback_rejects_provider_id_mismatch_between_route_and_state
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          getToken: ->(**_data) { raise "token callback should not run" },
          getUserInfo: ->(_tokens) { {id: "oidc-sub", email: "oidc@example.com"} }
        }
      }
    )
    state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")

    status, headers, _body = auth.api.callback_sso(
      params: {providerId: "other-id"},
      query: {code: "good-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard?error=invalid_state&error_description=provider+mismatch", headers.fetch("location")
  end

  def test_oidc_callback_creates_user_session_and_rejects_invalid_state
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          userInfoEndpoint: "https://idp.example.com/userinfo",
          getToken: ->(code:, **_data) {
            raise "unexpected code" unless code == "good-code"

            {accessToken: "access-token", idToken: "id-token"}
          },
          getUserInfo: ->(_tokens) { {id: "oidc-sub", email: "oidc@example.com", name: "OIDC User", emailVerified: true} }
        }
      }
    )
    sign_in = auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard", newUserCallbackURL: "/welcome"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")

    status, headers, _body = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "good-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/welcome", headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    user = auth.context.internal_adapter.find_user_by_email("oidc@example.com")[:user]
    assert_equal "OIDC User", user.fetch("name")

    invalid = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "good-code", state: "bad"},
      as_response: true
    )
    assert_equal 302, invalid.first
    assert_includes invalid[1].fetch("location"), "error=invalid_state"
  end

  def test_oidc_callback_redirects_existing_users_to_callback_url
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
          getToken: ->(**_data) { {accessToken: "access-token"} },
          getUserInfo: ->(_tokens) { {id: "oidc-sub", email: "oidc@example.com", name: "OIDC User"} }
        }
      }
    )

    first_state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard", newUserCallbackURL: "/welcome"})[:url]).query).fetch("state")
    auth.api.callback_sso(params: {providerId: "oidc"}, query: {code: "first", state: first_state}, as_response: true)

    second_state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard", newUserCallbackURL: "/welcome"})[:url]).query).fetch("state")
    status, headers, _body = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "second", state: second_state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
  end

  def test_oidc_callback_overrides_existing_user_info_when_enabled_by_default
    auth = build_auth(default_override_user_info: true, account: {account_linking: {trusted_providers: ["sso:oidc"]}})
    _existing_status, _existing_headers, _existing_body = auth.api.sign_up_email(
      body: {email: "override@example.com", password: "password123", name: "Old Name"},
      as_response: true
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
          getToken: ->(**_data) { {accessToken: "access-token"} },
          getUserInfo: ->(_tokens) { {id: "oidc-sub", email: "override@example.com", name: "New Name", picture: "https://cdn.example.com/new.png", emailVerified: true} }
        }
      }
    )
    state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")
    auth.api.callback_sso(params: {providerId: "oidc"}, query: {code: "code", state: state}, as_response: true)

    user = auth.context.internal_adapter.find_user_by_email("override@example.com").fetch(:user)
    assert_equal "New Name", user.fetch("name")
    assert_equal "https://cdn.example.com/new.png", user.fetch("image")
    refute user.fetch("emailVerified")
  end

  def test_oidc_callback_rejects_missing_required_user_info
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          getToken: ->(**_data) { {accessToken: "access-token"} },
          getUserInfo: ->(_tokens) { {email: "oidc@example.com"} }
        }
      }
    )

    state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")
    status, headers, _body = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "good-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard?error=invalid_provider&error_description=missing_user_info", headers.fetch("location")
    assert_nil auth.context.internal_adapter.find_user_by_email("oidc@example.com")
  end

  def test_oidc_callback_accepts_rs256_id_token_verified_with_jwks
    key = OpenSSL::PKey::RSA.generate(2048)
    token = nil
    jwks_calls = []
    auth = build_auth(
      oidc_jwks_fetch: ->(url) {
        jwks_calls << url
        {keys: [JWT::JWK.new(key.public_key, "rsa-1").export]}
      }
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
          getToken: ->(**_data) { {idToken: token} }
        }
      }
    )

    state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")
    token = oidc_id_token(key, kid: "rsa-1", email: "verified@example.com", nonce: oidc_state_nonce(state))
    status, headers, _body = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "good-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert_equal ["https://idp.example.com/jwks"], jwks_calls
    assert auth.context.internal_adapter.find_user_by_email("verified@example.com")[:user]
  end

  def test_oidc_callback_rejects_id_token_with_wrong_nonce
    key = OpenSSL::PKey::RSA.generate(2048)
    auth = build_auth(
      oidc_jwks_fetch: ->(_url) { {keys: [JWT::JWK.new(key.public_key, "rsa-1").export]} }
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
          getToken: ->(**_data) { {idToken: oidc_id_token(key, kid: "rsa-1", email: "wrong-nonce@example.com", nonce: "wrong-nonce")} }
        }
      }
    )

    state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")
    status, headers, _body = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "good-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard?error=invalid_provider&error_description=token_not_verified", headers.fetch("location")
    assert_nil auth.context.internal_adapter.find_user_by_email("wrong-nonce@example.com")
  end

  def test_oidc_callback_rejects_tampered_id_token
    key = OpenSSL::PKey::RSA.generate(2048)
    tampered = nil
    auth = build_auth(
      oidc_jwks_fetch: ->(_url) { {keys: [JWT::JWK.new(key.public_key, "rsa-1").export]} }
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
          getToken: ->(**_data) { {idToken: tampered} }
        }
      }
    )

    state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")
    token = oidc_id_token(key, kid: "rsa-1", email: "tampered@example.com", nonce: oidc_state_nonce(state))
    tampered = token.sub(/\A[^.]+/) { |header| header.reverse }
    status, headers, _body = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "bad-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard?error=invalid_provider&error_description=token_not_verified", headers.fetch("location")
    assert_nil auth.context.internal_adapter.find_user_by_email("tampered@example.com")
  end

  def test_oidc_callback_rejects_id_token_with_wrong_audience_issuer_or_expiry
    [
      oidc_callback_with_id_token_result(audience: "other-client", email: "wrong-audience@example.com"),
      oidc_callback_with_id_token_result(issuer: "https://evil.example.com", email: "wrong-issuer@example.com"),
      oidc_callback_with_id_token_result(expires_at: Time.now.to_i - 60, email: "expired@example.com")
    ].each do |auth, location, email|
      assert_equal "/dashboard?error=invalid_provider&error_description=token_not_verified", location
      assert_nil auth.context.internal_adapter.find_user_by_email(email)
    end
  end

  def test_oidc_callback_requires_jwks_endpoint_when_using_id_token
    key = OpenSSL::PKey::RSA.generate(2048)
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          getToken: ->(**_data) { {idToken: oidc_id_token(key, kid: "rsa-1")} }
        }
      }
    )

    state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")
    status, headers, _body = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "good-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard?error=invalid_provider&error_description=jwks_endpoint_not_found", headers.fetch("location")
  end

  def test_oidc_callback_hydrates_missing_jwks_endpoint_with_runtime_discovery
    key = OpenSSL::PKey::RSA.generate(2048)
    token = nil
    discovery_calls = []
    jwks_calls = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      trusted_origins: ["https://idp.example.com"],
      plugins: [
        BetterAuth::Plugins.sso(
          oidc_discovery_fetch: ->(url) {
            discovery_calls << url
            {
              issuer: "https://idp.example.com",
              authorization_endpoint: "https://idp.example.com/authorize",
              token_endpoint: "https://idp.example.com/token",
              jwks_uri: "https://idp.example.com/jwks"
            }
          },
          oidc_jwks_fetch: ->(url) {
            jwks_calls << url
            {keys: [JWT::JWK.new(key.public_key, "rsa-1").export]}
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          getToken: ->(**_data) { {idToken: token} }
        }
      }
    )

    state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")
    token = oidc_id_token(key, kid: "rsa-1", email: "discovered-jwks@example.com", nonce: oidc_state_nonce(state))
    status, headers, _body = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "good-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert_equal ["https://idp.example.com/.well-known/openid-configuration"], discovery_calls
    assert_equal ["https://idp.example.com/jwks"], jwks_calls
    assert auth.context.internal_adapter.find_user_by_email("discovered-jwks@example.com")[:user]
  end

  def test_oidc_shared_callback_uses_provider_id_from_state
    auth = build_auth(redirect_uri: "/sso/callback")
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          getToken: ->(**_data) { {accessToken: "access-token"} },
          getUserInfo: ->(_tokens) { {id: "oidc-sub", email: "shared@example.com", name: "Shared Callback"} }
        }
      }
    )
    state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")

    status, headers, _body = auth.api.callback_sso_shared(query: {code: "good-code", state: state}, as_response: true)

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("shared@example.com")
  end

  def test_oidc_callback_respects_disable_implicit_signup_and_request_signup
    auth = build_auth(disable_implicit_sign_up: true)
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          getToken: ->(**_data) { {accessToken: "access-token"} },
          getUserInfo: ->(_tokens) { {id: "oidc-sub", email: "blocked@example.com", name: "Blocked"} }
        }
      }
    )

    blocked_state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")
    blocked = auth.api.callback_sso(params: {providerId: "oidc"}, query: {code: "blocked", state: blocked_state}, as_response: true)

    assert_equal 302, blocked.first
    assert_equal "/dashboard?error=signup+disabled", blocked[1].fetch("location")
    assert_nil auth.context.internal_adapter.find_user_by_email("blocked@example.com")

    allowed_state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard", requestSignUp: true})[:url]).query).fetch("state")
    allowed = auth.api.callback_sso(params: {providerId: "oidc"}, query: {code: "allowed", state: allowed_state}, as_response: true)

    assert_equal 302, allowed.first
    assert_equal "/dashboard", allowed[1].fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("blocked@example.com")
  end

  def test_oidc_callback_runs_provision_user_hook_for_new_users_and_every_login_when_enabled
    provisioned = []
    auth = build_auth(
      provision_user: ->(user:, token:, provider:, **data) {
        user_info = data.fetch(:userInfo)
        provisioned << [user.fetch("email"), user_info.fetch(:id), token.fetch(:access_token), provider.fetch("providerId")]
      },
      provision_user_on_every_login: true
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          getToken: ->(**_data) { {accessToken: "access-token"} },
          getUserInfo: ->(_tokens) { {id: "oidc-sub", email: "provision@example.com", name: "Provisioned"} }
        }
      }
    )

    2.times do
      state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")
      auth.api.callback_sso(params: {providerId: "oidc"}, query: {code: "good-code", state: state}, as_response: true)
    end

    assert_equal 2, provisioned.length
    assert_equal ["provision@example.com", "oidc-sub", "access-token", "oidc"], provisioned.first
  end

  def test_oidc_sign_in_supports_upstream_request_options_and_shared_redirect_uri
    auth = build_auth(redirect_uri: "/sso/callback")
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          pkce: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks"
        }
      }
    )

    sign_in = auth.api.sign_in_sso(
      body: {
        domain: "example.com",
        providerType: "oidc",
        callbackURL: "/dashboard",
        scopes: ["openid", "email"],
        loginHint: "ada@example.com"
      }
    )
    uri = URI.parse(sign_in.fetch(:url))
    params = Rack::Utils.parse_query(uri.query)

    assert_equal "https://idp.example.com/authorize", "#{uri.scheme}://#{uri.host}#{uri.path}"
    assert_equal "http://localhost:3000/api/auth/sso/callback", params.fetch("redirect_uri")
    assert_equal "openid email", params.fetch("scope")
    assert_equal "ada@example.com", params.fetch("login_hint")
    assert params.fetch("code_challenge")
    assert_equal "S256", params.fetch("code_challenge_method")
  end

  def test_oidc_sign_in_rejects_provider_type_mismatch_and_unverified_domain
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.sso(domain_verification: {enabled: true})]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {clientId: "client-id", skipDiscovery: true, authorizationEndpoint: "https://idp.example.com/authorize"}
      }
    )

    unverified = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})
    end
    assert_equal 401, unverified.status_code
    assert_equal "Provider domain has not been verified", unverified.message

    mismatch = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_sso(body: {providerId: "oidc", providerType: "saml", callbackURL: "/dashboard"})
    end
    assert_equal 400, mismatch.status_code
    assert_equal "SAML provider is not configured", mismatch.message
  end

  def test_oidc_sign_in_supports_default_sso_provider
    auth = build_auth(
      default_sso: [
        {
          domain: "example.com",
          providerId: "default-oidc",
          oidcConfig: {
            issuer: "https://idp.example.com",
            clientId: "client-id",
            clientSecret: "client-secret",
            pkce: false,
            authorizationEndpoint: "https://idp.example.com/authorize",
            tokenEndpoint: "https://idp.example.com/token",
            jwksEndpoint: "https://idp.example.com/jwks"
          }
        }
      ]
    )

    sign_in = auth.api.sign_in_sso(body: {email: "ada@example.com", callbackURL: "/dashboard"})
    uri = URI.parse(sign_in.fetch(:url))
    params = Rack::Utils.parse_query(uri.query)

    assert_equal "client-id", params.fetch("client_id")
    assert_equal "http://localhost:3000/api/auth/sso/callback/default-oidc", params.fetch("redirect_uri")
    refute params.key?("code_challenge")
  end

  private

  def build_auth(options = {})
    account = options.delete(:account) || {}
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      account: account,
      plugins: [BetterAuth::Plugins.sso(options)]
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "owner@example.com", password: "password123", name: "Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def oidc_id_token(key, kid:, email: "verified@example.com", issuer: "https://idp.example.com", audience: "client-id", expires_at: Time.now.to_i + 300, nonce: nil)
    JWT.encode(
      {
        sub: "oidc-sub",
        email: email,
        name: "OIDC User",
        iss: issuer,
        aud: audience,
        exp: expires_at,
        nonce: nonce
      }.compact,
      key,
      "RS256",
      {kid: kid}
    )
  end

  def oidc_state_nonce(state)
    BetterAuth::Crypto.verify_jwt(state, SECRET).fetch("nonce")
  end

  def oidc_callback_with_id_token_result(email:, issuer: "https://idp.example.com", audience: "client-id", expires_at: Time.now.to_i + 300)
    key = OpenSSL::PKey::RSA.generate(2048)
    auth = build_auth(
      oidc_jwks_fetch: ->(_url) { {keys: [JWT::JWK.new(key.public_key, "rsa-1").export]} }
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
          getToken: ->(**_data) { {idToken: @oidc_result_token} }
        }
      }
    )
    state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard"})[:url]).query).fetch("state")
    @oidc_result_token = oidc_id_token(key, kid: "rsa-1", email: email, issuer: issuer, audience: audience, expires_at: expires_at, nonce: oidc_state_nonce(state))
    _status, headers, _body = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "bad-code", state: state},
      as_response: true
    )
    [auth, headers.fetch("location"), email]
  end
end

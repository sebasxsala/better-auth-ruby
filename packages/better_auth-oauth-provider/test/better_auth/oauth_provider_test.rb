# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "rack/mock"
require_relative "../test_helper"

class BetterAuthPluginsOAuthProviderTest < Minitest::Test
  SECRET = "phase-eleven-secret-with-enough-entropy-123"

  def test_validate_issuer_url_matches_rfc_9207_upstream_behavior
    assert_equal "https://issuer.example.com", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("https://issuer.example.com/")
    assert_equal "https://issuer.example.com/auth", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://issuer.example.com/auth?x=1#frag")
    assert_equal "http://localhost:3000", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://localhost:3000/")
    assert_equal "http://127.0.0.1:3000", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://127.0.0.1:3000/")
  end

  def test_schema_is_self_contained_and_does_not_register_core_oidc_application_table
    auth = build_auth
    schema = BetterAuth::Schema.auth_tables(auth.options)

    assert schema.key?("oauthClient")
    assert schema.key?("oauthAccessToken")
    assert schema.key?("oauthRefreshToken")
    assert schema.key?("oauthConsent")
    refute schema.key?("oauthApplication")
  end

  def test_plugin_exposes_upstream_rate_limit_rules
    plugin = BetterAuth::Plugins.oauth_provider(
      rate_limit: {
        token: {window: 15, max: 2},
        userinfo: false
      }
    )

    rules = plugin.rate_limit
    paths = rules.map { |rule| oauth_rate_limit_path(rule) }

    assert_equal [
      "/oauth2/token",
      "/oauth2/authorize",
      "/oauth2/introspect",
      "/oauth2/revoke",
      "/oauth2/register",
      "/oauth2/continue",
      "/oauth2/consent",
      "/oauth2/end-session"
    ], paths
    token_rule = rules.fetch(0)
    assert_equal 15, token_rule[:window]
    assert_equal 2, token_rule[:max]
    assert_equal({window: 60, max: 30}, rules.fetch(1).slice(:window, :max))
    assert_equal({window: 60, max: 100}, rules.fetch(2).slice(:window, :max))
    assert_equal({window: 60, max: 30}, rules.fetch(3).slice(:window, :max))
    assert_equal({window: 60, max: 5}, rules.fetch(4).slice(:window, :max))
  end

  def test_plugin_exposes_package_version_like_upstream
    plugin = BetterAuth::Plugins.oauth_provider(login_page: "/login", consent_page: "/consent")

    assert_equal BetterAuth::OAuthProvider::VERSION, plugin.version
  end

  def test_oauth_authorization_server_metadata_excludes_none_when_unauthenticated_disabled
    auth = build_auth(scopes: ["openid", "profile", "email"])
    metadata = auth.api.get_o_auth_server_config

    refute_includes metadata[:token_endpoint_auth_methods_supported], "none"
    assert_includes metadata[:token_endpoint_auth_methods_supported], "client_secret_basic"
    assert_includes metadata[:token_endpoint_auth_methods_supported], "client_secret_post"
  end

  def test_oauth_authorization_server_metadata_includes_none_when_unauthenticated_enabled
    auth = build_auth(allow_unauthenticated_client_registration: true)

    assert_includes auth.api.get_o_auth_server_config[:token_endpoint_auth_methods_supported], "none"
  end

  def test_oidc_metadata_uses_jwt_plugin_alg_when_available
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.jwt(jwks: {key_pair_config: {alg: "EdDSA"}}),
        BetterAuth::Plugins.oauth_provider(scopes: ["openid"], allow_dynamic_client_registration: true)
      ]
    )

    assert_equal ["EdDSA"], auth.api.get_open_id_config[:id_token_signing_alg_values_supported]
  end

  def test_oidc_metadata_advertises_prompt_none
    auth = build_auth(scopes: ["openid"])

    assert_includes auth.api.get_open_id_config[:prompt_values_supported], "none"
  end

  def test_access_token_schema_matches_upstream_canonical_columns
    fields = BetterAuth::Schema.auth_tables(build_auth.options).fetch("oauthAccessToken")[:fields].keys

    assert_includes fields, "token"
    assert_includes fields, "expiresAt"
    assert_includes fields, "scopes"
    refute_includes fields, "accessToken"
    refute_includes fields, "refreshToken"
    refute_includes fields, "accessTokenExpiresAt"
    refute_includes fields, "scope"
  end

  def test_oauth_hot_path_schema_fields_are_indexed
    schema = BetterAuth::Schema.auth_tables(build_auth.options)

    assert_equal true, schema.fetch("oauthClient")[:fields].fetch("userId")[:index]
    assert_equal true, schema.fetch("oauthClient")[:fields].fetch("referenceId")[:index]
    assert_equal true, schema.fetch("oauthConsent")[:fields].fetch("clientId")[:index]
    assert_equal true, schema.fetch("oauthConsent")[:fields].fetch("userId")[:index]
    assert_equal true, schema.fetch("oauthConsent")[:fields].fetch("referenceId")[:index]
    assert_equal true, schema.fetch("oauthRefreshToken")[:fields].fetch("clientId")[:index]
    assert_equal true, schema.fetch("oauthRefreshToken")[:fields].fetch("userId")[:index]
    assert_equal true, schema.fetch("oauthAccessToken")[:fields].fetch("clientId")[:index]
    assert_equal true, schema.fetch("oauthAccessToken")[:fields].fetch("userId")[:index]
    assert_equal true, schema.fetch("oauthAccessToken")[:fields].fetch("refreshId")[:index]
  end

  def test_consent_schema_drops_consent_given_column
    fields = BetterAuth::Schema.auth_tables(build_auth.options).fetch("oauthConsent")[:fields].keys

    refute_includes fields, "consentGiven"
  end

  def test_metadata_client_management_introspection_and_revocation
    auth = build_auth
    cookie = sign_up_cookie(auth)

    metadata = auth.api.get_o_auth_server_config
    assert_equal "http://localhost:3000", metadata[:issuer]
    assert_equal "http://localhost:3000/api/auth/oauth2/introspect", metadata[:introspection_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/revoke", metadata[:revocation_endpoint]
    assert_includes metadata[:grant_types_supported], "client_credentials"

    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Machine Client",
        scope: "read write"
      }
    )
    assert client[:client_id]
    assert client[:client_secret]

    public_client = auth.api.get_o_auth_client_public(query: {client_id: client[:client_id]})
    assert_equal "Machine Client", public_client[:client_name]
    assert_nil public_client[:client_secret]

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read"
      }
    )
    assert_equal "Bearer", tokens[:token_type]
    assert tokens[:access_token]
    assert_equal "read", tokens[:scope]

    active = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal true, active[:active]
    assert_equal client[:client_id], active[:client_id]
    assert_equal "read", active[:scope]

    revoke = auth.api.o_auth2_revoke(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal({revoked: true}, revoke)

    inactive = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal false, inactive[:active]
  end

  def test_dynamic_registration_requires_explicit_enablement
    auth = build_auth(allow_dynamic_client_registration: false)
    cookie = sign_up_cookie(auth)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_client(
        headers: {"cookie" => cookie},
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "none",
          client_name: "Public Client"
        }
      )
    end

    assert_equal 403, error.status_code
  end

  def test_unauthenticated_dynamic_registration_is_coerced_to_public_client
    auth = build_auth(
      scopes: ["openid", "profile", "email", "offline_access"],
      allow_unauthenticated_client_registration: true,
      client_registration_default_scopes: ["openid", "profile"],
      client_registration_allowed_scopes: ["openid", "profile", "email"],
      store_client_secret: "hashed"
    )

    status, headers, body = auth.api.register_o_auth_client(
      body: {
        client_id: "attacker-controlled-id",
        client_secret: "attacker-controlled-secret",
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Public Browser Client",
        scope: "openid email",
        type: "web",
        metadata: {software_id: "client-kit"},
        tos_uri: "https://resource.example/terms"
      },
      as_response: true
    )

    assert_equal 201, status
    assert_equal "no-store", headers.fetch("cache-control")
    assert_equal "no-cache", headers.fetch("pragma")
    client = JSON.parse(body.join, symbolize_names: true)
    refute_equal "attacker-controlled-id", client[:client_id]
    assert_nil client[:client_secret]
    refute client.key?(:client_secret_expires_at)
    assert_equal "none", client[:token_endpoint_auth_method]
    assert_equal true, client[:public]
    assert_nil client[:user_id]
    assert_nil client[:type]
    assert_equal "openid email", client[:scope]
    assert_equal "client-kit", client[:software_id]
    assert_equal "https://resource.example/terms", client[:tos_uri]
    refute client.key?(:skip_consent)
  end

  def test_dynamic_registration_omitted_scope_uses_provider_scopes
    auth = build_auth(scopes: ["openid", "profile"], allow_unauthenticated_client_registration: true)

    client = auth.api.register_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Default Scope Client"
      }
    )

    assert_equal "openid profile", client[:scope]
  end

  def test_dynamic_registration_defaults_require_pkce_to_true
    auth = build_auth(allow_unauthenticated_client_registration: true)

    client = auth.api.register_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"]
      }
    )

    assert_equal true, client[:require_pkce]
  end

  def test_dynamic_registration_rejects_skip_consent
    auth = build_auth(allow_unauthenticated_client_registration: true)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_client(
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code"],
          response_types: ["code"],
          skip_consent: true
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/skip_consent/i, error.message)
  end

  def test_unauthenticated_dynamic_registration_rejects_confidential_grants
    auth = build_auth(allow_unauthenticated_client_registration: true)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_client(
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "none",
          grant_types: ["client_credentials"],
          response_types: []
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/public/i, error.message)
  end

  def test_dynamic_registration_rejects_invalid_client_metadata_enums
    auth = build_auth(allow_unauthenticated_client_registration: true)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_client(
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "private_key_jwt",
          grant_types: ["authorization_code"],
          response_types: ["code"]
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/token_endpoint_auth_method/i, error.message)
  end

  def test_authorization_code_flow_requires_and_records_consent
    auth = build_auth(consent_page: "/consent")
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Browser Client",
        scope: "read write"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-123",
        prompt: "consent",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    consent_redirect = URI.parse(headers.fetch("location"))
    assert_equal "/consent", consent_redirect.path
    consent_code = Rack::Utils.parse_query(consent_redirect.query).fetch("consent_code")

    consent = auth.api.o_auth2_consent(
      headers: {"cookie" => cookie},
      body: {accept: true, consent_code: consent_code}
    )
    callback = URI.parse(consent.fetch(:redirectURI))
    params = Rack::Utils.parse_query(callback.query)
    assert_equal "state-123", params.fetch("state")
    assert_equal "http://localhost:3000", params.fetch("iss")
    assert params.fetch("code")

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: params.fetch("code"),
        redirect_uri: "https://resource.example/callback",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        code_verifier: pkce_verifier
      }
    )
    assert_equal "Bearer", tokens[:token_type]
    assert_equal "read", tokens[:scope]
    assert_nil tokens[:refresh_token]

    consent_record = auth.context.adapter.find_one(model: "oauthConsent", where: [{field: "clientId", value: client[:client_id]}])
    assert_equal ["read"], consent_record.fetch("scopes")
  end

  def test_consent_can_grant_narrower_scope_set
    auth = build_auth(scopes: ["read", "write"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Narrow Consent Client",
        scope: "read write"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read write",
        state: "narrow-state",
        prompt: "consent",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    consent_code = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query).fetch("consent_code")

    consent = auth.api.o_auth2_consent(
      headers: {"cookie" => cookie},
      body: {accept: true, consent_code: consent_code, scope: "read"}
    )
    code = Rack::Utils.parse_query(URI.parse(consent.fetch(:redirectURI)).query).fetch("code")
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

    assert_equal "read", tokens[:scope]
    saved = auth.api.get_o_auth_consent(headers: {"cookie" => cookie}, query: {client_id: client[:client_id]})
    assert_equal ["read"], saved[:scopes]
  end

  def test_continue_created_reenters_authorize_from_signed_oauth_query
    auth = build_auth(signup: {page: "/signup"}, consent_page: "/consent")
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Continue Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "continue-state",
        prompt: "create consent",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    signup_uri = URI.parse(headers.fetch("location"))
    assert_equal "/signup", signup_uri.path
    signup_params = Rack::Utils.parse_query(signup_uri.query)
    assert signup_params["sig"]
    assert signup_params["exp"]

    continued = auth.api.o_auth2_continue(
      headers: {"cookie" => cookie},
      body: {created: true, oauth_query: signup_uri.query}
    )

    assert_equal true, continued[:redirect]
    redirect_uri = URI.parse(continued[:url])
    assert_equal "/consent", redirect_uri.path
    assert_equal client[:client_id], Rack::Utils.parse_query(redirect_uri.query).fetch("client_id")
  end

  def test_continue_selected_reenters_authorize_and_issues_code
    auth = build_auth(select_account: {page: "/select-account"})
    cookie = sign_up_cookie(auth)
    client = auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Select Account Client",
        scope: "read",
        skip_consent: true
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "select-state",
        prompt: "select_account",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    select_uri = URI.parse(headers.fetch("location"))
    assert_equal "/select-account", select_uri.path

    continued = auth.api.o_auth2_continue(
      headers: {"cookie" => cookie},
      body: {selected: true, oauth_query: select_uri.query}
    )

    callback = URI.parse(continued[:url])
    params = Rack::Utils.parse_query(callback.query)
    assert_equal "select-state", params.fetch("state")
    assert params.fetch("code")
  end

  def test_continue_post_login_reenters_authorize_and_issues_code
    auth = build_auth(
      post_login: {
        page: "/post-login",
        should_redirect: ->(_info) { true }
      }
    )
    cookie = sign_up_cookie(auth)
    client = auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Post Login Client",
        scope: "read",
        skip_consent: true
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "post-login-state",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    post_login_uri = URI.parse(headers.fetch("location"))
    assert_equal "/post-login", post_login_uri.path

    continued = auth.api.o_auth2_continue(
      headers: {"cookie" => cookie},
      body: {postLogin: true, oauth_query: post_login_uri.query}
    )

    callback = URI.parse(continued[:url])
    params = Rack::Utils.parse_query(callback.query)
    assert_equal "post-login-state", params.fetch("state")
    assert params.fetch("code")
  end

  def test_authorize_requires_pkce_by_default
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Public Browser Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-pkce"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "invalid_request", params.fetch("error")
    assert_match(/pkce/i, params.fetch("error_description"))
    assert_equal "state-pkce", params.fetch("state")
  end

  def test_confidential_authorize_requires_pkce_by_default
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Confidential Browser Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-confidential-pkce"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "invalid_request", params.fetch("error")
    assert_match(/pkce/i, params.fetch("error_description"))
  end

  def test_dynamic_registration_rejects_pkce_opt_out
    auth = build_auth
    cookie = sign_up_cookie(auth)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_client(
        headers: {"cookie" => cookie},
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "client_secret_post",
          grant_types: ["authorization_code"],
          response_types: ["code"],
          client_name: "Confidential Browser Client",
          scope: "read",
          require_pkce: false
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/pkce/i, error.message)
  end

  def test_authorize_rejects_scopes_outside_client_registration
    auth = build_auth(scopes: ["read", "write"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Scoped Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "write",
        state: "state-scope",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "invalid_scope", params.fetch("error")
  end

  def test_authorize_rejects_plain_pkce_challenge_method
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Public Browser Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-pkce",
        code_challenge: "plain-verifier",
        code_challenge_method: "plain"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "invalid_request", params.fetch("error")
    assert_match(/S256/i, params.fetch("error_description"))
  end

  def test_openid_metadata_is_not_available_without_openid_scope
    auth = build_auth(scopes: ["read"])

    error = assert_raises(BetterAuth::APIError) do
      auth.api.get_open_id_config
    end

    assert_equal 404, error.status_code
  end

  def test_metadata_supports_advertised_overrides_and_cache_headers
    auth = build_auth(
      scopes: ["openid", "profile", "email"],
      advertised_metadata: {
        scopes_supported: ["openid", "profile"],
        claims_supported: ["sub", "name"]
      }
    )

    status, headers, body = auth.api.get_open_id_config(as_response: true)
    metadata = JSON.parse(body.join, symbolize_names: true)

    assert_equal 200, status
    assert_equal "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400", headers.fetch("cache-control")
    refute metadata.key?(:jwks_uri)
    assert_equal ["openid", "profile"], metadata[:scopes_supported]
    assert_equal ["sub", "name"], metadata[:claims_supported]
  end

  def test_metadata_advertises_configured_jwks_uri_only_when_available
    auth = build_auth(
      scopes: ["openid"],
      advertised_metadata: {
        jwks_uri: "https://issuer.example/.well-known/jwks.json"
      }
    )

    metadata = auth.api.get_open_id_config
    server_metadata = auth.api.get_o_auth_server_config

    assert_equal "https://issuer.example/.well-known/jwks.json", metadata[:jwks_uri]
    assert_equal "https://issuer.example/.well-known/jwks.json", server_metadata[:jwks_uri]
  end

  def test_userinfo_requires_openid_scope
    auth = build_auth(scopes: ["openid", "profile", "email"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Machine Client",
        scope: "profile email"
      }
    )

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "profile email")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_user_info(headers: {"authorization" => "Bearer #{tokens[:access_token]}"})
    end

    assert_equal 400, error.status_code
  end

  def test_userinfo_returns_standard_openid_profile_and_email_claims
    auth = build_auth(scopes: ["openid", "profile", "email"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Browser Client",
        scope: "openid profile email"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "openid profile email",
        state: "state-userinfo",
        prompt: "consent",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    consent_code = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query).fetch("consent_code")
    consent = auth.api.o_auth2_consent(
      headers: {"cookie" => cookie},
      body: {accept: true, consent_code: consent_code}
    )
    code = Rack::Utils.parse_query(URI.parse(consent.fetch(:redirectURI)).query).fetch("code")
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

    userinfo = auth.api.o_auth2_user_info(headers: {"authorization" => "Bearer #{tokens[:access_token]}"})

    assert userinfo[:sub]
    assert_equal "OAuth Owner", userinfo[:name]
    assert_equal "oauth-provider@example.com", userinfo[:email]
    assert_equal false, userinfo[:email_verified]
  end

  def test_token_prefixes_are_returned_and_respected_by_introspection
    auth = build_auth(
      scopes: ["openid", "offline_access"],
      prefix: {
        opaque_access_token: "hello_at_",
        refresh_token: "hello_rt_",
        client_secret: "hello_cs_"
      }
    )
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Prefixed Client",
        scope: "openid offline_access"
      }
    )
    assert client[:client_secret].start_with?("hello_cs_")

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access")
    assert tokens[:access_token].start_with?("hello_at_")
    assert tokens[:refresh_token].start_with?("hello_rt_")

    access = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal true, access[:active]
    assert_equal "openid offline_access", access[:scope]

    refresh = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:refresh_token],
        token_type_hint: "refresh_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal true, refresh[:active]
    assert_equal "openid offline_access", refresh[:scope]

    wrong_hint = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "refresh_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal false, wrong_hint[:active]
  end

  def test_refresh_token_rotation_prevents_replay_and_reduces_scopes
    auth = build_auth(scopes: ["openid", "profile", "offline_access"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Refresh Client",
        scope: "openid profile offline_access"
      }
    )
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile offline_access")

    refreshed = auth.api.o_auth2_token(
      body: {
        grant_type: "refresh_token",
        refresh_token: tokens[:refresh_token],
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "openid"
      }
    )
    assert refreshed[:refresh_token]
    assert_equal "openid", refreshed[:scope]

    replay_error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "refresh_token",
          refresh_token: tokens[:refresh_token],
          client_id: client[:client_id],
          client_secret: client[:client_secret]
        }
      )
    end
    assert_equal 400, replay_error.status_code
    assert_match(/invalid_grant/i, replay_error.message)

    cascade_error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "refresh_token",
          refresh_token: refreshed[:refresh_token],
          client_id: client[:client_id],
          client_secret: client[:client_secret]
        }
      )
    end
    assert_equal 400, cascade_error.status_code
  end

  def test_refresh_token_rejects_authenticated_client_mismatch
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    client_a = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Refresh Client A",
        scope: "openid offline_access"
      }
    )
    client_b = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Refresh Client B",
        scope: "openid offline_access"
      }
    )
    tokens = issue_authorization_code_tokens(auth, cookie, client_a, scope: "openid offline_access")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(body: refresh_grant_body(client_b, tokens[:refresh_token]))
    end

    assert_equal 400, error.status_code
    assert_match(/invalid_grant/i, error.message)
  end

  def test_id_token_includes_nonce_and_preserves_auth_time_after_refresh
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "OIDC Refresh Client",
        scope: "openid offline_access"
      }
    )

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access", nonce: "nonce-123")
    id_token = decode_id_token(tokens[:id_token], client)

    assert_equal "nonce-123", id_token["nonce"]
    assert_kind_of Integer, id_token["auth_time"]

    refreshed = auth.api.o_auth2_token(
      body: {
        grant_type: "refresh_token",
        refresh_token: tokens[:refresh_token],
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "openid offline_access"
      }
    )
    refreshed_id_token = decode_id_token(refreshed[:id_token], client)
    assert_equal id_token["auth_time"], refreshed_id_token["auth_time"]
  end

  def test_id_token_is_not_signed_with_public_client_id
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid"
      }
    )
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    assert_raises(JWT::VerificationError) do
      JWT.decode(tokens[:id_token], client[:client_id], true, algorithm: "HS256")
    end
    assert_equal client[:client_id], decode_id_token(tokens[:id_token], client)["aud"]
  end

  def test_token_endpoint_rejects_grants_not_registered_for_client
    auth = build_auth(allow_public_client_prelogin: true)
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Authorization Code Only Client",
        scope: "read"
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

    assert_equal 400, error.status_code
    assert_match(/unsupported_grant_type/i, error.message)
  end

  def test_token_endpoint_validates_requested_resource_audience
    auth = build_auth(scopes: ["read"], valid_audiences: ["https://api.example"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Resource Client",
        scope: "read"
      }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          scope: "read",
          resource: "https://wrong.example"
        }
      )
    end
    assert_equal 400, error.status_code
    assert_match(/resource/i, error.message)

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read",
        resource: "https://api.example"
      }
    )
    assert_equal "https://api.example", tokens[:audience]
  end

  def test_resource_request_issues_jwt_access_token_with_pinned_claims
    auth = build_auth(
      scopes: ["read"],
      valid_audiences: ["https://api.example"],
      custom_access_token_claims: ->(_info) { {tenant: "acme", aud: "https://evil.example", scope: "evil"} }
    )
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "JWT Resource Client",
        scope: "read"
      }
    )

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read",
        resource: "https://api.example"
      }
    )
    refute tokens[:access_token].start_with?("ba_at_")

    payload = JWT.decode(tokens[:access_token], SECRET, true, algorithm: "HS256").first
    assert_equal "https://api.example", payload["aud"]
    assert_equal client[:client_id], payload["azp"]
    assert_equal "read", payload["scope"]
    assert_equal "acme", payload["tenant"]

    active = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal true, active[:active]
    assert_equal client[:client_id], active[:client_id]
    assert_equal "read", active[:scope]
    assert_equal "https://api.example", active[:aud]
  end

  def test_custom_token_response_and_userinfo_claims
    auth = build_auth(
      scopes: ["openid", "profile"],
      custom_token_response_fields: ->(info) { {tenant: "acme", grant: info[:grant_type]} },
      custom_user_info_claims: ->(info) { {roles: ["admin"], requested: info[:scopes]} }
    )
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Custom Claims Client",
        scope: "openid profile"
      }
    )

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile")
    assert_equal "acme", tokens[:tenant]
    assert_equal "authorization_code", tokens[:grant]

    userinfo = auth.api.o_auth2_user_info(headers: {"authorization" => "Bearer #{tokens[:access_token]}"})
    assert_equal ["admin"], userinfo[:roles]
    assert_equal ["openid", "profile"], userinfo[:requested]
  end

  def test_pairwise_subjects_are_client_specific
    auth = build_auth(scopes: ["openid"], pairwise_secret: "pairwise-secret-with-enough-entropy-123")
    cookie = sign_up_cookie(auth)
    client_a = auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://a.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Pairwise A",
        scope: "openid",
        subject_type: "pairwise"
      }
    )
    client_b = auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://b.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Pairwise B",
        scope: "openid",
        subject_type: "pairwise"
      }
    )

    tokens_a = issue_authorization_code_tokens(auth, cookie, client_a, scope: "openid", redirect_uri: "https://a.example/callback")
    tokens_b = issue_authorization_code_tokens(auth, cookie, client_b, scope: "openid", redirect_uri: "https://b.example/callback")
    sub_a = decode_id_token(tokens_a[:id_token], client_a).fetch("sub")
    sub_b = decode_id_token(tokens_b[:id_token], client_b).fetch("sub")

    refute_equal sub_a, sub_b
    refute_equal auth.context.adapter.find_one(model: "user", where: [{field: "email", value: "oauth-provider@example.com"}]).fetch("id"), sub_a

    userinfo = auth.api.o_auth2_user_info(headers: {"authorization" => "Bearer #{tokens_a[:access_token]}"})
    assert_equal sub_a, userinfo[:sub]
  end

  def test_end_session_validates_id_token_and_redirects_to_registered_logout_uri
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        post_logout_redirect_uris: ["https://resource.example/logout"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Logout Client",
        scope: "openid",
        enable_end_session: true
      }
    )
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    status, headers, = auth.api.o_auth2_end_session(
      query: {
        id_token_hint: tokens[:id_token],
        post_logout_redirect_uri: "https://resource.example/logout",
        state: "logout-state"
      },
      as_response: true
    )

    assert_equal 302, status
    redirect = URI.parse(headers.fetch("location"))
    assert_equal "https://resource.example/logout", "#{redirect.scheme}://#{redirect.host}#{redirect.path}"
    assert_equal "logout-state", Rack::Utils.parse_query(redirect.query).fetch("state")
  end

  def test_end_session_rejects_clients_without_logout_enabled
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        post_logout_redirect_uris: ["https://resource.example/logout"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Logout Client",
        scope: "openid"
      }
    )
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_end_session(
        query: {
          id_token_hint: tokens[:id_token],
          post_logout_redirect_uri: "https://resource.example/logout"
        }
      )
    end

    assert_equal 401, error.status_code
  end

  def test_client_management_enforces_ownership_updates_and_rotates_secret
    auth = build_auth(prefix: {client_secret: "rot_"})
    owner_cookie = sign_up_cookie(auth)
    other_cookie = sign_up_cookie(auth, email: "other-oauth-owner@example.com")
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => owner_cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Original Client",
        scope: "read"
      }
    )

    ownership_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_o_auth_client(headers: {"cookie" => other_cookie}, params: {id: client[:client_id]})
    end
    assert_equal 404, ownership_error.status_code

    updated = auth.api.update_o_auth_client(
      headers: {"cookie" => owner_cookie},
      body: {
        client_id: client[:client_id],
        update: {client_name: "Updated Client", scope: "read write"}
      }
    )
    assert_equal "Updated Client", updated[:client_name]
    assert_nil updated[:client_secret]
    assert_equal "read write", updated[:scope]

    rotated = auth.api.rotate_o_auth_client_secret(
      headers: {"cookie" => owner_cookie},
      body: {client_id: client[:client_id]}
    )
    assert rotated[:client_secret].start_with?("rot_")
    refute_equal client[:client_secret], rotated[:client_secret]

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
  end

  def test_oauth2_get_client_uses_query_param_like_upstream
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "client-paths@example.com")
    client = auth.api.create_o_auth_client(headers: {"cookie" => cookie}, body: {redirect_uris: ["https://example.com/cb"]})

    fetched = auth.api.get_o_auth_client(headers: {"cookie" => cookie}, query: {client_id: client[:client_id]})

    assert_equal client[:client_id], fetched[:client_id]
  end

  def test_oauth2_get_clients_returns_owned_clients
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "list-clients@example.com")
    auth.api.create_o_auth_client(headers: {"cookie" => cookie}, body: {redirect_uris: ["https://example.com/cb"]})

    assert_equal 1, auth.api.get_o_auth_clients(headers: {"cookie" => cookie}).length
  end

  def test_oauth2_update_client_post_with_update_envelope
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "update-paths@example.com")
    client = auth.api.create_o_auth_client(headers: {"cookie" => cookie}, body: {redirect_uris: ["https://example.com/cb"]})

    updated = auth.api.update_o_auth_client(
      headers: {"cookie" => cookie},
      body: {client_id: client[:client_id], update: {client_name: "renamed"}}
    )

    assert_equal "renamed", updated[:client_name]
  end

  def test_oauth2_delete_client_post_with_client_id_body
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "delete-paths@example.com")
    client = auth.api.create_o_auth_client(headers: {"cookie" => cookie}, body: {redirect_uris: ["https://example.com/cb"]})

    deleted = auth.api.delete_o_auth_client(headers: {"cookie" => cookie}, body: {client_id: client[:client_id]})

    assert_equal({deleted: true}, deleted)
  end

  def test_oauth2_public_client_endpoint_returns_public_fields_only
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "public-fields@example.com")
    client = auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {redirect_uris: ["https://example.com/cb"], client_name: "Public Test"}
    )

    body = auth.api.get_o_auth_client_public(headers: {"cookie" => cookie}, query: {client_id: client[:client_id]})

    assert_equal "Public Test", body[:client_name]
    refute body.key?(:client_secret)
    refute body.key?(:redirect_uris)
  end

  def test_admin_create_oauth_client_is_server_only
    auth = build_auth

    status, _headers, _body = auth.handler.call(rack_env("POST", "/api/auth/admin/oauth2/create-client", body: {redirect_uris: ["https://admin.example.com/cb"]}))
    assert_equal 403, status

    client = auth.api.admin_create_o_auth_client(body: {redirect_uris: ["https://admin.example.com/cb"], client_secret_expires_at: 0})
    assert_equal 0, client[:client_secret_expires_at]
    assert_equal ["https://admin.example.com/cb"], client[:redirect_uris]
  end

  def test_rotate_client_secret_returns_full_response_with_expires_at
    auth = build_auth(prefix: {client_secret: "rot_"})
    cookie = sign_up_cookie(auth, email: "rotate-secret@example.com")
    client = auth.api.create_o_auth_client(headers: {"cookie" => cookie}, body: {redirect_uris: ["https://example.com/cb"]})

    rotated = auth.api.rotate_o_auth_client_secret(headers: {"cookie" => cookie}, body: {client_id: client[:client_id]})

    assert_equal client[:client_id], rotated[:client_id]
    assert rotated[:client_secret].start_with?("rot_")
    assert_equal 0, rotated[:client_secret_expires_at]
  end

  def test_user_create_client_does_not_require_dynamic_registration
    auth = build_auth(allow_dynamic_client_registration: false)
    cookie = sign_up_cookie(auth)

    client = auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "User Created Client",
        scope: "read",
        skip_consent: true,
        require_pkce: false
      }
    )

    assert_equal "User Created Client", client[:client_name]
    assert_equal true, client[:skip_consent]
    assert_equal false, client[:require_pkce]
    assert client[:user_id]
  end

  def test_client_privileges_can_block_management_actions
    auth = build_auth(client_privileges: ->(info) { info[:action] != "create" })
    cookie = sign_up_cookie(auth)

    create_error = assert_raises(BetterAuth::APIError) do
      auth.api.create_o_auth_client(
        headers: {"cookie" => cookie},
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "client_secret_post",
          grant_types: ["client_credentials"],
          response_types: [],
          client_name: "Blocked Client",
          scope: "read"
        }
      )
    end
    assert_equal 401, create_error.status_code

    restricted_auth = build_auth(client_privileges: ->(info) { info[:action] != "rotate" })
    restricted_cookie = sign_up_cookie(restricted_auth)
    client = restricted_auth.api.create_o_auth_client(
      headers: {"cookie" => restricted_cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Rotate Blocked Client",
        scope: "read"
      }
    )

    rotate_error = assert_raises(BetterAuth::APIError) do
      restricted_auth.api.rotate_o_auth_client_secret(
        headers: {"cookie" => restricted_cookie},
        body: {client_id: client[:client_id]}
      )
    end
    assert_equal 401, rotate_error.status_code
  end

  def test_public_client_prelogin_returns_only_public_client_fields
    auth = build_auth(allow_public_client_prelogin: true)
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Public View Client",
        client_uri: "https://resource.example",
        logo_uri: "https://resource.example/icon.png",
        scope: "read"
      }
    )
    signed_query = BetterAuth::Plugins.oauth_signed_query(
      Struct.new(:context, keyword_init: true).new(context: auth.context),
      {
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        response_type: "code",
        scope: "read"
      }
    )

    public_client = auth.api.get_o_auth_client_public_prelogin(body: {client_id: client[:client_id], oauth_query: signed_query})

    assert_equal client[:client_id], public_client[:client_id]
    assert_equal "Public View Client", public_client[:client_name]
    assert_equal "https://resource.example", public_client[:client_uri]
    assert_equal "https://resource.example/icon.png", public_client[:logo_uri]
    assert_nil public_client[:client_secret]
    refute public_client.key?(:redirect_uris)
  end

  def test_consent_management_lists_updates_and_deletes_user_consent
    auth = build_auth(scopes: ["openid", "profile"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Consent Client",
        scope: "openid profile"
      }
    )
    issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile")

    listed = auth.api.list_o_auth_consents(headers: {"cookie" => cookie})
    assert_equal [client[:client_id]], listed.map { |consent| consent[:client_id] }

    consent = auth.api.get_o_auth_consent(headers: {"cookie" => cookie}, query: {client_id: client[:client_id]})
    assert_equal "openid profile", consent[:scope]

    updated = auth.api.update_o_auth_consent(
      headers: {"cookie" => cookie},
      body: {client_id: client[:client_id], scopes: ["openid"]}
    )
    assert_equal "openid", updated[:scope]

    deleted = auth.api.delete_o_auth_consent(headers: {"cookie" => cookie}, body: {client_id: client[:client_id]})
    assert_equal({deleted: true}, deleted)
    assert_equal [], auth.api.list_o_auth_consents(headers: {"cookie" => cookie})
  end

  def test_get_oauth_consent_uses_id_query_param
    auth = build_auth(scopes: ["openid", "profile"])
    cookie = sign_up_cookie(auth, email: "consent-id@example.com")
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope: "openid profile"
      }
    )
    issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile")
    consent_id = auth.context.adapter.find_one(model: "oauthConsent", where: [{field: "clientId", value: client[:client_id]}]).fetch("id")

    consent = auth.api.get_o_auth_consent(headers: {"cookie" => cookie}, query: {id: consent_id})

    assert_equal client[:client_id], consent[:client_id]
  end

  def test_get_oauth_consents_returns_user_consents
    auth = build_auth(scopes: ["openid", "profile"])
    cookie = sign_up_cookie(auth, email: "consents-list@example.com")
    2.times do |index|
      client = auth.api.register_o_auth_client(
        headers: {"cookie" => cookie},
        body: {
          redirect_uris: ["https://resource#{index}.example/callback"],
          token_endpoint_auth_method: "client_secret_post",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          scope: "openid profile"
        }
      )
      issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile", redirect_uri: "https://resource#{index}.example/callback")
    end

    assert_equal 2, auth.api.get_o_auth_consents(headers: {"cookie" => cookie}).length
  end

  def test_update_oauth_consent_post_with_id_envelope
    auth = build_auth(scopes: ["openid", "profile", "email"])
    cookie = sign_up_cookie(auth, email: "consent-update@example.com")
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope: "openid profile email"
      }
    )
    issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile email")
    consent_id = auth.context.adapter.find_one(model: "oauthConsent", where: [{field: "clientId", value: client[:client_id]}]).fetch("id")

    updated = auth.api.update_o_auth_consent(headers: {"cookie" => cookie}, body: {id: consent_id, update: {scopes: ["openid"]}})

    assert_equal ["openid"], updated[:scopes]
  end

  def test_delete_oauth_consent_post_with_id_body
    auth = build_auth(scopes: ["openid", "profile"])
    cookie = sign_up_cookie(auth, email: "consent-delete@example.com")
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope: "openid profile"
      }
    )
    issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile")
    consent_id = auth.context.adapter.find_one(model: "oauthConsent", where: [{field: "clientId", value: client[:client_id]}]).fetch("id")

    deleted = auth.api.delete_o_auth_consent(headers: {"cookie" => cookie}, body: {id: consent_id})

    assert_equal({deleted: true}, deleted)
  end

  def test_pairwise_subject_uses_sector_identifier_from_redirect_uris
    auth = build_auth(scopes: ["openid"], pairwise_secret: "pairwise-secret-with-enough-entropy-123")
    cookie = sign_up_cookie(auth, email: "pairwise-sector@example.com")
    client_a = auth.api.admin_create_o_auth_client(body: pairwise_client_body("https://app.example.com/cb"))
    client_b = auth.api.admin_create_o_auth_client(body: pairwise_client_body("https://app.example.com/other"))
    client_c = auth.api.admin_create_o_auth_client(body: pairwise_client_body("https://other.example.com/cb"))

    sub_a = pairwise_sub_for(auth, cookie, client_a, redirect_uri: "https://app.example.com/cb")
    sub_b = pairwise_sub_for(auth, cookie, client_b, redirect_uri: "https://app.example.com/other")
    sub_c = pairwise_sub_for(auth, cookie, client_c, redirect_uri: "https://other.example.com/cb")

    assert_equal sub_a, sub_b
    refute_equal sub_a, sub_c
  end

  def test_refresh_token_replay_revokes_descendant_access_tokens
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth, email: "refresh-replay@example.com")
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope: "openid offline_access"
      }
    )
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access")
    rotated = auth.api.o_auth2_token(body: refresh_grant_body(client, tokens[:refresh_token]))

    assert_raises(BetterAuth::APIError) { auth.api.o_auth2_token(body: refresh_grant_body(client, tokens[:refresh_token])) }

    old_access = auth.api.o_auth2_introspect(body: introspect_body(client, tokens[:access_token]))
    new_access = auth.api.o_auth2_introspect(body: introspect_body(client, rotated[:access_token]))
    assert_equal false, old_access[:active]
    assert_equal false, new_access[:active]
  end

  def test_authorize_prompt_none_returns_consent_required_without_prior_consent
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Prompt None Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-456",
        prompt: "none",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "consent_required", params.fetch("error")
    assert_equal "state-456", params.fetch("state")
  end

  private

  def build_auth(options = {})
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.oauth_provider({scopes: ["read", "write"], allow_dynamic_client_registration: true}.merge(options))]
    )
  end

  def oauth_rate_limit_path(rule)
    %w[
      /oauth2/token
      /oauth2/authorize
      /oauth2/introspect
      /oauth2/revoke
      /oauth2/register
      /oauth2/userinfo
      /oauth2/continue
      /oauth2/consent
      /oauth2/end-session
    ].find { |path| rule.fetch(:path_matcher).call(path) }
  end

  def pkce_verifier
    "a" * 64
  end

  def pkce_challenge
    Base64.urlsafe_encode64(OpenSSL::Digest.digest("SHA256", pkce_verifier), padding: false)
  end

  def issue_authorization_code_tokens(auth, cookie, client, scope:, redirect_uri: "https://resource.example/callback", nonce: nil)
    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: redirect_uri,
        scope: scope,
        state: "state-token",
        prompt: "consent",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256",
        nonce: nonce
      }.compact,
      as_response: true
    )
    assert_equal 302, status
    consent_code = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query).fetch("consent_code")
    consent = auth.api.o_auth2_consent(
      headers: {"cookie" => cookie},
      body: {accept: true, consent_code: consent_code}
    )
    code = Rack::Utils.parse_query(URI.parse(consent.fetch(:redirectURI)).query).fetch("code")
    auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirect_uri,
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        code_verifier: pkce_verifier
      }
    )
  end

  def sign_up_cookie(auth, email: "oauth-provider@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "OAuth Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def refresh_grant_body(client, refresh_token)
    {
      grant_type: "refresh_token",
      refresh_token: refresh_token,
      client_id: client[:client_id],
      client_secret: client[:client_secret]
    }
  end

  def decode_id_token(token, client)
    key = OpenSSL::HMAC.hexdigest("SHA256", SECRET, "oidc.id_token.#{client[:client_id]}")
    JWT.decode(token, key, true, algorithm: "HS256").first
  end

  def introspect_body(client, token)
    {
      token: token,
      token_type_hint: "access_token",
      client_id: client[:client_id],
      client_secret: client[:client_secret]
    }
  end

  def pairwise_client_body(redirect_uri)
    {
      redirect_uris: [redirect_uri],
      token_endpoint_auth_method: "client_secret_post",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "openid",
      subject_type: "pairwise"
    }
  end

  def pairwise_sub_for(auth, cookie, client, redirect_uri:)
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid", redirect_uri: redirect_uri)
    decode_id_token(tokens[:id_token], client).fetch("sub")
  end

  def rack_env(method, path, body: nil)
    Rack::MockRequest.env_for(
      path,
      :method => method,
      "CONTENT_TYPE" => "application/json",
      :input => body ? JSON.generate(body) : nil
    )
  end
end

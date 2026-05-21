# frozen_string_literal: true

require "jwt"
require "rack/mock"
require_relative "../../test_helper"

class BetterAuthPluginsOIDCProviderTest < Minitest::Test
  SECRET = "phase-eleven-secret-with-enough-entropy-123"

  def test_oidc_provider_emits_upstream_deprecation_warning_once
    warnings = []
    BetterAuth::Plugins::OIDCProvider.reset_deprecation_warning!

    BetterAuth::Plugins.oidc_provider(logger: ->(message) { warnings << message })
    BetterAuth::Plugins.oidc_provider(logger: ->(message) { warnings << message })

    assert_equal 1, warnings.length
    assert_includes warnings.first, '"oidc-provider" plugin is deprecated'
    assert_includes warnings.first, "better_auth-oauth-provider"
  ensure
    BetterAuth::Plugins::OIDCProvider.reset_deprecation_warning!
  end

  def test_parse_prompt_matches_upstream_rules
    assert_equal ["login"], BetterAuth::Plugins::OIDCProvider.parse_prompt("login").to_a
    assert_equal ["login", "consent"], BetterAuth::Plugins::OIDCProvider.parse_prompt(" login   consent ").to_a
    assert_equal [], BetterAuth::Plugins::OIDCProvider.parse_prompt("unknown").to_a

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins::OIDCProvider.parse_prompt("none consent")
    end
    assert_equal "invalid_request", error.message
  end

  def test_metadata_registration_authorization_token_and_userinfo_flow
    auth = build_auth(store_client_secret: :hashed)
    cookie = sign_up_cookie(auth)

    metadata = auth.api.get_open_id_config
    assert_equal "http://localhost:3000", metadata[:issuer]
    assert_equal "http://localhost:3000/api/auth/oauth2/authorize", metadata[:authorization_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/token", metadata[:token_endpoint]
    assert_includes metadata[:scopes_supported], "openid"

    client = auth.api.register_o_auth_application(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        skip_consent: true,
        client_name: "Ruby Client"
      }
    )
    assert_equal "none", client[:token_endpoint_auth_method]
    assert_nil client[:client_secret]

    status, headers, _body = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://client.example/callback",
        scope: "openid email profile offline_access",
        state: "state-123",
        prompt: "none"
      },
      as_response: true
    )
    assert_equal 302, status
    redirect = URI.parse(headers.fetch("location"))
    redirect_params = Rack::Utils.parse_query(redirect.query)
    assert_equal "state-123", redirect_params["state"]
    assert_equal "http://localhost:3000", redirect_params["iss"]
    assert redirect_params["code"]

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: redirect_params.fetch("code"),
        redirect_uri: "https://client.example/callback",
        client_id: client[:client_id]
      }
    )
    assert_equal "Bearer", tokens[:token_type]
    assert tokens[:access_token]
    assert tokens[:id_token]
    assert tokens[:refresh_token]

    userinfo = auth.api.o_auth2_user_info(headers: {"authorization" => "Bearer #{tokens[:access_token]}"})
    assert_equal "oidc@example.com", userinfo[:email]
    assert_equal false, userinfo[:email_verified]
    assert_equal "OIDC User", userinfo[:name]
  end

  def test_metadata_exposes_and_routes_support_introspection_and_revocation
    auth = build_auth
    cookie = sign_up_cookie(auth)
    metadata = auth.api.get_open_id_config

    assert_equal "http://localhost:3000/api/auth/oauth2/introspect", metadata[:introspection_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/revoke", metadata[:revocation_endpoint]
    assert_equal ["client_secret_basic", "client_secret_post"], metadata[:introspection_endpoint_auth_methods_supported]
    assert_equal ["client_secret_basic", "client_secret_post"], metadata[:revocation_endpoint_auth_methods_supported]

    client = auth.api.register_o_auth_application(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        skip_consent: true,
        client_name: "Introspection Client"
      }
    )
    code = authorize_code(auth, cookie, client, scope: "openid email")
    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://client.example/callback",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        code_verifier: "verifier"
      }
    )

    active = auth.api.o_auth2_introspect(
      body: {
        token: tokens.fetch(:access_token),
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal true, active[:active]
    assert_equal client[:client_id], active[:client_id]
    assert_equal "openid email", active[:scope]

    assert_equal(
      {revoked: true},
      auth.api.o_auth2_revoke(
        body: {
          token: tokens.fetch(:access_token),
          token_type_hint: "access_token",
          client_id: client[:client_id],
          client_secret: client[:client_secret]
        }
      )
    )

    inactive = auth.api.o_auth2_introspect(
      body: {
        token: tokens.fetch(:access_token),
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal false, inactive[:active]
  end

  def test_metadata_and_token_flow_work_through_rack_for_external_clients
    auth = build_auth
    cookie = sign_up_cookie(auth)
    request = Rack::MockRequest.new(auth)

    metadata_response = request.get("/api/auth/.well-known/openid-configuration")
    metadata = JSON.parse(metadata_response.body)

    assert_equal 200, metadata_response.status
    assert_equal "http://localhost:3000/api/auth/oauth2/token", metadata.fetch("token_endpoint")

    register_response = request.post(
      "/api/auth/oauth2/register",
      "CONTENT_TYPE" => "application/json",
      "HTTP_COOKIE" => cookie,
      "HTTP_ORIGIN" => "http://localhost:3000",
      :input => JSON.generate(
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        skip_consent: true,
        client_name: "Rack Client"
      )
    )
    client = JSON.parse(register_response.body)

    assert_equal 201, register_response.status
    assert_equal "none", client.fetch("token_endpoint_auth_method")

    authorize_response = request.get(
      "/api/auth/oauth2/authorize?#{Rack::Utils.build_query(
        response_type: "code",
        client_id: client.fetch("client_id"),
        redirect_uri: "https://client.example/callback",
        scope: "openid email",
        state: "rack-state",
        prompt: "none"
      )}",
      "HTTP_COOKIE" => cookie
    )
    redirect_params = Rack::Utils.parse_query(URI.parse(authorize_response["location"]).query)

    assert_equal 302, authorize_response.status
    assert_equal "rack-state", redirect_params.fetch("state")
    assert redirect_params.fetch("code")

    token_response = request.post(
      "/api/auth/oauth2/token",
      "CONTENT_TYPE" => "application/json",
      :input => JSON.generate(
        grant_type: "authorization_code",
        code: redirect_params.fetch("code"),
        redirect_uri: "https://client.example/callback",
        client_id: client.fetch("client_id")
      )
    )
    tokens = JSON.parse(token_response.body)

    assert_equal 200, token_response.status
    assert_equal "Bearer", tokens.fetch("token_type")
    assert tokens.fetch("access_token")
    assert tokens.fetch("id_token")
  end

  def test_logout_endpoint_clears_session_and_redirects_to_registered_url
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_application(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://client.example/callback"],
        post_logout_redirect_uris: ["https://client.example/logout"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Logout Client"
      }
    )

    status, headers, _body = auth.api.end_session(
      headers: {"cookie" => cookie},
      query: {
        client_id: client[:client_id],
        post_logout_redirect_uri: "https://client.example/logout",
        state: "bye"
      },
      as_response: true
    )

    assert_equal 302, status
    assert_equal "https://client.example/logout?state=bye", headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token=;"
  end

  def test_authorization_prompt_consent_records_consent_before_issuing_code
    auth = build_auth(consent_page: "/oidc/consent")
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_application(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Consent Client"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://client.example/callback",
        scope: "openid email",
        state: "consent-state",
        prompt: "consent"
      },
      as_response: true
    )
    assert_equal 302, status
    consent_redirect = URI.parse(headers.fetch("location"))
    assert_equal "/oidc/consent", consent_redirect.path
    consent_code = Rack::Utils.parse_query(consent_redirect.query).fetch("consent_code")

    consent = auth.api.o_auth_consent(headers: {"cookie" => cookie}, body: {accept: true, consent_code: consent_code})
    callback = URI.parse(consent.fetch(:redirectURI))
    params = Rack::Utils.parse_query(callback.query)
    assert_equal "consent-state", params.fetch("state")
    assert params.fetch("code")

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: params.fetch("code"),
        redirect_uri: "https://client.example/callback",
        client_id: client[:client_id]
      }
    )
    assert tokens[:id_token]
    assert_equal "openid email", tokens[:scope]
  end

  def test_prompt_none_returns_consent_required_when_consent_is_missing
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_application(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Prompt None Client"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://client.example/callback",
        scope: "openid email",
        state: "state-missing-consent",
        prompt: "none"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "consent_required", params.fetch("error")
    assert_equal "state-missing-consent", params.fetch("state")
  end

  def test_dynamic_registration_requires_authentication_unless_enabled
    auth = build_auth

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_application(
        body: {
          redirect_uris: ["https://client.example/callback"],
          client_name: "Anonymous Client"
        }
      )
    end
    assert_equal "UNAUTHORIZED", error.status

    open_auth = build_auth(allow_dynamic_client_registration: true)
    client = open_auth.api.register_o_auth_application(
      body: {
        redirect_uris: ["https://client.example/callback"],
        client_name: "Anonymous Client"
      }
    )

    assert client[:client_id]
    assert client[:client_secret]
    assert_equal 0, client[:client_secret_expires_at]
  end

  def test_registration_validates_grant_response_type_and_returns_rfc7591_metadata
    auth = build_auth
    cookie = sign_up_cookie(auth)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_application(
        headers: {"cookie" => cookie},
        body: {
          redirect_uris: ["https://client.example/callback"],
          grant_types: ["authorization_code"],
          response_types: ["token"],
          client_name: "Invalid Client"
        }
      )
    end
    assert_equal "invalid_client_metadata", error.message

    result = auth.api.register_o_auth_application(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Registered Client",
        metadata: {tenant: "ruby"}
      },
      return_status: true,
      return_headers: true
    )

    client = result.fetch(:response)
    assert_equal 201, result.fetch(:status)
    assert_equal "no-store", result.fetch(:headers).fetch("cache-control")
    assert_equal "no-cache", result.fetch(:headers).fetch("pragma")
    assert client[:client_id_issued_at]
    assert_equal 0, client[:client_secret_expires_at]
    assert_equal({"tenant" => "ruby"}, client[:metadata])
  end

  def test_dynamic_client_lifecycle_lists_updates_rotates_and_deletes_owned_clients
    auth = build_auth(store_client_secret: :hashed)
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_application(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Lifecycle Client"
      }
    )

    listed = auth.api.list_o_auth_applications(headers: {"cookie" => cookie})
    assert_equal [client[:client_id]], listed.map { |entry| entry.fetch(:client_id) }
    refute listed.first.key?(:client_secret)

    updated = auth.api.update_o_auth_application(
      headers: {"cookie" => cookie},
      params: {id: client[:client_id]},
      body: {
        redirect_uris: ["https://client.example/callback", "https://client.example/second"],
        token_endpoint_auth_method: "none",
        client_secret: "ignored-secret",
        client_name: "Updated Client"
      }
    )
    assert_equal "Updated Client", updated[:client_name]
    assert_equal ["https://client.example/callback", "https://client.example/second"], updated[:redirect_uris]
    assert_equal "client_secret_post", updated[:token_endpoint_auth_method]
    refute updated.key?(:client_secret)

    rotated = auth.api.rotate_o_auth_application_secret(headers: {"cookie" => cookie}, params: {id: client[:client_id]})
    assert rotated[:client_secret]
    refute_equal client[:client_secret], rotated[:client_secret]
    refute_equal rotated[:client_secret], auth.context.adapter.find_one(model: "oauthApplication", where: [{field: "clientId", value: client[:client_id]}]).fetch("clientSecret")

    deleted = auth.api.delete_o_auth_application(headers: {"cookie" => cookie}, params: {id: client[:client_id]})
    assert_equal({success: true}, deleted)
    assert_raises(BetterAuth::APIError) { auth.api.get_o_auth_client(params: {id: client[:client_id]}) }
  end

  def test_oidc_provider_normalizes_issuer_like_upstream_rfc_9207
    auth = build_auth(auth_base_url: "http://issuer.example.com")

    metadata = auth.api.get_open_id_config

    assert_equal "https://issuer.example.com", metadata[:issuer]
    assert_equal "https://issuer.example.com/auth", BetterAuth::Plugins::OIDCProvider.normalize_issuer("http://issuer.example.com/auth/?x=1#frag")
  end

  def test_authorization_validates_scope_pkce_and_max_age
    auth = build_auth(require_pkce: true, login_page: "/login")
    cookie = sign_up_cookie(auth)
    client = register_public_client(auth, cookie)

    invalid_scope = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: authorize_query(client).merge(scope: "openid missing_scope", prompt: "none"),
      as_response: true
    )
    invalid_scope_params = Rack::Utils.parse_query(URI.parse(invalid_scope[1].fetch("location")).query)
    assert_equal "invalid_scope", invalid_scope_params.fetch("error")

    missing_pkce = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: authorize_query(client).merge(code_challenge: nil, code_challenge_method: nil, prompt: "none"),
      as_response: true
    )
    missing_pkce_params = Rack::Utils.parse_query(URI.parse(missing_pkce[1].fetch("location")).query)
    assert_equal "invalid_request", missing_pkce_params.fetch("error")

    max_age = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: authorize_query(client).merge(max_age: "0"),
      as_response: true
    )
    assert_equal 302, max_age[0]
    assert_match %r{\A/login\?}, max_age[1].fetch("location")
    assert_includes max_age[1].fetch("set-cookie"), "oidc_login_prompt="
  end

  def test_stored_client_secret_can_be_hashed_or_encrypted_and_still_authenticate
    [:hashed, :encrypted].each do |mode|
      auth = build_auth(store_client_secret: mode)
      cookie = sign_up_cookie(auth)
      client = auth.api.register_o_auth_application(
        headers: {"cookie" => cookie},
        body: {
          redirect_uris: ["https://client.example/callback"],
          token_endpoint_auth_method: "client_secret_post",
          client_name: "#{mode} client"
        }
      )
      stored = auth.context.adapter.find_one(model: "oauthApplication", where: [{field: "clientId", value: client[:client_id]}])
      refute_equal client[:client_secret], stored.fetch("clientSecret")

      code = authorize_and_consent(auth, cookie, client, scope: "openid offline_access")
      tokens = auth.api.o_auth2_token(
        body: {
          grant_type: "authorization_code",
          code: code,
          redirect_uri: "https://client.example/callback",
          client_id: client[:client_id],
          code_verifier: "verifier",
          client_secret: client[:client_secret]
        }
      )
      assert tokens[:access_token]
      assert tokens[:refresh_token]
    end
  end

  def test_custom_hashed_client_secret_uses_constant_time_compare
    calls = []
    original = BetterAuth::Crypto.method(:constant_time_compare)

    BetterAuth::Crypto.stub(:constant_time_compare, lambda do |left, right|
      calls << [left, right]
      original.call(left, right)
    end) do
      assert BetterAuth::Plugins::OAuthProtocol.send(
        :verify_client_secret,
        nil,
        "stored:client-secret",
        "client-secret",
        {hash: ->(secret) { "stored:#{secret}" }}
      )
    end
    assert_equal [["stored:client-secret", "stored:client-secret"]], calls
  end

  def test_jwt_plugin_negotiates_id_token_signing_algorithm
    auth = build_auth(use_jwt_plugin: true, extra_plugins: [BetterAuth::Plugins.jwt])
    cookie = sign_up_cookie(auth)
    client = register_public_client(auth, cookie, skip_consent: true)

    metadata = auth.api.get_open_id_config
    assert_includes metadata[:id_token_signing_alg_values_supported], "EdDSA"
    refute_includes metadata[:id_token_signing_alg_values_supported], "HS256"

    code = authorize_code(auth, cookie, client, scope: "openid")
    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://client.example/callback",
        client_id: client[:client_id],
        code_verifier: "verifier"
      }
    )
    header = JWT.decode(tokens.fetch(:id_token), nil, false).last
    assert_equal "EdDSA", header.fetch("alg")

    jwk = auth.api.get_jwks[:keys].first
    payload = BetterAuth::Plugins.verify_jwt_token(
      endpoint_context(auth),
      tokens.fetch(:id_token),
      {jwks: {key_pair_config: {alg: "EdDSA"}}, jwt: {audience: client[:client_id], issuer: "http://localhost:3000"}}
    )
    assert_equal "oidc@example.com", payload.fetch("email")
    assert_equal jwk[:kid], header.fetch("kid")
  end

  def test_userinfo_merges_additional_claims_for_requested_scopes
    auth = build_auth(
      get_additional_user_info_claim: ->(user, scopes, client) {
        {custom: "custom value", userId: user.fetch("id"), requestedScopes: scopes, clientId: client.fetch("clientId")}
      }
    )
    cookie = sign_up_cookie(auth)
    client = register_public_client(auth, cookie, skip_consent: true)
    code = authorize_code(auth, cookie, client, scope: "openid profile email")
    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://client.example/callback",
        client_id: client[:client_id],
        code_verifier: "verifier"
      }
    )

    userinfo = auth.api.o_auth2_user_info(headers: {"authorization" => "Bearer #{tokens[:access_token]}"})
    assert_equal "custom value", userinfo[:custom]
    assert_equal ["openid", "profile", "email"], userinfo[:requestedScopes]
    assert_equal client[:client_id], userinfo[:clientId]
  end

  def test_consent_can_render_html_when_no_consent_page_is_configured
    auth = build_auth(
      consent_page: nil,
      get_consent_html: ->(data) {
        "<h1>Consent for #{data.fetch(:clientName)}</h1><p>#{data.fetch(:scopes).join(" ")}</p>"
      }
    )
    cookie = sign_up_cookie(auth)
    client = register_public_client(auth, cookie)

    status, headers, body = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: authorize_query(client),
      as_response: true
    )

    assert_equal 200, status
    assert_equal "text/html", headers.fetch("content-type")
    assert_includes body.join, "Consent for Public Client"
    assert_includes body.join, "openid email"
  end

  def test_prompt_login_resumes_authorization_after_successful_login
    auth = build_auth(allow_dynamic_client_registration: true, login_page: "/login")
    sign_up_cookie(auth)
    client = auth.api.register_o_auth_application(
      body: {
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Login Prompt Client"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      query: authorize_query(client).merge(prompt: "login"),
      as_response: true
    )
    assert_equal 302, status
    assert_match %r{\A/login\?}, headers.fetch("location")
    prompt_cookie = headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")

    login_status, login_headers, = auth.api.sign_in_email(
      headers: {"cookie" => prompt_cookie},
      body: {email: "oidc@example.com", password: "password123"},
      as_response: true
    )

    assert_equal 302, login_status
    assert_match %r{\A/oauth2/authorize\?}, login_headers.fetch("location")
    assert_includes login_headers.fetch("location"), "consent_code="
    assert_match(/oidc_login_prompt=; .*Max-Age=0/, login_headers.fetch("set-cookie"))
    assert_match(/better-auth\.session_token=/, login_headers.fetch("set-cookie"))
  end

  private

  def build_auth(options = {})
    extra_plugins = Array(options.delete(:extra_plugins))
    auth_base_url = options.delete(:auth_base_url) || "http://localhost:3000"
    BetterAuth.auth(
      base_url: auth_base_url,
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.oidc_provider({__skip_deprecation_warning: true}.merge(options)), *extra_plugins]
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "oidc@example.com", password: "password123", name: "OIDC User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def register_public_client(auth, cookie, skip_consent: false)
    auth.api.register_o_auth_application(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        skip_consent: skip_consent,
        client_name: "Public Client"
      }
    )
  end

  def authorize_query(client)
    {
      response_type: "code",
      client_id: client[:client_id],
      redirect_uri: "https://client.example/callback",
      scope: "openid email",
      state: "state-123",
      code_challenge: Base64.urlsafe_encode64(OpenSSL::Digest.digest("SHA256", "verifier"), padding: false),
      code_challenge_method: "S256"
    }
  end

  def authorize_code(auth, cookie, client, scope: "openid email")
    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: authorize_query(client).merge(scope: scope, prompt: "none"),
      as_response: true
    )
    assert_equal 302, status
    Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query).fetch("code")
  end

  def authorize_and_consent(auth, cookie, client, scope:)
    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: authorize_query(client).merge(scope: scope),
      as_response: true
    )
    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    return params.fetch("code") if params["code"]

    consent = auth.api.o_auth_consent(headers: {"cookie" => cookie}, body: {accept: true, consent_code: params.fetch("consent_code")})
    Rack::Utils.parse_query(URI.parse(consent.fetch(:redirectURI)).query).fetch("code")
  end

  def endpoint_context(auth)
    BetterAuth::Endpoint::Context.new(
      path: "/oauth2/token",
      method: "POST",
      query: {},
      body: {},
      params: {},
      headers: {},
      context: auth.context
    )
  end
end

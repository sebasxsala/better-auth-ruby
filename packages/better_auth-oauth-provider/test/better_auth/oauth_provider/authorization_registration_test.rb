# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderAuthorizationRegistrationTest < Minitest::Test
  include OAuthProviderFlowHelpers

  MemoryStorage = Struct.new(:store) do
    def initialize
      super({})
    end

    def set(key, value, _ttl = nil)
      store[key] = value
    end

    def get(key)
      store[key]
    end

    def delete(key)
      store.delete(key)
    end
  end

  def test_validate_issuer_url_covers_remaining_upstream_cases
    assert_equal "https://issuer.example.com", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("https://issuer.example.com?x=1")
    assert_equal "https://issuer.example.com/path", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("https://issuer.example.com/path#frag")
    assert_equal "https://issuer.example.com/path", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("https://issuer.example.com/path/")
    assert_equal "http://[::1]:3000", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://[::1]:3000/")
    assert_equal "not a url", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("not a url?query#fragment")
  end

  def test_unauthenticated_authorize_redirects_to_login_with_signed_query
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)

    status, headers, = auth.api.o_auth2_authorize(
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "openid",
        state: "login-state",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )

    assert_equal 302, status
    uri = URI.parse(headers.fetch("location"))
    assert_equal "/login", uri.path
    params = Rack::Utils.parse_query(uri.query)
    assert_equal client[:client_id], params.fetch("client_id")
    assert_equal "login-state", params.fetch("state")
    assert params["sig"]
    assert params["exp"]
  end

  def test_prompt_none_without_session_redirects_login_required_to_client
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)

    status, headers, = auth.api.o_auth2_authorize(
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "openid",
        state: "prompt-none-login",
        prompt: "none",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "login_required", params.fetch("error")
    assert_equal "prompt-none-login", params.fetch("state")
    assert_equal "http://localhost:3000", params.fetch("iss")
  end

  def test_authorize_resolves_request_uri_and_discards_front_channel_params
    resolved = nil
    auth = build_auth(
      scopes: ["openid", "profile"],
      request_uri_resolver: ->(input) {
        resolved = input
        {
          response_type: "code",
          client_id: input[:client_id],
          redirect_uri: "https://resource.example/callback",
          scope: "openid",
          state: "par-state",
          code_challenge: pkce_challenge,
          code_challenge_method: "S256"
        }
      }
    )
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid profile", skip_consent: true)

    status, headers, = auth.api.o_auth2_authorize(
      query: {
        client_id: client[:client_id],
        request_uri: "urn:ietf:params:oauth:request_uri:test",
        scope: "openid profile admin",
        prompt: "none"
      },
      as_response: true
    )

    assert_equal 302, status
    assert_equal "urn:ietf:params:oauth:request_uri:test", resolved.fetch(:request_uri)
    redirect = URI.parse(headers.fetch("location"))
    assert_equal "/login", redirect.path
    signed = Rack::Utils.parse_query(redirect.query)
    assert_equal "openid", signed.fetch("scope")
    refute signed.key?("request_uri")
    refute signed.key?("prompt")
  end

  def test_request_uri_resolution_keeps_front_channel_client_id
    auth = build_auth(
      scopes: ["openid"],
      request_uri_resolver: ->(_input) {
        {
          response_type: "code",
          client_id: "attacker-client",
          redirect_uri: "https://resource.example/callback",
          scope: "openid",
          code_challenge: pkce_challenge,
          code_challenge_method: "S256"
        }
      }
    )
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)

    status, headers, = auth.api.o_auth2_authorize(
      query: {
        client_id: client[:client_id],
        request_uri: "urn:ietf:params:oauth:request_uri:front-client"
      },
      as_response: true
    )

    assert_equal 302, status
    signed = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal client[:client_id], signed.fetch("client_id")
  end

  def test_prompt_none_cannot_be_combined_with_interactive_prompts
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
        prompt: "none login",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "invalid_request", params.fetch("error")
    assert_match(/prompt/, params.fetch("error_description"))
  end

  def test_request_uri_without_resolver_redirects_invalid_request_uri
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid")

    status, headers, = auth.api.o_auth2_authorize(
      query: {
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        request_uri: "urn:ietf:params:oauth:request_uri:missing"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "invalid_request_uri", params.fetch("error")
  end

  def test_safe_redirect_uri_validation_accepts_local_http_and_custom_schemes
    auth = build_auth(scopes: ["openid", "profile", "email", "offline_access"])
    cookie = sign_up_cookie(auth)

    localhost = register_client(auth, cookie, redirect_uris: ["http://localhost:3000/callback"], token_endpoint_auth_method: "none")
    ipv4 = register_client(auth, cookie, redirect_uris: ["http://127.0.0.1:4567/callback"], token_endpoint_auth_method: "none")
    ipv6 = register_client(auth, cookie, redirect_uris: ["http://[::1]:4567/callback"], token_endpoint_auth_method: "none")
    mobile = register_client(auth, cookie, redirect_uris: ["com.example.app:/callback"], token_endpoint_auth_method: "none", type: "native")

    assert_equal ["http://localhost:3000/callback"], localhost[:redirect_uris]
    assert_equal ["http://127.0.0.1:4567/callback"], ipv4[:redirect_uris]
    assert_equal ["http://[::1]:4567/callback"], ipv6[:redirect_uris]
    assert_equal ["com.example.app:/callback"], mobile[:redirect_uris]
  end

  def test_safe_redirect_uri_validation_rejects_unsafe_values
    auth = build_auth
    cookie = sign_up_cookie(auth)

    [
      "http://issuer.example.com/callback",
      "http://192.168.1.1/callback",
      "http://localhost.evil.com/callback",
      "http://127.0.0.1.evil.com/callback",
      "javascript:alert(1)",
      "data:text/plain,hello",
      "vbscript:msgbox(1)",
      "",
      "not a url"
    ].each do |redirect_uri|
      error = assert_raises(BetterAuth::APIError) do
        register_client(auth, cookie, redirect_uris: [redirect_uri], token_endpoint_auth_method: "none")
      end
      assert_equal 400, error.status_code
    end
  end

  def test_registration_rejects_missing_body_and_unauthenticated_request
    auth = build_auth

    missing_body = assert_raises(BetterAuth::APIError) { auth.api.register_o_auth_client(body: nil) }
    assert_equal 401, missing_body.status_code

    unauthenticated = assert_raises(BetterAuth::APIError) do
      register_client(auth, nil, redirect_uris: ["https://resource.example/callback"])
    end
    assert_equal 401, unauthenticated.status_code
  end

  def test_registration_preserves_confidential_type_and_strips_unknown_metadata
    auth = build_auth(scopes: ["openid"], client_registration_allowed_scopes: ["openid"])
    cookie = sign_up_cookie(auth)

    client = register_client(
      auth,
      cookie,
      redirect_uris: ["https://resource.example/callback"],
      token_endpoint_auth_method: "client_secret_post",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "openid",
      type: "web",
      metadata: {software_id: "kit", unknown_field: "strip-me"},
      tos_uri: "https://resource.example/terms"
    )

    assert_equal "client_secret_post", client[:token_endpoint_auth_method]
    assert_equal "web", client[:type]
    assert_equal "kit", client[:software_id]
    assert_equal "https://resource.example/terms", client[:tos_uri]
    refute client.key?(:unknown_field)
    refute client[:metadata].key?("unknown_field")
  end

  def test_registration_type_matrix_matches_upstream
    auth = build_auth
    cookie = sign_up_cookie(auth)

    web_public = assert_raises(BetterAuth::APIError) do
      register_client(auth, cookie, token_endpoint_auth_method: "none", type: "web")
    end
    assert_equal 400, web_public.status_code

    %w[native user-agent-based].each do |type|
      confidential = assert_raises(BetterAuth::APIError) do
        register_client(auth, cookie, token_endpoint_auth_method: "client_secret_post", type: type)
      end
      assert_equal 400, confidential.status_code

      public_client = auth.api.admin_create_o_auth_client(
        body: {
          redirect_uris: ["https://resource.example/#{type}/callback"],
          token_endpoint_auth_method: "none",
          type: type
        }
      )
      assert_equal type, public_client[:type]
      assert_nil public_client[:client_secret]
    end
  end

  def test_secondary_storage_requires_database_backed_sessions_for_oauth_provider
    storage = MemoryStorage.new

    error = assert_raises(BetterAuth::APIError) do
      build_auth(secondary_storage: storage)
    end
    assert_match(/store_session_in_database/i, error.message)

    auth = build_auth(secondary_storage: storage, session: {store_session_in_database: true})
    assert auth.context
  end
end

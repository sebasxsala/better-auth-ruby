# frozen_string_literal: true

require "json"
require "rack/mock"
require "socket"
require_relative "../../test_helper"

class BetterAuthPluginsGenericOAuthTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"

  def test_oauth2_callback_endpoint_is_get_only_like_upstream
    auth = build_auth

    assert_equal ["GET"], auth.api.endpoints.fetch(:o_auth2_callback).methods
  end

  def test_sign_in_oauth2_generates_authorization_url_with_state_and_scopes
    auth = build_auth

    result = auth.api.sign_in_with_oauth2(
      body: {
        providerId: "custom",
        callbackURL: "/dashboard",
        newUserCallbackURL: "/welcome",
        scopes: ["calendar"],
        disableRedirect: true
      }
    )
    uri = URI.parse(result[:url])
    params = Rack::Utils.parse_query(uri.query)

    assert_equal false, result[:redirect]
    assert_equal "https", uri.scheme
    assert_equal "provider.example.com", uri.host
    assert_equal "/authorize", uri.path
    assert_equal "client-id", params["client_id"]
    assert_equal "code", params["response_type"]
    assert_equal "calendar profile email", params["scope"]
    assert_equal "http://localhost:3000/api/auth/oauth2/callback/custom", params["redirect_uri"]
    assert params["state"]
  end

  def test_sign_in_oauth2_supports_dynamic_authorization_params_and_response_mode
    auth = build_auth(
      provider_overrides: {
        authorization_url_params: ->(ctx) { {audience: "api", origin: ctx.context.base_url} },
        response_mode: "query"
      }
    )

    result = auth.api.sign_in_with_oauth2(body: {providerId: "custom", disableRedirect: true})
    params = Rack::Utils.parse_query(URI.parse(result[:url]).query)

    assert_equal "api", params.fetch("audience")
    assert_equal "http://localhost:3000/api/auth", params.fetch("origin")
    assert_equal "query", params.fetch("response_mode")
  end

  def test_pkce_uses_s256_challenge_and_token_exchange_only_sends_verifier_when_enabled
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo",
          pkce: true
        }
      )
      _status, headers, body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      data = JSON.parse(body.join)
      params = Rack::Utils.parse_query(URI.parse(data.fetch("url")).query)
      state = params.fetch("state")

      assert_equal "S256", params.fetch("code_challenge_method")
      auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: state},
        headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
        as_response: true
      )

      assert requests.find { |request| request[:path] == "/token" }.fetch(:params).key?("code_verifier")
    end

    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo",
          pkce: false
        }
      )
      _status, headers, body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      params = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query)

      refute params.key?("code_challenge")
      refute params.key?("code_challenge_method")

      auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: params.fetch("state")},
        headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
        as_response: true
      )

      refute requests.find { |request| request[:path] == "/token" }.fetch(:params).key?("code_verifier")
    end
  end

  def test_callback_without_state_redirects_to_restart_error
    auth = build_auth(on_api_error: {error_url: "/error"})

    status, headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/error?error=please_restart_the_process", headers.fetch("location")
  end

  def test_callback_redirects_when_provider_and_mapped_profile_omit_email
    auth = build_auth(
      user_info: {id: "missing-email-sub", name: "Missing Email User", emailVerified: true},
      on_api_error: {error_url: "/error"}
    )
    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")

    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_includes headers.fetch("location"), "error=email_is_missing"
  end

  def test_additional_data_cannot_override_internal_state_fields
    auth = build_auth(on_api_error: {error_url: "/error"})
    _status, headers, body = auth.api.sign_in_with_oauth2(
      body: {
        providerId: "custom",
        callbackURL: "/dashboard",
        additionalData: {
          callbackURL: "/evil",
          errorURL: "/evil-error",
          codeVerifier: "attacker-verifier"
        }
      },
      as_response: true
    )
    state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")

    status, callback_headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", callback_headers.fetch("location")
  end

  def test_discovery_headers_are_sent_when_fetching_metadata
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: nil,
          token_url: nil,
          user_info_url: nil,
          discovery_url: "#{base_url}/.well-known/openid-configuration",
          discovery_headers: {"X-Discovery-Token" => "secret"}
        }
      )

      auth.api.sign_in_with_oauth2(body: {providerId: "custom", disableRedirect: true})

      discovery_request = requests.find { |request| request[:path] == "/.well-known/openid-configuration" }
      assert_equal "secret", discovery_request.fetch(:headers).fetch("x-discovery-token")
    end
  end

  def test_callback_creates_user_account_session_and_redirects_new_user
    auth = build_auth
    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard", newUserCallbackURL: "/welcome"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")

    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/welcome", headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    user = auth.context.internal_adapter.find_user_by_email("oauth@example.com")[:user]
    account = auth.context.internal_adapter.find_account_by_provider_id("oauth-sub", "custom")
    assert_equal user["id"], account["userId"]
    assert_equal "access-token", account["accessToken"]
    assert_equal "refresh-token", account["refreshToken"]
    assert_equal "openid,email", account["scope"]
  end

  def test_callback_handles_numeric_account_ids_without_duplicate_accounts
    auth = build_auth(user_info: {id: 123_456_789, email: "numeric@example.com", name: "Numeric User", emailVerified: true})

    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard", newUserCallbackURL: "/welcome"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/welcome", headers.fetch("location")
    user = auth.context.internal_adapter.find_user_by_email("numeric@example.com")[:user]
    accounts = auth.context.internal_adapter.find_accounts(user["id"])
    assert_equal 1, accounts.length
    assert_equal "123456789", accounts.first["accountId"]

    second_sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard"})
    second_state = Rack::Utils.parse_query(URI.parse(second_sign_in[:url]).query).fetch("state")
    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: second_state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert_equal 1, auth.context.internal_adapter.find_accounts(user["id"]).length
  end

  def test_callback_applies_map_profile_to_user_callable
    auth = build_auth(
      user_info: {id: "mapped-sub", email: "mapped@example.com", name: "Original Name", emailVerified: false},
      provider_overrides: {
        map_profile_to_user: ->(profile) { {name: "Mapped #{profile[:name]}", emailVerified: true} }
      }
    )
    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")

    status, _headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    user = auth.context.internal_adapter.find_user_by_email("mapped@example.com")[:user]
    assert_equal "Mapped Original Name", user["name"]
    assert_equal true, user["emailVerified"]
  end

  def test_social_provider_get_user_info_applies_map_profile_to_user_callable
    auth = build_auth(
      user_info: {id: "social-provider-sub", email: "social-provider@example.com", name: "Social Provider", emailVerified: true},
      provider_overrides: {
        map_profile_to_user: ->(_profile) { {custom_field: "mapped-data"} }
      }
    )
    provider = auth.context.social_providers.fetch(:custom)

    result = provider.fetch(:get_user_info).call(accessToken: "access-token")

    assert_equal "social-provider@example.com", result.fetch(:user).fetch(:email)
    assert_equal "mapped-data", result.fetch(:user).fetch(:custom_field)
    assert_equal "social-provider-sub", result.fetch(:data).fetch(:id)
  end

  def test_oidc_discovery_provider_helpers_do_not_install_custom_user_info_callbacks
    refute_includes BetterAuth::Plugins.auth0(client_id: "id", client_secret: "secret", domain: "tenant.auth0.com"), :get_user_info
    refute_includes BetterAuth::Plugins.okta(client_id: "id", client_secret: "secret", issuer: "https://okta.example.com/oauth2/default"), :get_user_info
    refute_includes BetterAuth::Plugins.keycloak(client_id: "id", client_secret: "secret", issuer: "https://realm.example.com/realms/main"), :get_user_info
  end

  def test_state_cookie_is_set_and_cleared_for_database_state_strategy
    auth = build_auth
    status, headers, body = auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", callbackURL: "/dashboard"},
      as_response: true
    )
    data = JSON.parse(body.join)
    state = Rack::Utils.parse_query(URI.parse(data.fetch("url")).query).fetch("state")

    assert_equal 200, status
    assert_includes headers.fetch("set-cookie"), "better-auth.state="

    callback_status, callback_headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      as_response: true
    )

    assert_equal 302, callback_status
    state_cookie = callback_headers.fetch("set-cookie").lines.find { |line| line.start_with?("better-auth.state=") }
    assert state_cookie
    assert_includes state_cookie, "Max-Age=0"
  end

  def test_database_state_strategy_rejects_rack_callback_without_state_cookie
    auth = build_auth(on_api_error: {error_url: "/error"})
    _status, _headers, body = auth.call(rack_env("POST", "/api/auth/sign-in/oauth2", body: {providerId: "custom", callbackURL: "/dashboard"}))
    state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")

    callback_status, callback_headers, = auth.call(rack_env("GET", "/api/auth/oauth2/callback/custom?code=oauth-code&state=#{URI.encode_www_form_component(state)}"))

    assert_equal 302, callback_status
    assert_equal "/error?error=state_mismatch", callback_headers.fetch("location")
    refute auth.context.internal_adapter.find_account_by_provider_id("oauth-sub", "custom")
  end

  def test_cookie_state_strategy_uses_oauth_state_cookie
    auth = build_auth(account: {store_state_strategy: "cookie"})
    status, headers, body = auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", callbackURL: "/dashboard", newUserCallbackURL: "/welcome"},
      as_response: true
    )
    data = JSON.parse(body.join)
    state = Rack::Utils.parse_query(URI.parse(data.fetch("url")).query).fetch("state")

    assert_equal 200, status
    assert_includes headers.fetch("set-cookie"), "better-auth.oauth_state="

    callback_status, callback_headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      as_response: true
    )

    assert_equal 302, callback_status
    assert_equal "/welcome", callback_headers.fetch("location")
    state_cookie = callback_headers.fetch("set-cookie").lines.find { |line| line.start_with?("better-auth.oauth_state=") }
    assert state_cookie
    assert_includes state_cookie, "Max-Age=0"
  end

  def test_cookie_state_strategy_survives_secret_rotation
    old_auth = build_auth(
      account: {store_state_strategy: "cookie"},
      secrets: [{version: 1, value: "old-generic-oauth-secret-with-enough-entropy"}]
    )
    _status, headers, body = old_auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", callbackURL: "/dashboard", newUserCallbackURL: "/welcome"},
      as_response: true
    )
    state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")
    new_auth = build_auth(
      database: old_auth.context.adapter,
      account: {store_state_strategy: "cookie"},
      secrets: [
        {version: 2, value: "new-generic-oauth-secret-with-enough-entropy"},
        {version: 1, value: "old-generic-oauth-secret-with-enough-entropy"}
      ]
    )

    callback_status, callback_headers, = new_auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      as_response: true
    )

    assert_equal 302, callback_status
    assert_equal "/welcome", callback_headers.fetch("location")
  end

  def test_cookie_state_strategy_rejects_state_mismatch
    auth = build_auth(account: {store_state_strategy: "cookie"}, on_api_error: {error_url: "/error"})
    _status, headers, body = auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", callbackURL: "/dashboard"},
      as_response: true
    )
    state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")

    callback_status, callback_headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: "#{state}-tampered"},
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      as_response: true
    )

    assert_equal 302, callback_status
    assert_equal "/error?error=state_mismatch", callback_headers.fetch("location")
    state_cookie = callback_headers.fetch("set-cookie").lines.find { |line| line.start_with?("better-auth.oauth_state=") }
    assert state_cookie
    assert_includes state_cookie, "Max-Age=0"
  end

  def test_cookie_state_strategy_rejects_missing_state_cookie
    auth = build_auth(account: {store_state_strategy: "cookie"}, on_api_error: {error_url: "/error"})
    _status, _headers, body = auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", callbackURL: "/dashboard"},
      as_response: true
    )
    state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")

    callback_status, callback_headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )

    assert_equal 302, callback_status
    assert_equal "/error?error=state_mismatch", callback_headers.fetch("location")
  end

  def test_callback_reuses_existing_user_and_honors_disable_implicit_sign_up
    disabled = build_auth(disable_implicit_sign_up: true)
    sign_in = disabled.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard", errorCallbackURL: "/error"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    status, headers, _body = disabled.api.o_auth2_callback(params: {providerId: "custom"}, query: {code: "oauth-code", state: state}, as_response: true)

    assert_equal 302, status
    assert_equal "/error?error=signup_disabled", headers.fetch("location")

    requested = build_auth(disable_implicit_sign_up: true)
    sign_in = requested.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard", errorCallbackURL: "/error", requestSignUp: true})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    status, headers, _body = requested.api.o_auth2_callback(params: {providerId: "custom"}, query: {code: "oauth-code", state: state}, as_response: true)

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
  end

  def test_override_user_info_updates_existing_user_on_sign_in
    calls = 0
    auth = build_auth(
      provider_overrides: {
        override_user_info: true,
        get_user_info: ->(_tokens) {
          calls += 1
          {
            id: "override-sub",
            email: "override@example.com",
            name: (calls == 1) ? "Original Name" : "Updated Name",
            image: (calls == 1) ? "https://example.com/original.png" : "https://example.com/updated.png",
            emailVerified: true
          }
        }
      }
    )

    first = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard"})
    first_state = Rack::Utils.parse_query(URI.parse(first[:url]).query).fetch("state")
    auth.api.o_auth2_callback(params: {providerId: "custom"}, query: {code: "oauth-code", state: first_state}, as_response: true)

    second = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard"})
    second_state = Rack::Utils.parse_query(URI.parse(second[:url]).query).fetch("state")
    auth.api.o_auth2_callback(params: {providerId: "custom"}, query: {code: "oauth-code", state: second_state}, as_response: true)

    user = auth.context.internal_adapter.find_user_by_email("override@example.com")[:user]
    assert_equal "Updated Name", user.fetch("name")
    assert_equal "https://example.com/updated.png", user.fetch("image")
  end

  def test_link_account_generates_link_state_and_callback_links_to_current_user
    auth = build_auth(user_info: {id: "linked-sub", email: "link@example.com", name: "Linked User"})
    cookie = sign_up_cookie(auth, email: "link@example.com")
    link = auth.api.o_auth2_link_account(
      headers: {"cookie" => cookie},
      body: {providerId: "custom", callbackURL: "/settings", scopes: ["files"]}
    )
    state = Rack::Utils.parse_query(URI.parse(link[:url]).query).fetch("state")

    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/settings", headers.fetch("location")
    user = auth.context.internal_adapter.find_user_by_email("link@example.com")[:user]
    account = auth.context.internal_adapter.find_account_by_provider_id("linked-sub", "custom")
    assert_equal user["id"], account["userId"]
  end

  def test_invalid_provider_and_issuer_mismatch_errors
    auth = build_auth

    provider_error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_with_oauth2(body: {providerId: "missing"})
    end
    assert_equal 400, provider_error.status_code
    assert_equal "No config found for provider missing", provider_error.message

    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", errorCallbackURL: "/error"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state, iss: "https://wrong.example.com"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/error?error=issuer_mismatch", headers.fetch("location")
  end

  def test_callback_redirects_when_custom_get_token_raises
    auth = build_auth(
      provider_overrides: {
        get_token: ->(**_data) { raise "provider down" }
      }
    )
    status, headers, body = auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", errorCallbackURL: "/error"},
      as_response: true
    )
    state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")

    callback_status, callback_headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      as_response: true
    )

    assert_equal 200, status
    assert_equal 302, callback_status
    assert_equal "/error?error=oauth_code_verification_failed", callback_headers.fetch("location")
  end

  def test_standard_http_token_exchange_supports_headers_basic_auth_params_and_userinfo_mapping
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo",
          authorization_headers: {"X-Custom-Header" => "test-value"},
          token_url_params: ->(_ctx) { {audience: "api", resource: "calendar"} },
          authentication: "basic",
          pkce: true
        }
      )
      status, headers, body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")

      callback_status, callback_headers, = auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: state},
        headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
        as_response: true
      )

      assert_equal 200, status
      assert_equal 302, callback_status
      assert_equal "/dashboard", callback_headers.fetch("location")
      token_request = requests.find { |request| request[:path] == "/token" }
      assert token_request
      assert_equal "POST", token_request.fetch(:method)
      assert_equal "test-value", token_request.fetch(:headers).fetch("x-custom-header")
      assert_match(/\ABasic /, token_request.fetch(:headers).fetch("authorization"))
      assert_equal "oauth-code", token_request.fetch(:params).fetch("code")
      assert_equal "api", token_request.fetch(:params).fetch("audience")
      assert_equal "calendar", token_request.fetch(:params).fetch("resource")
      refute token_request.fetch(:params).key?("client_secret")

      userinfo_request = requests.find { |request| request[:path] == "/userinfo" }
      assert_equal "Bearer http-access-token", userinfo_request.fetch(:headers).fetch("authorization")
      account = auth.context.internal_adapter.find_account_by_provider_id("http-sub", "custom")
      assert_equal "http-access-token", account.fetch("accessToken")
      assert_equal "http-refresh-token", account.fetch("refreshToken")
      assert_equal "openid,email", account.fetch("scope")
      assert_instance_of Time, account.fetch("accessTokenExpiresAt")
      assert_instance_of Time, account.fetch("refreshTokenExpiresAt")
    end
  end

  def test_provider_helper_factories_match_upstream_defaults
    assert_equal(
      {
        provider_id: "auth0",
        discovery_url: "https://tenant.auth0.com/.well-known/openid-configuration",
        scopes: ["openid", "profile", "email"]
      },
      BetterAuth::Plugins.auth0(client_id: "id", client_secret: "secret", domain: "https://tenant.auth0.com").slice(:provider_id, :discovery_url, :scopes)
    )
    assert_equal "https://okta.example.com/oauth2/default/.well-known/openid-configuration", BetterAuth::Plugins.okta(client_id: "id", client_secret: "secret", issuer: "https://okta.example.com/oauth2/default/")[:discovery_url]
    assert_equal "https://realm.example.com/realms/main/.well-known/openid-configuration", BetterAuth::Plugins.keycloak(client_id: "id", client_secret: "secret", issuer: "https://realm.example.com/realms/main/")[:discovery_url]
    assert_equal "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", BetterAuth::Plugins.microsoft_entra_id(client_id: "id", client_secret: "secret", tenant_id: "common")[:authorization_url]
    assert_equal "https://slack.com/openid/connect/authorize", BetterAuth::Plugins.slack(client_id: "id", client_secret: "secret")[:authorization_url]
    assert_equal "line-jp", BetterAuth::Plugins.line(provider_id: "line-jp", client_id: "id", client_secret: "secret")[:provider_id]
    assert_equal "https://gumroad.com/oauth/authorize", BetterAuth::Plugins.gumroad(client_id: "id", client_secret: "secret")[:authorization_url]
    assert_equal "post", BetterAuth::Plugins.hubspot(client_id: "id", client_secret: "secret")[:authentication]
    assert_equal "https://www.patreon.com/oauth2/authorize", BetterAuth::Plugins.patreon(client_id: "id", client_secret: "secret")[:authorization_url]
  end

  def test_duplicate_provider_ids_emit_warning
    _out, err = capture_io do
      BetterAuth::Plugins.generic_oauth(
        config: [
          {provider_id: "dup", client_id: "id", client_secret: "secret", authorization_url: "https://one.example/auth", token_url: "https://one.example/token"},
          {provider_id: "dup", client_id: "id", client_secret: "secret", authorization_url: "https://two.example/auth", token_url: "https://two.example/token"}
        ]
      )
    end

    assert_includes err, "Duplicate provider IDs found: dup"
  end

  def test_generic_oauth_provider_is_available_to_account_info
    auth = build_auth(user_info: {id: "info-sub", email: "info@example.com", name: "Info User", emailVerified: true})
    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    _status, headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )
    account = auth.context.internal_adapter.find_account_by_provider_id("info-sub", "custom")

    info = auth.api.account_info(
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      query: {accountId: account.fetch("id")}
    )

    assert_equal "info-sub", info.fetch(:user).fetch(:id)
    assert_equal "info@example.com", info.fetch(:user).fetch(:email)
    assert_equal "info-sub", info.fetch(:data).fetch(:id)
  end

  def test_generic_oauth_provider_refreshes_access_tokens_through_account_routes
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo",
          authentication: "basic"
        }
      )
      _status, sign_in_headers, sign_in_body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      state = Rack::Utils.parse_query(URI.parse(JSON.parse(sign_in_body.join).fetch("url")).query).fetch("state")
      _callback_status, callback_headers, = auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: state},
        headers: {"cookie" => cookie_header(sign_in_headers.fetch("set-cookie"))},
        as_response: true
      )
      account = auth.context.internal_adapter.find_account_by_provider_id("http-sub", "custom")
      auth.context.internal_adapter.update_account(account.fetch("id"), "accessTokenExpiresAt" => Time.now - 60)

      token = auth.api.get_access_token(
        headers: {"cookie" => cookie_header(callback_headers.fetch("set-cookie"))},
        body: {providerId: "custom"}
      )

      assert_equal "refreshed-access-token", token.fetch(:accessToken)
      refresh_request = requests.reverse.find { |request| request[:path] == "/token" }
      assert_equal "refresh_token", refresh_request.fetch(:params).fetch("grant_type")
      assert_equal "http-refresh-token", refresh_request.fetch(:params).fetch("refresh_token")
      assert_match(/\ABasic /, refresh_request.fetch(:headers).fetch("authorization"))
    end
  end

  def test_generic_oauth_sets_and_refreshes_account_cookie
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        account: {store_account_cookie: true},
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo"
        }
      )
      _status, sign_in_headers, sign_in_body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      state = Rack::Utils.parse_query(URI.parse(JSON.parse(sign_in_body.join).fetch("url")).query).fetch("state")
      _callback_status, callback_headers, = auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: state},
        headers: {"cookie" => cookie_header(sign_in_headers.fetch("set-cookie"))},
        as_response: true
      )
      account_cookie = decoded_account_cookie(callback_headers.fetch("set-cookie"), auth)

      assert_equal "custom", account_cookie.fetch("providerId")
      assert_equal "http-sub", account_cookie.fetch("accountId")
      assert_equal "http-access-token", account_cookie.fetch("accessToken")

      _token_status, token_headers, = auth.api.refresh_token(
        headers: {"cookie" => cookie_header(callback_headers.fetch("set-cookie"))},
        body: {providerId: "custom"},
        as_response: true
      )
      refreshed_cookie = decoded_account_cookie(token_headers.fetch("set-cookie"), auth)

      assert_equal "refreshed-access-token", refreshed_cookie.fetch("accessToken")
      assert_equal "http-refresh-token", refreshed_cookie.fetch("refreshToken")
    end
  end

  def test_account_routes_can_read_generic_oauth_account_cookie
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        account: {store_account_cookie: true},
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo"
        }
      )
      _status, sign_in_headers, sign_in_body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      state = Rack::Utils.parse_query(URI.parse(JSON.parse(sign_in_body.join).fetch("url")).query).fetch("state")
      _callback_status, callback_headers, = auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: state},
        headers: {"cookie" => cookie_header(sign_in_headers.fetch("set-cookie"))},
        as_response: true
      )
      account = auth.context.internal_adapter.find_account_by_provider_id("http-sub", "custom")
      auth.context.internal_adapter.delete_account(account.fetch("id"))

      token = auth.api.get_access_token(
        headers: {"cookie" => cookie_header(callback_headers.fetch("set-cookie"))},
        body: {providerId: "custom"}
      )

      assert_equal "http-access-token", token.fetch(:accessToken)
      assert_equal ["openid", "email"], token.fetch(:scopes)
    end
  end

  def test_generic_oauth_encrypts_stored_tokens_and_returns_decrypted_access_token
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        account: {store_account_cookie: true, encrypt_oauth_tokens: true},
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo"
        }
      )
      _status, sign_in_headers, sign_in_body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      state = Rack::Utils.parse_query(URI.parse(JSON.parse(sign_in_body.join).fetch("url")).query).fetch("state")
      _callback_status, callback_headers, = auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: state},
        headers: {"cookie" => cookie_header(sign_in_headers.fetch("set-cookie"))},
        as_response: true
      )
      account = auth.context.internal_adapter.find_account_by_provider_id("http-sub", "custom")
      account_cookie = decoded_account_cookie(callback_headers.fetch("set-cookie"), auth)

      refute_equal "http-access-token", account.fetch("accessToken")
      refute_equal "http-refresh-token", account.fetch("refreshToken")
      refute_equal "http-access-token", account_cookie.fetch("accessToken")

      token = auth.api.get_access_token(
        headers: {"cookie" => cookie_header(callback_headers.fetch("set-cookie"))},
        body: {providerId: "custom"}
      )

      assert_equal "http-access-token", token.fetch(:accessToken)

      auth.context.internal_adapter.update_account(account.fetch("id"), "accessTokenExpiresAt" => Time.now - 60)
      refreshed = auth.api.get_access_token(
        headers: {"cookie" => cookie_header_without_account_data(callback_headers.fetch("set-cookie"), auth)},
        body: {providerId: "custom"}
      )

      assert_equal "refreshed-access-token", refreshed.fetch(:accessToken)
    end
  end

  private

  def build_auth(options = {})
    user_info = options.delete(:user_info) || {id: "oauth-sub", email: "oauth@example.com", name: "OAuth User", emailVerified: true, image: "https://example.com/avatar.png"}
    disable_implicit = options.delete(:disable_implicit_sign_up)
    provider_overrides = options.delete(:provider_overrides) || {}
    extra_options = options

    BetterAuth.auth(
      {
        base_url: "http://localhost:3000",
        secret: SECRET,
        database: :memory,
        email_and_password: {enabled: true},
        plugins: [
          BetterAuth::Plugins.generic_oauth(
            config: [
              {
                provider_id: "custom",
                authorization_url: "https://provider.example.com/authorize",
                token_url: "https://provider.example.com/token",
                issuer: "https://provider.example.com",
                client_id: "client-id",
                client_secret: "client-secret",
                scopes: ["profile", "email"],
                disable_implicit_sign_up: disable_implicit,
                get_token: ->(code:, **_data) {
                  raise "unexpected code" unless code == "oauth-code"

                  {
                    accessToken: "access-token",
                    refreshToken: "refresh-token",
                    idToken: "id-token",
                    scopes: ["openid", "email"]
                  }
                },
                get_user_info: ->(_tokens) { user_info }
              }.merge(provider_overrides)
            ]
          )
        ]
      }.merge(extra_options)
    )
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "OAuth User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def rack_env(method, path, body: nil, cookie: nil)
    path_info, query_string = path.split("?", 2)
    payload = body ? JSON.generate(body) : ""
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path_info,
      "QUERY_STRING" => query_string || "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(payload),
      "CONTENT_TYPE" => body ? "application/json" : nil,
      "CONTENT_LENGTH" => payload.bytesize.to_s,
      "HTTP_COOKIE" => cookie,
      "HTTP_ORIGIN" => "http://localhost:3000"
    }.compact
  end

  def cookie_header_without_account_data(set_cookie, auth)
    account_cookie = auth.context.auth_cookies[:account_data].name
    set_cookie.to_s.lines
      .reject { |line| line.start_with?("#{account_cookie}=") }
      .map { |line| line.split(";").first }
      .join("; ")
  end

  def decoded_account_cookie(set_cookie, auth)
    cookie_name = auth.context.auth_cookies[:account_data].name
    line = set_cookie.to_s.lines.find { |entry| entry.start_with?("#{cookie_name}=") && !entry.match?(/Max-Age=0/i) }
    value = line.to_s.split(";", 2).first.split("=", 2).last
    assert value && !value.empty?

    BetterAuth::Crypto.symmetric_decode_jwt(value, SECRET, "better-auth-account")
  end

  def with_oauth_server(requests)
    server = TCPServer.new("127.0.0.1", 0)
    @oauth_server_base_url = "http://127.0.0.1:#{server.addr[1]}"
    thread = Thread.new do
      loop do
        socket = server.accept
        request_line = socket.gets.to_s
        method, target = request_line.split
        headers = {}
        while (line = socket.gets)
          line = line.chomp
          break if line.empty?

          key, value = line.split(":", 2)
          headers[key.downcase] = value.to_s.strip
        end
        body = socket.read(headers["content-length"].to_i).to_s
        uri = URI.parse(target)
        params = (method == "POST") ? Rack::Utils.parse_nested_query(body) : Rack::Utils.parse_nested_query(uri.query.to_s)
        requests << {method: method, path: uri.path, headers: headers, params: params}
        response_body = oauth_server_response_body(uri.path, params)
        socket.write "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: #{response_body.bytesize}\r\nconnection: close\r\n\r\n#{response_body}"
      rescue IOError
        break
      ensure
        socket&.close
      end
    end
    yield @oauth_server_base_url
  ensure
    server&.close
    thread&.join
  end

  def oauth_server_response_body(path, params = {})
    if path == "/.well-known/openid-configuration"
      return JSON.generate(
        authorization_endpoint: "#{@oauth_server_base_url}/authorize",
        token_endpoint: "#{@oauth_server_base_url}/token",
        userinfo_endpoint: "#{@oauth_server_base_url}/userinfo",
        issuer: @oauth_server_base_url
      )
    end

    if path == "/token"
      access_token = (params["grant_type"] == "refresh_token") ? "refreshed-access-token" : "http-access-token"
      return JSON.generate(
        access_token: access_token,
        refresh_token: "http-refresh-token",
        expires_in: 3600,
        refresh_token_expires_in: 7200,
        scope: "openid email",
        token_type: "Bearer",
        raw_provider_field: "preserved"
      )
    end

    JSON.generate(
      sub: "http-sub",
      email: "http@example.com",
      name: "HTTP User",
      email_verified: true,
      picture: "https://example.com/http.png"
    )
  end
end

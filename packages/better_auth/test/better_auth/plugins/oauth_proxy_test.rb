# frozen_string_literal: true

require "json"
require "rack/mock"
require_relative "../../test_helper"

class BetterAuthPluginsOAuthProxyTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"

  def test_sign_in_social_rewrites_callback_to_current_url_proxy
    auth = build_auth(plugins: [BetterAuth::Plugins.oauth_proxy(current_url: "http://preview.local")])

    result = auth.api.sign_in_social(body: {provider: "google", callbackURL: "/dashboard"})
    state = Rack::Utils.parse_query(URI.parse(result[:url]).query).fetch("state")
    state_data = BetterAuth::Crypto.verify_jwt(state, auth.context.secret)

    assert_match(%r{\Ahttp://preview\.local/api/auth/oauth-proxy-callback\?callbackURL=%2Fdashboard\z}, state_data.fetch("callbackURL"))
  end

  def test_callback_to_cross_origin_proxy_appends_encrypted_cookies
    auth = build_auth(plugins: [BetterAuth::Plugins.oauth_proxy(current_url: "http://preview.local")])
    sign_in = auth.api.sign_in_social(body: {provider: "google", callbackURL: "/dashboard"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "google"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    location = headers.fetch("location")
    assert_match(%r{\Ahttp://preview\.local/api/auth/oauth-proxy-callback\?}, location)
    cookies = Rack::Utils.parse_query(URI.parse(location).query).fetch("cookies")
    payload = JSON.parse(BetterAuth::Crypto.symmetric_decrypt(key: auth.context.secret, data: cookies))
    assert_includes payload.fetch("cookies"), "better-auth.session_token="
    assert_kind_of Integer, payload.fetch("timestamp")
  end

  def test_callback_same_origin_unwraps_proxy_location
    auth = build_auth(plugins: [BetterAuth::Plugins.oauth_proxy(current_url: "http://localhost:3000", production_url: "http://localhost:3000")])
    sign_in = auth.api.sign_in_social(body: {provider: "google", callbackURL: "/dashboard"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "google"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
  end

  def test_oauth_proxy_callback_decrypts_cookies_sets_them_and_redirects
    auth = build_auth(plugins: [BetterAuth::Plugins.oauth_proxy(max_age: 60)])
    payload = {
      cookies: "sessionid=abcd1234; Path=/; HttpOnly\nstate=statevalue; Path=/",
      timestamp: (Time.now.to_f * 1000).to_i
    }
    encrypted = BetterAuth::Crypto.symmetric_encrypt(key: auth.context.secret, data: JSON.generate(payload))

    status, headers, _body = auth.api.o_auth_proxy(
      query: {callbackURL: "/dashboard", cookies: encrypted},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "sessionid=abcd1234"
    assert_includes headers.fetch("set-cookie"), "state=statevalue"
  end

  def test_oauth_proxy_uses_dedicated_secret_override
    proxy_secret = "proxy-secret-that-is-long-enough-for-override"
    auth = build_auth(plugins: [BetterAuth::Plugins.oauth_proxy(max_age: 60, secret: proxy_secret)])
    payload = {
      cookies: "sessionid=override-secret; Path=/; HttpOnly",
      timestamp: (Time.now.to_f * 1000).to_i
    }
    encrypted = BetterAuth::Crypto.symmetric_encrypt(key: proxy_secret, data: JSON.generate(payload))

    status, headers, _body = auth.api.o_auth_proxy(
      query: {callbackURL: "/dashboard", cookies: encrypted},
      as_response: true
    )

    assert_equal 302, status
    assert_includes headers.fetch("set-cookie"), "sessionid=override-secret"
  end

  def test_oauth_proxy_callback_rejects_expired_or_invalid_payloads
    auth = build_auth(plugins: [BetterAuth::Plugins.oauth_proxy(max_age: 5)])
    expired = BetterAuth::Crypto.symmetric_encrypt(
      key: auth.context.secret,
      data: JSON.generate({cookies: "sessionid=abcd1234", timestamp: ((Time.now - 10).to_f * 1000).to_i})
    )

    status, headers, _body = auth.api.o_auth_proxy(query: {callbackURL: "/dashboard", cookies: expired}, as_response: true)

    assert_equal 302, status
    assert_includes URI.decode_www_form_component(headers.fetch("location")), "Payload expired or invalid"

    status, headers, _body = auth.api.o_auth_proxy(query: {callbackURL: "/dashboard", cookies: "bad"}, as_response: true)
    assert_equal 302, status
    assert_includes URI.decode_www_form_component(headers.fetch("location")), "Invalid cookies or secret"

    missing_cookies = BetterAuth::Crypto.symmetric_encrypt(
      key: auth.context.secret,
      data: JSON.generate({timestamp: (Time.now.to_f * 1000).to_i})
    )
    status, headers, _body = auth.api.o_auth_proxy(query: {callbackURL: "/dashboard", cookies: missing_cookies}, as_response: true)
    assert_equal 302, status
    assert_includes URI.decode_www_form_component(headers.fetch("location")), "Invalid payload structure"
  end

  def test_oauth_proxy_callback_rejects_untrusted_callback_url
    auth = build_auth(trusted_origins: ["http://localhost:3000"], plugins: [BetterAuth::Plugins.oauth_proxy(max_age: 60)])
    payload = {
      cookies: "better-auth.session_token=session-token; Path=/; HttpOnly",
      timestamp: (Time.now.to_f * 1000).to_i
    }
    encrypted = BetterAuth::Crypto.symmetric_encrypt(key: auth.context.secret, data: JSON.generate(payload))

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth_proxy(query: {callbackURL: "https://evil.example/dashboard", cookies: encrypted})
    end

    assert_equal 403, error.status_code
    assert_equal "Invalid callbackURL", error.message
  end

  def test_stateless_oauth_proxy_encrypts_state_cookie_package
    auth = build_auth(
      database: nil,
      plugins: [
        BetterAuth::Plugins.oauth_proxy(current_url: "http://preview.local"),
        generic_oauth_plugin
      ]
    )

    _status, headers, body = auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", callbackURL: "/dashboard"},
      as_response: true
    )
    state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")
    decrypted = BetterAuth::Crypto.symmetric_decrypt(key: auth.context.secret, data: state)
    package = JSON.parse(decrypted)

    assert_includes headers.fetch("set-cookie"), "better-auth.oauth_state="
    assert package.fetch("state").length >= 20
    assert package.fetch("stateCookie").length > 20
    assert_equal true, package.fetch("isOAuthProxy")
  end

  def test_stateless_oauth_proxy_restores_state_cookie_for_dbless_callback_flow
    auth = build_auth(
      database: nil,
      plugins: [
        BetterAuth::Plugins.oauth_proxy(current_url: "http://preview.local"),
        generic_oauth_plugin
      ]
    )
    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard"})
    encrypted_state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")

    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: encrypted_state},
      as_response: true
    )

    assert_equal 302, status
    location = headers.fetch("location")
    assert_match(%r{\Ahttp://preview\.local/api/auth/oauth-proxy-callback\?}, location)
    assert_includes location, "callbackURL=%2Fdashboard"
    encrypted_cookies = Rack::Utils.parse_query(URI.parse(location).query).fetch("cookies")
    payload = JSON.parse(BetterAuth::Crypto.symmetric_decrypt(key: auth.context.secret, data: encrypted_cookies))
    assert_includes payload.fetch("cookies"), "better-auth.session_token="
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      social_providers: {
        google: {
          create_authorization_url: ->(data) { "https://accounts.google.com/o/oauth2/v2/auth?state=#{Rack::Utils.escape(data[:state])}" },
          validate_authorization_code: ->(_data) { {accessToken: "access-token", idToken: "id-token"} },
          get_user_info: ->(_tokens) { {user: {id: "google-sub", email: "proxy@example.com", name: "Proxy User", emailVerified: true}} }
        }
      }
    }.merge(options))
  end

  def generic_oauth_plugin
    BetterAuth::Plugins.generic_oauth(
      config: [
        {
          providerId: "custom",
          clientId: "client-id",
          clientSecret: "client-secret",
          authorizationUrl: "https://provider.example.com/authorize",
          tokenUrl: "https://provider.example.com/token",
          getToken: ->(**) { {accessToken: "access-token"} },
          getUserInfo: ->(_tokens) { {id: "custom-sub", email: "proxy-generic@example.com", name: "Proxy Generic", emailVerified: true} }
        }
      ]
    )
  end
end

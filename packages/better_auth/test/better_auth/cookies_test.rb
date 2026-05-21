# frozen_string_literal: true

require "test_helper"

class BetterAuthCookiesTest < Minitest::Test
  SECRET = "phase-four-secret-with-enough-entropy-123"

  def test_cookie_definitions_follow_upstream_defaults_and_secure_prefix
    auth = BetterAuth.auth(
      secret: SECRET,
      base_url: "https://example.com",
      advanced: {
        use_secure_cookies: true,
        cookie_prefix: "custom",
        cross_subdomain_cookies: {enabled: true}
      }
    )

    cookie = auth.context.auth_cookies[:session_token]

    assert_equal "__Secure-custom.session_token", cookie.name
    assert_equal true, cookie.attributes[:secure]
    assert_equal "lax", cookie.attributes[:same_site]
    assert_equal "/", cookie.attributes[:path]
    assert_equal true, cookie.attributes[:http_only]
    assert_equal "example.com", cookie.attributes[:domain]
    assert_equal 60 * 60 * 24 * 7, cookie.attributes[:max_age]
  end

  def test_advanced_cookie_overrides_name_and_attributes
    auth = BetterAuth.auth(
      secret: SECRET,
      advanced: {
        cookie_prefix: "custom",
        cookies: {
          session_token: {
            name: "sid",
            attributes: {same_site: "none", path: "/auth"}
          }
        }
      }
    )

    cookie = auth.context.auth_cookies[:session_token]

    assert_equal "sid", cookie.name
    assert_equal "none", cookie.attributes[:same_site]
    assert_equal "/auth", cookie.attributes[:path]
  end

  def test_session_cookie_parser_accepts_secure_and_legacy_names
    secure = "__Secure-better-auth.session_token=signed"
    legacy = "better-auth-session_token=legacy"

    assert_equal "signed", BetterAuth::Cookies.get_session_cookie(secure)
    assert_equal "legacy", BetterAuth::Cookies.get_session_cookie(legacy)
  end

  def test_signed_cookie_round_trip_and_rejects_tampering
    ctx = endpoint_context(BetterAuth.auth(secret: SECRET))

    ctx.set_signed_cookie("better-auth.session_token", "token-1", SECRET)
    cookie = ctx.response_headers.fetch("set-cookie")
    request_ctx = endpoint_context(BetterAuth.auth(secret: SECRET), cookie: cookie.split(";").first)

    assert_equal "token-1", request_ctx.get_signed_cookie("better-auth.session_token", SECRET)
    tampered = cookie.sub("token-1", "token-2")
    tampered_ctx = endpoint_context(BetterAuth.auth(secret: SECRET), cookie: tampered.split(";").first)
    assert_nil tampered_ctx.get_signed_cookie("better-auth.session_token", SECRET)
  end

  def test_parse_cookies_decodes_percent_encoded_values_without_rejecting_legacy_raw_values
    cookies = BetterAuth::Cookies.parse_cookies("json=%7B%22prompt%22%3A%22login%3Bstrict%22%7D; legacy=raw%ZZvalue")

    assert_equal "{\"prompt\":\"login;strict\"}", cookies.fetch("json")
    assert_equal "raw%ZZvalue", cookies.fetch("legacy")
  end

  def test_cookie_cache_compact_strategy_round_trips_and_validates_version
    auth = BetterAuth.auth(
      secret: SECRET,
      session: {cookie_cache: {enabled: true, strategy: "compact", version: "2"}}
    )
    ctx = endpoint_context(auth)
    data = {
      session: {"id" => "session-1", "token" => "token-1", "userId" => "user-1"},
      user: {"id" => "user-1", "email" => "ada@example.com"}
    }

    BetterAuth::Cookies.set_cookie_cache(ctx, data, false)
    cookie = ctx.response_headers.fetch("set-cookie").lines.find { |line| line.include?("session_data") }.split(";").first

    parsed = BetterAuth::Cookies.get_cookie_cache(cookie, secret: SECRET, strategy: "compact", version: "2")
    assert_equal "session-1", parsed["session"]["id"]
    assert_nil BetterAuth::Cookies.get_cookie_cache(cookie, secret: SECRET, strategy: "compact", version: "3")
  end

  def test_cookie_cache_uses_custom_session_data_cookie_name
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      email_and_password: {enabled: true},
      session: {cookie_cache: {enabled: true, max_age: 120}},
      advanced: {cookies: {session_data: {name: "custom.session_payload"}}}
    )

    status, headers, = auth.api.sign_up_email(
      body: {email: "custom-cache@example.com", password: "password123", name: "Cached"},
      as_response: true
    )
    assert_equal 200, status

    cookie = headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
    session = auth.api.get_session(headers: {"cookie" => cookie})
    user_id = session.fetch(:user).fetch("id")
    auth.context.adapter.update(model: "user", where: [{field: "id", value: user_id}], update: {name: "Database"})

    cached = auth.api.get_session(headers: {"cookie" => cookie})

    assert_equal "Cached", cached.fetch(:user).fetch("name")
  end

  def test_cookie_cache_supports_compact_jwt_and_jwe_strategies
    %w[compact jwt jwe].each do |strategy|
      auth = BetterAuth.auth(
        secret: SECRET,
        session: {cookie_cache: {enabled: true, strategy: strategy, version: "1"}}
      )
      ctx = endpoint_context(auth)

      BetterAuth::Cookies.set_cookie_cache(ctx, {
        session: {"id" => "session-1", "token" => "token-1", "userId" => "user-1"},
        user: {"id" => "user-1", "email" => "ada@example.com"}
      }, false)

      cookie = ctx.response_headers.fetch("set-cookie").lines.find { |line| line.include?("session_data") }.split(";").first
      payload = BetterAuth::Cookies.get_cookie_cache(cookie, secret: SECRET, strategy: strategy, version: "1")

      assert_equal "token-1", payload.fetch("session").fetch("token")
      assert_equal "ada@example.com", payload.fetch("user").fetch("email")
    end
  end

  def test_jwe_cookie_cache_and_account_cookie_survive_secret_rotation
    old_auth = BetterAuth.auth(
      secret: "legacy-secret-that-is-long-enough-for-cookies",
      secrets: [{version: 1, value: "old-secret-that-is-long-enough-for-cookies"}],
      session: {cookie_cache: {enabled: true, strategy: "jwe"}},
      account: {store_account_cookie: true}
    )
    old_ctx = endpoint_context(old_auth)

    BetterAuth::Cookies.set_cookie_cache(old_ctx, {
      session: {"id" => "session-1", "token" => "token-1", "userId" => "user-1"},
      user: {"id" => "user-1", "email" => "ada@example.com"}
    }, false)
    BetterAuth::Cookies.set_account_cookie(old_ctx, {"providerId" => "github", "accountId" => "account-1"})

    header = old_ctx.response_headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
    new_auth = BetterAuth.auth(
      secret: "legacy-secret-that-is-long-enough-for-cookies",
      secrets: [
        {version: 2, value: "new-secret-that-is-long-enough-for-cookies"},
        {version: 1, value: "old-secret-that-is-long-enough-for-cookies"}
      ],
      session: {cookie_cache: {enabled: true, strategy: "jwe"}},
      account: {store_account_cookie: true}
    )
    new_ctx = endpoint_context(new_auth, cookie: header)

    session_cookie = BetterAuth::SessionStore.get_chunked_cookie(new_ctx, new_auth.context.auth_cookies[:session_data].name)
    session_payload = BetterAuth::Cookies.decode_cookie_cache(session_cookie, new_auth.context.secret_config, strategy: "jwe")

    assert_equal "token-1", session_payload.fetch("session").fetch("token")
    assert_equal "account-1", BetterAuth::Cookies.get_account_cookie(new_ctx).fetch("accountId")
  end

  def test_cookie_cache_filters_fields_marked_returned_false
    auth = BetterAuth.auth(
      secret: SECRET,
      session: {cookie_cache: {enabled: true, strategy: "jwt"}},
      plugins: [
        {
          id: "private-cache-field",
          schema: {
            user: {
              fields: {
                secretNote: {type: "string", returned: false}
              }
            },
            session: {
              fields: {
                serverOnly: {type: "string", returned: false}
              }
            }
          }
        }
      ]
    )
    ctx = endpoint_context(auth)

    BetterAuth::Cookies.set_cookie_cache(ctx, {
      session: {
        "id" => "session-1",
        "token" => "token-1",
        "userId" => "user-1",
        "serverOnly" => "do-not-cache"
      },
      user: {
        "id" => "user-1",
        "email" => "ada@example.com",
        "secretNote" => "do-not-cache"
      }
    }, false)

    cookie = ctx.response_headers.fetch("set-cookie").lines.find { |line| line.include?("session_data") }.split(";").first
    payload = BetterAuth::Cookies.get_cookie_cache(cookie, secret: SECRET, strategy: "jwt")

    refute payload.fetch("session").key?("serverOnly")
    refute payload.fetch("user").key?("secretNote")
  end

  def test_session_store_chunks_and_reassembles_large_values
    auth = BetterAuth.auth(secret: SECRET)
    ctx = endpoint_context(auth)
    store = BetterAuth::SessionStore.new("better-auth.session_data", {}, ctx)
    cookies = store.chunk("x" * 8_000)

    assert_operator cookies.length, :>, 1
    store.set_cookies(cookies)

    header = ctx.response_headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
    request_ctx = endpoint_context(auth, cookie: header)
    assert_equal "x" * 8_000, BetterAuth::SessionStore.get_chunked_cookie(request_ctx, "better-auth.session_data")
  end

  private

  def endpoint_context(auth, cookie: nil)
    headers = {}
    headers["cookie"] = cookie if cookie
    BetterAuth::Endpoint::Context.new(
      path: "/test",
      method: "GET",
      query: {},
      body: {},
      params: {},
      headers: headers,
      context: auth.context
    )
  end
end

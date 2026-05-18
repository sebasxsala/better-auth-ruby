# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthRoutesSessionTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_get_session_returns_nil_without_cookie
    auth = build_auth

    assert_nil auth.api.get_session
  end

  def test_get_session_endpoint_accepts_get_and_post_like_upstream
    auth = build_auth

    assert_equal ["GET", "POST"], auth.api.endpoints.fetch(:get_session).methods
  end

  def test_get_session_post_requires_deferred_refresh
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "post-session@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.get_session(headers: {"cookie" => cookie}, method: "POST")
    end

    assert_equal 405, error.status_code
    assert_equal "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED", error.code
    assert_equal BetterAuth::BASE_ERROR_CODES["METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED"], error.message
  end

  def test_update_session_requires_body_object_like_upstream
    auth = build_auth(
      session: {
        additional_fields: {
          activeOrganizationId: {type: "string", required: false}
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "session-body-object@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_session(headers: {"cookie" => cookie}, body: ["not-object"])
    end

    assert_equal 400, error.status_code
    assert_equal "BODY_MUST_BE_AN_OBJECT", error.code
    assert_equal BetterAuth::BASE_ERROR_CODES["BODY_MUST_BE_AN_OBJECT"], error.message
  end

  def test_get_session_deferred_get_reports_needs_refresh_without_updating_session
    auth = build_auth(session: {defer_session_refresh: true, update_age: 60, expires_in: 120, cookie_cache: {enabled: false}})
    cookie = sign_up_cookie(auth, email: "deferred-session@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie}, method: "POST")
    stale_updated_at = Time.now - 61
    auth.context.adapter.update(
      model: "session",
      where: [{field: "token", value: session[:session]["token"]}],
      update: {updatedAt: stale_updated_at, expiresAt: Time.now + 30}
    )

    result = auth.api.get_session(headers: {"cookie" => cookie})
    stored = auth.context.adapter.find_one(model: "session", where: [{field: "token", value: session[:session]["token"]}])

    assert_equal true, result[:needsRefresh]
    assert_in_delta stale_updated_at.to_i, stored.fetch("updatedAt").to_i, 1
  end

  def test_get_session_deferred_post_refreshes_stale_session
    auth = build_auth(session: {defer_session_refresh: true, update_age: 60, expires_in: 120, cookie_cache: {enabled: false}})
    cookie = sign_up_cookie(auth, email: "deferred-post-refresh@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie}, method: "POST")
    stale_updated_at = Time.now - 61
    auth.context.adapter.update(
      model: "session",
      where: [{field: "token", value: session[:session]["token"]}],
      update: {updatedAt: stale_updated_at, expiresAt: Time.now + 30}
    )

    result = auth.api.get_session(headers: {"cookie" => cookie}, method: "POST")
    stored = auth.context.adapter.find_one(model: "session", where: [{field: "token", value: session[:session]["token"]}])

    assert_equal "deferred-post-refresh@example.com", result[:user]["email"]
    refute result.key?(:needsRefresh)
    assert_operator stored.fetch("updatedAt"), :>, stale_updated_at
  end

  def test_get_session_returns_current_session_and_user
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "session@example.com")

    result = auth.api.get_session(headers: {"cookie" => cookie})

    assert_equal "session@example.com", result[:user]["email"]
    assert_match(/\A[0-9a-f]{32}\z/, result[:session]["token"])
    assert_equal result[:user]["id"], result[:session]["userId"]
  end

  def test_sign_in_sets_session_cookie_attributes
    auth = build_auth
    sign_up_cookie(auth, email: "cookie-attributes@example.com")

    status, headers, _body = auth.api.sign_in_email(
      body: {email: "cookie-attributes@example.com", password: "password123"},
      as_response: true
    )

    assert_equal 200, status
    session_cookie = headers.fetch("set-cookie").lines.find { |line| line.include?("better-auth.session_token=") }
    assert_includes session_cookie, "Max-Age=604800"
    assert_includes session_cookie, "Path=/"
    assert_includes session_cookie, "SameSite=Lax"
    assert_includes session_cookie, "HttpOnly"
  end

  def test_get_session_refreshes_database_session_when_update_age_is_reached
    auth = build_auth(session: {update_age: 60, expires_in: 120, cookie_cache: {enabled: false}})
    cookie = sign_up_cookie(auth, email: "refresh-age@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie})
    original_expires_at = session[:session]["expiresAt"]

    auth.context.adapter.update(
      model: "session",
      where: [{field: "token", value: session[:session]["token"]}],
      update: {updatedAt: Time.now - 61, expiresAt: Time.now + 30}
    )
    stale_expires_at = auth.context.adapter.find_one(model: "session", where: [{field: "token", value: session[:session]["token"]}]).fetch("expiresAt")

    status, headers, body = auth.api.get_session(headers: {"cookie" => cookie}, as_response: true)
    refreshed = JSON.parse(body.join)

    assert_equal 200, status
    assert_operator Time.parse(refreshed.fetch("session").fetch("expiresAt")), :>, stale_expires_at
    assert_operator Time.parse(refreshed.fetch("session").fetch("expiresAt")), :>=, Time.parse(original_expires_at.to_s)
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_includes headers.fetch("set-cookie"), "Max-Age=120"
  end

  def test_get_session_disable_refresh_leaves_stale_database_session_unchanged
    auth = build_auth(session: {update_age: 60, expires_in: 120, cookie_cache: {enabled: false}})
    cookie = sign_up_cookie(auth, email: "disable-refresh@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie})
    stale_expires_at = Time.now + 30
    stale_updated_at = Time.now - 61
    auth.context.adapter.update(
      model: "session",
      where: [{field: "token", value: session[:session]["token"]}],
      update: {updatedAt: stale_updated_at, expiresAt: stale_expires_at}
    )

    status, headers, body = auth.api.get_session(
      headers: {"cookie" => cookie},
      query: {disableRefresh: true},
      as_response: true
    )
    result = JSON.parse(body.join)
    stored = auth.context.adapter.find_one(model: "session", where: [{field: "token", value: session[:session]["token"]}])

    assert_equal 200, status
    refute headers.fetch("set-cookie", "").include?("better-auth.session_token=")
    assert_in_delta stale_expires_at.to_i, Time.parse(result.fetch("session").fetch("expiresAt")).to_i, 1
    assert_in_delta stale_updated_at.to_i, stored.fetch("updatedAt").to_i, 1
  end

  def test_get_session_with_expired_database_session_returns_null_and_clears_cookie
    auth = build_auth(session: {cookie_cache: {enabled: false}})
    cookie = sign_up_cookie(auth, email: "expired-session@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie})
    auth.context.adapter.update(
      model: "session",
      where: [{field: "token", value: session[:session]["token"]}],
      update: {expiresAt: Time.now - 1}
    )

    status, headers, body = auth.api.get_session(headers: {"cookie" => cookie}, as_response: true)

    assert_equal 200, status
    assert_nil JSON.parse(body.join)
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_includes headers.fetch("set-cookie"), "Max-Age=0"
  end

  def test_get_session_disable_cookie_cache_reads_authoritative_database
    auth = build_auth(session: {cookie_cache: {enabled: true, strategy: "jwe", max_age: 300}})
    cookie = sign_up_cookie(auth, email: "disable-cache@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie})
    auth.context.adapter.update(
      model: "user",
      where: [{field: "id", value: session[:user]["id"]}],
      update: {name: "Authoritative Name"}
    )

    cached = auth.api.get_session(headers: {"cookie" => cookie})
    authoritative = auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true})

    refute_equal "Authoritative Name", cached[:user]["name"]
    assert_equal "Authoritative Name", authoritative[:user]["name"]
  end

  def test_get_session_with_tampered_cache_falls_back_to_database_and_refreshes_cache
    auth = build_auth(session: {cookie_cache: {enabled: true, strategy: "jwe", max_age: 300}})
    cookie = sign_up_cookie(auth, email: "tampered-cache@example.com")
    tampered = cookie.gsub(/better-auth\.session_data=[^; ]+/, "better-auth.session_data=invalid")

    status, headers, body = auth.api.get_session(headers: {"cookie" => tampered}, as_response: true)

    assert_equal 200, status
    assert_equal "tampered-cache@example.com", JSON.parse(body.join).fetch("user").fetch("email")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_data="
  end

  def test_cookie_cache_version_mismatch_falls_back_to_authoritative_session
    auth = build_auth(session: {cookie_cache: {enabled: true, strategy: "jwe", version: "1", max_age: 300}})
    cookie = sign_up_cookie(auth, email: "version-cache@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie})
    auth.context.adapter.update(
      model: "user",
      where: [{field: "id", value: session[:user]["id"]}],
      update: {name: "Fresh User"}
    )
    auth.context.session_config[:cookie_cache] = auth.context.session_config[:cookie_cache].merge(version: "2")

    result = auth.api.get_session(headers: {"cookie" => cookie})

    assert_equal "Fresh User", result[:user]["name"]
  end

  def test_stateless_cookie_cache_refresh_extends_session_token_cookie
    auth = build_auth(database: nil, session: {expires_in: 300, cookie_cache: {enabled: true, strategy: "jwe", max_age: 300, refresh_cache: {update_age: 0}}})
    cookie = sign_up_cookie(auth, email: "stateless-refresh@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie})
    auth.context.internal_adapter.delete_session(session[:session]["token"])

    status, headers, body = auth.api.get_session(headers: {"cookie" => cookie}, as_response: true)
    refreshed = JSON.parse(body.join)

    assert_equal 200, status
    assert_equal "stateless-refresh@example.com", refreshed.fetch("user").fetch("email")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_data="
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_includes headers.fetch("set-cookie"), "Max-Age=300"
  end

  def test_remember_me_false_stays_session_cookie_after_refresh
    auth = build_auth(session: {update_age: 0, expires_in: 120, cookie_cache: {enabled: false}})
    _signup_cookie = sign_up_cookie(auth, email: "browser-session@example.com")

    status, headers, _body = auth.api.sign_in_email(
      body: {email: "browser-session@example.com", password: "password123", rememberMe: false},
      as_response: true
    )
    assert_equal 200, status
    cookie = cookie_header(headers.fetch("set-cookie"))
    session_cookie_line = headers.fetch("set-cookie").lines.find { |line| line.include?("session_token") }
    refute_includes session_cookie_line, "Max-Age="

    _status, refresh_headers, _refresh_body = auth.api.get_session(headers: {"cookie" => cookie}, as_response: true)
    refreshed_session_cookie_line = refresh_headers.fetch("set-cookie").lines.find { |line| line.include?("session_token") }
    refute_includes refreshed_session_cookie_line, "Max-Age="
  end

  def test_sign_out_deletes_current_session_and_clears_cookies
    deleted = []
    auth = build_auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database_hooks: {
        session: {
          delete: {
            after: ->(session, _context) { deleted << session["token"] }
          }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "sign-out@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie})

    status, headers, body = auth.api.sign_out(headers: {"cookie" => cookie}, as_response: true)

    assert_equal 200, status
    assert_equal({"success" => true}, JSON.parse(body.join))
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_includes headers.fetch("set-cookie"), "Max-Age=0"
    assert_includes deleted, session[:session]["token"]
    assert_nil auth.context.internal_adapter.find_session(session[:session]["token"])
    assert_nil auth.api.get_session(headers: {"cookie" => cookie})
  end

  def test_list_sessions_returns_active_sessions_for_current_user
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "list@example.com")
    second_cookie = sign_in_cookie(auth, email: "list@example.com")

    result = auth.api.list_sessions(headers: {"cookie" => second_cookie})

    assert_equal 2, result.length
    assert_equal [auth.api.get_session(headers: {"cookie" => cookie})[:session]["userId"]], result.map { |session| session["userId"] }.uniq
  end

  def test_update_session_returns_updated_session_payload
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.additional_fields(
          session: {
            deviceName: {type: "string", required: false}
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "update-session@example.com")

    result = auth.api.update_session(headers: {"cookie" => cookie}, body: {deviceName: "mobile"})

    assert_equal "mobile", result.fetch(:session).fetch("deviceName")
    refute result.key?(:user)
  end

  def test_update_session_ignores_core_fields_and_updates_cookie
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.additional_fields(
          session: {
            deviceName: {type: "string", required: false}
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "update-session-core-fields@example.com")
    original = auth.api.get_session(headers: {"cookie" => cookie})

    result = auth.api.update_session(
      headers: {"cookie" => cookie},
      body: {
        token: "attacker-token",
        userId: "attacker-user",
        expiresAt: Time.now + 86_400,
        deviceName: "tablet"
      },
      return_headers: true
    )
    refreshed_cookie = cookie_header(result.fetch(:headers).fetch("set-cookie"))
    refreshed = auth.api.get_session(headers: {"cookie" => refreshed_cookie})

    assert_equal "tablet", result.fetch(:response).fetch(:session).fetch("deviceName")
    assert_equal original[:session]["token"], refreshed[:session]["token"]
    assert_equal original[:session]["userId"], refreshed[:session]["userId"]
    assert_equal "tablet", refreshed[:session]["deviceName"]
  end

  def test_update_session_allows_stale_regular_session
    auth = build_auth(
      session: {fresh_age: 1, expires_in: 3600, update_age: 3600},
      plugins: [
        BetterAuth::Plugins.additional_fields(
          session: {
            deviceName: {type: "string", required: false}
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "stale-update-session@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie})[:session]
    auth.context.internal_adapter.update_session(
      session["token"],
      "createdAt" => Time.now - 120,
      "updatedAt" => Time.now - 120
    )

    result = auth.api.update_session(headers: {"cookie" => cookie}, body: {deviceName: "desktop"})

    assert_equal "desktop", result.fetch(:session).fetch("deviceName")
  end

  def test_revoke_session_deletes_only_matching_user_session
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "revoke@example.com")
    second_cookie = sign_in_cookie(auth, email: "revoke@example.com")
    first_token = auth.api.get_session(headers: {"cookie" => first_cookie})[:session]["token"]

    result = auth.api.revoke_session(headers: {"cookie" => second_cookie}, body: {token: first_token})

    assert_equal({status: true}, result)
    assert_nil auth.api.get_session(headers: {"cookie" => first_cookie})
    refute_nil auth.api.get_session(headers: {"cookie" => second_cookie})
  end

  def test_sensitive_session_routes_ignore_cookie_cache_without_requiring_fresh_session
    auth = build_auth(session: {fresh_age: 60, cookie_cache: {enabled: true, strategy: "jwe", max_age: 300}})
    cookie = sign_up_cookie(auth, email: "stale-sensitive@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie})
    auth.context.adapter.update(
      model: "session",
      where: [{field: "token", value: session[:session]["token"]}],
      update: {createdAt: Time.now - 300, updatedAt: Time.now - 300}
    )

    assert_equal({status: true}, auth.api.revoke_sessions(headers: {"cookie" => cookie}))
    assert_nil auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true})
  end

  def test_revoke_sessions_deletes_all_current_user_sessions
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "revoke-all@example.com")
    second_cookie = sign_in_cookie(auth, email: "revoke-all@example.com")

    result = auth.api.revoke_sessions(headers: {"cookie" => second_cookie})

    assert_equal({status: true}, result)
    assert_nil auth.api.get_session(headers: {"cookie" => first_cookie})
    assert_nil auth.api.get_session(headers: {"cookie" => second_cookie})
  end

  def test_revoke_other_sessions_keeps_current_session
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "revoke-other@example.com")
    second_cookie = sign_in_cookie(auth, email: "revoke-other@example.com")

    result = auth.api.revoke_other_sessions(headers: {"cookie" => second_cookie})

    assert_equal({status: true}, result)
    assert_nil auth.api.get_session(headers: {"cookie" => first_cookie})
    refute_nil auth.api.get_session(headers: {"cookie" => second_cookie})
  end

  def test_secondary_storage_stores_lists_and_revokes_session
    storage = StringStorage.new
    auth = build_auth(secondary_storage: storage)
    cookie = sign_up_cookie(auth, email: "secondary-session@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie})
    user_id = session[:user]["id"]
    token = session[:session]["token"]

    assert_equal ["active-sessions-#{user_id}", token].sort, storage.keys.sort
    stored_session = JSON.parse(storage.get(token))
    assert_equal user_id, stored_session.fetch("user").fetch("id")
    assert_equal user_id, stored_session.fetch("session").fetch("userId")
    assert stored_session.fetch("session").fetch("id")
    active_sessions = JSON.parse(storage.get("active-sessions-#{user_id}"))
    assert_equal [{"token" => token, "expiresAt" => active_sessions.first.fetch("expiresAt")}], active_sessions
    assert_equal [token], auth.api.list_sessions(headers: {"cookie" => cookie}).map { |entry| entry["token"] }

    result = auth.api.revoke_session(headers: {"cookie" => cookie}, body: {token: token})

    assert_equal({status: true}, result)
    assert_empty storage.keys
    assert_nil auth.api.get_session(headers: {"cookie" => cookie})
  end

  def test_secondary_storage_can_return_already_parsed_objects
    storage = ObjectStorage.new
    auth = build_auth(secondary_storage: storage)
    cookie = sign_up_cookie(auth, email: "object-storage@example.com")

    session = auth.api.get_session(headers: {"cookie" => cookie})
    active = storage.get("active-sessions-#{session[:user]["id"]}")

    assert_kind_of Array, active
    assert_equal 1, active.length
    assert_equal 1, auth.api.list_sessions(headers: {"cookie" => cookie}).length

    result = auth.api.revoke_session(headers: {"cookie" => cookie}, body: {token: session[:session]["token"]})

    assert_equal({status: true}, result)
    assert_nil auth.api.get_session(headers: {"cookie" => cookie})
    assert_nil storage.get("active-sessions-#{session[:user]["id"]}")
  end

  def test_revoke_session_deletes_database_copy_when_secondary_storage_database_preserve_is_false
    storage = StringStorage.new
    auth = build_auth(secondary_storage: storage, session: {store_session_in_database: true, preserve_session_in_database: false})
    cookie = sign_up_cookie(auth, email: "secondary-db-delete@example.com")
    token = auth.api.get_session(headers: {"cookie" => cookie})[:session]["token"]

    result = auth.api.revoke_session(headers: {"cookie" => cookie}, body: {token: token})

    assert_equal({status: true}, result)
    assert_nil storage.get(token)
    assert_nil auth.context.adapter.find_one(model: "session", where: [{field: "token", value: token}])
    assert_nil auth.api.get_session(headers: {"cookie" => cookie})
  end

  def test_revoke_session_preserves_database_copy_without_restoring_revoked_secondary_session
    storage = StringStorage.new
    auth = build_auth(secondary_storage: storage, session: {store_session_in_database: true, preserve_session_in_database: true})
    cookie = sign_up_cookie(auth, email: "secondary-db-preserve@example.com")
    token = auth.api.get_session(headers: {"cookie" => cookie})[:session]["token"]

    result = auth.api.revoke_session(headers: {"cookie" => cookie}, body: {token: token})

    assert_equal({status: true}, result)
    assert_nil storage.get(token)
    assert auth.context.adapter.find_one(model: "session", where: [{field: "token", value: token}])
    assert_nil auth.api.get_session(headers: {"cookie" => cookie})
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Session User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def sign_in_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_in_email(
      body: {email: email, password: "password123"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end

  class ObjectStorage
    def initialize
      @store = {}
    end

    def set(key, value, _ttl = nil)
      @store[key] = JSON.parse(value)
    end

    def get(key)
      @store[key]
    end

    def delete(key)
      @store.delete(key)
    end
  end

  class StringStorage
    def initialize
      @store = {}
    end

    def set(key, value, _ttl = nil)
      @store[key] = value
    end

    def get(key)
      @store[key]
    end

    def delete(key)
      @store.delete(key)
    end

    def keys
      @store.keys
    end
  end
end

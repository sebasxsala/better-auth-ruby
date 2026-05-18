# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthRoutesUserTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_update_user_updates_profile_and_rejects_email
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "update@example.com", password: "password123")

    assert_equal({status: true}, auth.api.update_user(headers: {"cookie" => cookie}, body: {name: "Updated", image: nil}))
    assert_equal "Updated", auth.api.get_session(headers: {"cookie" => cookie})[:user]["name"]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_user(headers: {"cookie" => cookie}, body: {email: "other@example.com"})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["EMAIL_CAN_NOT_BE_UPDATED"], error.message
  end

  def test_update_user_requires_body_object_like_upstream
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "body-object@example.com", password: "password123")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_user(headers: {"cookie" => cookie}, body: "not-object")
    end

    assert_equal 400, error.status_code
    assert_equal "BODY_MUST_BE_AN_OBJECT", error.code
    assert_equal BetterAuth::BASE_ERROR_CODES["BODY_MUST_BE_AN_OBJECT"], error.message
  end

  def test_change_password_updates_password_and_can_revoke_other_sessions
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "change-password@example.com", password: "password123")
    second_cookie = sign_in_cookie(auth, email: "change-password@example.com", password: "password123")

    result = auth.api.change_password(
      headers: {"cookie" => second_cookie},
      body: {currentPassword: "password123", newPassword: "new-password", revokeOtherSessions: true}
    )

    assert_match(/\A[0-9a-f]{32}\z/, result[:token])
    assert_nil auth.api.get_session(headers: {"cookie" => first_cookie})
    assert auth.api.sign_in_email(body: {email: "change-password@example.com", password: "new-password"})[:token]
  end

  def test_change_password_accepts_snake_case_body_aliases
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "change-password-snake@example.com", password: "password123")

    result = auth.api.change_password(
      headers: {"cookie" => cookie},
      body: {current_password: "password123", new_password: "new-password"}
    )

    assert_nil result[:token]
    assert auth.api.sign_in_email(body: {email: "change-password-snake@example.com", password: "new-password"})[:token]
  end

  def test_change_password_updates_credential_account_updated_at
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "change-updated-at@example.com", password: "password123")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "credential" }
    original_updated_at = account.fetch("updatedAt")

    auth.api.change_password(
      headers: {"cookie" => cookie},
      body: {currentPassword: "password123", newPassword: "new-password"}
    )

    updated_account = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "credential" }
    assert_operator updated_account.fetch("updatedAt"), :>, original_updated_at
  end

  def test_change_password_uses_configured_custom_password_callbacks
    auth = build_auth(
      email_and_password: {
        password: {
          hash: ->(password) { "custom:#{password.reverse}" },
          verify: ->(password, digest) { digest == "custom:#{password.reverse}" }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "custom-change@example.com", password: "password123")

    auth.api.change_password(
      headers: {"cookie" => cookie},
      body: {currentPassword: "password123", newPassword: "new-password"}
    )

    account = auth.context.adapter.find_one(model: "account", where: [{field: "providerId", value: "credential"}])
    assert_equal "custom:drowssap-wen", account["password"]
    assert auth.api.sign_in_email(body: {email: "custom-change@example.com", password: "new-password"})[:token]
  end

  def test_set_password_creates_credential_account_for_session_user_without_password
    auth = build_auth
    user = auth.context.internal_adapter.create_user(email: "set-password@example.com", name: "Set", emailVerified: true)
    cookie = session_cookie(auth, user)

    assert_equal({status: true}, auth.api.set_password(headers: {"cookie" => cookie}, body: {newPassword: "password123"}))
    assert auth.api.sign_in_email(body: {email: "set-password@example.com", password: "password123"})[:token]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.set_password(headers: {"cookie" => cookie}, body: {newPassword: "another-password"})
    end
    assert_equal 400, error.status_code
    assert_equal "BAD_REQUEST", error.code
    assert_equal BetterAuth::BASE_ERROR_CODES["PASSWORD_ALREADY_SET"], error.message
  end

  def test_change_password_allows_stale_sensitive_session
    auth = build_auth(session: {fresh_age: 1, expires_in: 3600, update_age: 3600})
    cookie = sign_up_cookie(auth, email: "stale-change-password@example.com", password: "password123")
    session = auth.api.get_session(headers: {"cookie" => cookie})[:session]
    auth.context.internal_adapter.update_session(
      session["token"],
      "createdAt" => Time.now - 120,
      "updatedAt" => Time.now - 120
    )

    result = auth.api.change_password(
      headers: {"cookie" => cookie},
      body: {currentPassword: "password123", newPassword: "new-password"}
    )

    assert_nil result[:token]
    assert auth.api.sign_in_email(body: {email: "stale-change-password@example.com", password: "new-password"})[:token]
  end

  def test_change_password_reports_missing_credential_account
    auth = build_auth
    user = auth.context.internal_adapter.create_user(email: "social-only-change@example.com", name: "Social", emailVerified: true)
    auth.context.internal_adapter.create_account(userId: user["id"], providerId: "github", accountId: "gh-social-change")
    cookie = session_cookie(auth, user)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.change_password(
        headers: {"cookie" => cookie},
        body: {currentPassword: "password123", newPassword: "new-password"}
      )
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["CREDENTIAL_ACCOUNT_NOT_FOUND"], error.message
  end

  def test_change_email_updates_unverified_user_when_enabled
    auth = build_auth(user: {change_email: {enabled: true, update_email_without_verification: true}})
    cookie = sign_up_cookie(auth, email: "old-email@example.com", password: "password123")

    assert_equal({status: true}, auth.api.change_email(headers: {"cookie" => cookie}, body: {newEmail: "new-email@example.com"}))
    assert_equal "new-email@example.com", auth.context.internal_adapter.find_user_by_email("new-email@example.com")[:user]["email"]
  end

  def test_change_email_accepts_snake_case_new_email_alias
    auth = build_auth(user: {change_email: {enabled: true, update_email_without_verification: true}})
    cookie = sign_up_cookie(auth, email: "old-snake-email@example.com", password: "password123")

    result = auth.api.change_email(headers: {"cookie" => cookie}, body: {new_email: "new-snake-email@example.com"})

    assert_equal({status: true}, result)
    assert_equal "new-snake-email@example.com", auth.context.internal_adapter.find_user_by_email("new-snake-email@example.com")[:user]["email"]
  end

  def test_change_email_update_without_verification_sends_verification_for_new_email
    sent = []
    auth = build_auth(
      user: {change_email: {enabled: true, update_email_without_verification: true}},
      email_verification: {send_verification_email: ->(data, _request = nil) { sent << data }}
    )
    cookie = sign_up_cookie(auth, email: "old-unverified-sender@example.com", password: "password123")

    assert_equal(
      {status: true},
      auth.api.change_email(headers: {"cookie" => cookie}, body: {newEmail: "new-unverified-sender@example.com"})
    )

    assert_equal 1, sent.length
    assert_equal "new-unverified-sender@example.com", sent.first.fetch(:user).fetch("email")
    auth.api.verify_email(query: {token: sent.first.fetch(:token)})
    user = auth.context.internal_adapter.find_user_by_email("new-unverified-sender@example.com")[:user]
    assert_equal true, user["emailVerified"]
  end

  def test_change_email_secure_flow_returns_success_when_target_email_exists
    sent = []
    auth = build_auth(
      user: {change_email: {enabled: true}},
      email_verification: {send_verification_email: ->(data, _request = nil) { sent << data }}
    )
    cookie = sign_up_cookie(auth, email: "source-existing-target@example.com", password: "password123")
    sign_up_cookie(auth, email: "target-existing@example.com", password: "password123")

    assert_equal({status: true}, auth.api.change_email(headers: {"cookie" => cookie}, body: {newEmail: "target-existing@example.com"}))

    assert_empty sent
    assert auth.context.internal_adapter.find_user_by_email("source-existing-target@example.com")
  end

  def test_change_email_without_sender_returns_same_error_for_existing_and_new_targets
    auth = build_auth(user: {change_email: {enabled: true}})
    cookie = sign_up_cookie(auth, email: "source-no-sender@example.com", password: "password123")
    sign_up_cookie(auth, email: "target-no-sender@example.com", password: "password123")

    existing = assert_raises(BetterAuth::APIError) do
      auth.api.change_email(headers: {"cookie" => cookie}, body: {newEmail: "target-no-sender@example.com"})
    end
    missing = assert_raises(BetterAuth::APIError) do
      auth.api.change_email(headers: {"cookie" => cookie}, body: {newEmail: "new-no-sender@example.com"})
    end

    assert_equal 400, existing.status_code
    assert_equal 400, missing.status_code
    assert_equal missing.message, existing.message
  end

  def test_update_user_rejects_input_false_additional_fields
    auth = build_auth(
      user: {
        additional_fields: {
          role: {type: "string", required: false, input: false}
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "input-false-update@example.com", password: "password123")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_user(headers: {"cookie" => cookie}, body: {role: "admin"})
    end

    assert_equal 400, error.status_code
    assert_equal "role is not allowed to be set", error.message
  end

  def test_delete_user_disabled_returns_not_found
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "delete-disabled@example.com", password: "password123")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_user(headers: {"cookie" => cookie}, body: {password: "password123"})
    end

    assert_equal 404, error.status_code
  end

  def test_delete_user_requires_fresh_session_when_no_password_or_verification_token_is_provided
    auth = build_auth(
      session: {fresh_age: 1, expires_in: 3600, update_age: 3600},
      user: {delete_user: {enabled: true}}
    )
    cookie = sign_up_cookie(auth, email: "stale-delete@example.com", password: "password123")
    session = auth.api.get_session(headers: {"cookie" => cookie})[:session]
    auth.context.internal_adapter.update_session(
      session["token"],
      "createdAt" => Time.now - 120,
      "updatedAt" => Time.now - 120
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_user(headers: {"cookie" => cookie}, body: {})
    end

    assert_equal 400, error.status_code
    assert_equal "SESSION_EXPIRED", error.code
    assert_equal BetterAuth::BASE_ERROR_CODES["SESSION_EXPIRED"], error.message
    assert auth.context.internal_adapter.find_user_by_email("stale-delete@example.com")
  end

  def test_delete_user_allows_stale_session_when_password_is_valid
    auth = build_auth(
      session: {fresh_age: 1, expires_in: 3600, update_age: 3600},
      user: {delete_user: {enabled: true}}
    )
    cookie = sign_up_cookie(auth, email: "stale-password-delete@example.com", password: "password123")
    session = auth.api.get_session(headers: {"cookie" => cookie})[:session]
    auth.context.internal_adapter.update_session(
      session["token"],
      "createdAt" => Time.now - 120,
      "updatedAt" => Time.now - 120
    )

    result = auth.api.delete_user(headers: {"cookie" => cookie}, body: {password: "password123"})

    assert_equal({success: true, message: "User deleted"}, result)
    assert_nil auth.context.internal_adapter.find_user_by_email("stale-password-delete@example.com")
  end

  def test_delete_user_reports_missing_credential_account_when_password_provided
    auth = build_auth(user: {delete_user: {enabled: true}})
    user = auth.context.internal_adapter.create_user(email: "social-only-delete@example.com", name: "Social", emailVerified: true)
    auth.context.internal_adapter.create_account(userId: user["id"], providerId: "github", accountId: "gh-social-delete")
    cookie = session_cookie(auth, user)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_user(headers: {"cookie" => cookie}, body: {password: "password123"})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["CREDENTIAL_ACCOUNT_NOT_FOUND"], error.message
    assert auth.context.internal_adapter.find_user_by_id(user["id"])
  end

  def test_delete_user_sender_receives_callback_url
    sent = []
    auth = build_auth(
      user: {
        delete_user: {
          enabled: true,
          send_delete_account_verification: ->(data, _request = nil) { sent << data }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "delete-callback-url@example.com", password: "password123")

    result = auth.api.delete_user(headers: {"cookie" => cookie}, body: {callbackURL: "/deleted"})

    assert_equal({success: true, message: "Verification email sent"}, result)
    assert_equal 1, sent.length
    assert_match(%r{/delete-user/callback\?token=[0-9a-f]+&callbackURL=%2Fdeleted}, sent.first.fetch(:url))
    assert sent.first.fetch(:token)
  end

  def test_delete_user_callback_rejects_untrusted_callback_url
    auth = build_auth(user: {delete_user: {enabled: true}})
    cookie = sign_up_cookie(auth, email: "delete-callback@example.com", password: "password123")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    token = "delete-token"
    auth.context.internal_adapter.create_verification_value(
      identifier: "delete-account-#{token}",
      value: user_id,
      expiresAt: Time.now + 3600
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_user_callback(
        headers: {"cookie" => cookie},
        query: {token: token, callbackURL: "https://evil.example/deleted"}
      )
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_CALLBACK_URL"], error.message
    assert auth.context.internal_adapter.find_user_by_id(user_id)
  end

  def test_update_user_propagates_across_secondary_storage_sessions
    storage = LoggingStorage.new
    auth = build_auth(secondary_storage: storage)
    first_cookie = sign_up_cookie(auth, email: "secondary-user@example.com", password: "password123")
    second_cookie = sign_in_cookie(auth, email: "secondary-user@example.com", password: "password123")

    auth.api.update_user(headers: {"cookie" => first_cookie}, body: {name: "Updated Name"})

    assert_equal "Updated Name", auth.api.get_session(headers: {"cookie" => first_cookie})[:user]["name"]
    assert_equal "Updated Name", auth.api.get_session(headers: {"cookie" => second_cookie})[:user]["name"]
  end

  def test_update_user_writes_each_secondary_storage_session_once
    storage = LoggingStorage.new
    auth = build_auth(secondary_storage: storage)
    cookie = sign_up_cookie(auth, email: "secondary-writes@example.com", password: "password123")
    token = auth.api.get_session(headers: {"cookie" => cookie})[:session]["token"]

    storage.write_log.clear
    auth.api.update_user(headers: {"cookie" => cookie}, body: {name: "Updated Name"})

    assert_equal 1, storage.write_log.count { |entry| entry[:key] == token }
  end

  def test_delete_user_deletes_current_user_sessions_and_calls_hooks
    calls = []
    auth = build_auth(
      user: {
        delete_user: {
          enabled: true,
          before_delete: ->(user, _request = nil) { calls << "before:#{user["email"]}" },
          after_delete: ->(user, _request = nil) { calls << "after:#{user["email"]}" }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "delete@example.com", password: "password123")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    result = auth.api.delete_user(headers: {"cookie" => cookie}, body: {password: "password123"})

    assert_equal({success: true, message: "User deleted"}, result)
    assert_equal ["before:delete@example.com", "after:delete@example.com"], calls
    assert_nil auth.context.internal_adapter.find_user_by_id(user_id)
    assert_nil auth.api.get_session(headers: {"cookie" => cookie})
  end

  def test_delete_user_with_verification_sender_requires_token_before_deleting
    sent = []
    auth = build_auth(
      user: {
        delete_user: {
          enabled: true,
          send_delete_account_verification: ->(data, _request = nil) { sent << data }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "delete-token@example.com", password: "password123")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    request = auth.api.delete_user(headers: {"cookie" => cookie}, body: {password: "password123"})
    assert_equal({success: true, message: "Verification email sent"}, request)
    assert_equal 1, sent.length
    assert auth.context.internal_adapter.find_user_by_id(user_id)
    assert auth.api.get_session(headers: {"cookie" => cookie})

    result = auth.api.delete_user(headers: {"cookie" => cookie}, body: {token: sent.first.fetch(:token)})
    assert_equal({success: true, message: "User deleted"}, result)
    assert_nil auth.context.internal_adapter.find_user_by_id(user_id)
  end

  def test_delete_user_database_hooks_can_abort_delete
    calls = []
    auth = build_auth(
      user: {delete_user: {enabled: true}},
      database_hooks: {
        user: {
          delete: {
            before: ->(user, _context) {
              calls << [:before, user["email"]]
              false
            },
            after: ->(user, _context) { calls << [:after, user["email"]] }
          }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "abort-delete@example.com", password: "password123")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_user(headers: {"cookie" => cookie}, body: {password: "password123"})
    end

    assert_equal "BAD_REQUEST", error.code
    assert_equal [[:before, "abort-delete@example.com"]], calls
    assert auth.context.internal_adapter.find_user_by_id(user_id)
    assert auth.api.get_session(headers: {"cookie" => cookie})
  end

  def test_delete_user_deletes_all_secondary_storage_sessions
    storage = LoggingStorage.new
    auth = build_auth(
      secondary_storage: storage,
      user: {delete_user: {enabled: true}}
    )
    first_cookie = sign_up_cookie(auth, email: "delete-secondary@example.com", password: "password123")
    second_cookie = sign_in_cookie(auth, email: "delete-secondary@example.com", password: "password123")
    session = auth.api.get_session(headers: {"cookie" => second_cookie})
    user_id = session[:user]["id"]
    tokens = [
      auth.api.get_session(headers: {"cookie" => first_cookie})[:session]["token"],
      session[:session]["token"]
    ]

    active_sessions = JSON.parse(storage.get("active-sessions-#{user_id}"))
    assert_equal tokens.sort, active_sessions.map { |entry| entry.fetch("token") }.sort

    result = auth.api.delete_user(headers: {"cookie" => second_cookie}, body: {password: "password123"})

    assert_equal({success: true, message: "User deleted"}, result)
    assert_nil storage.get("active-sessions-#{user_id}")
    tokens.each { |token| assert_nil storage.get(token) }
    assert_empty storage.keys
    assert_nil auth.context.internal_adapter.find_user_by_id(user_id)
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:, password:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: password, name: "User Routes"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def sign_in_cookie(auth, email:, password:)
    _status, headers, _body = auth.api.sign_in_email(
      body: {email: email, password: password},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def session_cookie(auth, user)
    session = auth.context.internal_adapter.create_session(user["id"])
    token = session["token"]
    name = auth.context.auth_cookies[:session_token].name
    signature = BetterAuth::Crypto.hmac_signature(token, SECRET, encoding: :base64url)
    "#{name}=#{token}.#{signature}"
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end

  class LoggingStorage
    attr_reader :write_log

    def initialize
      @store = {}
      @write_log = []
    end

    def set(key, value, _ttl = nil)
      write_log << {key: key}
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

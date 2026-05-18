# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthRoutesPasswordTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_request_password_reset_sends_generic_response_and_reset_password_updates_credential
    sent = []
    reset = []
    auth = build_auth(
      email_and_password: {
        send_reset_password: ->(data, _request = nil) { sent << data },
        on_password_reset: ->(data, _request = nil) { reset << data[:user]["email"] },
        revoke_sessions_on_password_reset: true
      }
    )
    cookie = sign_up_cookie(auth, email: "reset@example.com", password: "old-password")
    old_session = auth.api.get_session(headers: {"cookie" => cookie})[:session]["token"]

    response = auth.api.request_password_reset(body: {email: "reset@example.com", redirectTo: "/reset"})

    assert_equal({status: true, message: "If this email exists in our system, check your email for the reset link"}, response)
    assert_equal 1, sent.length
    assert_equal "reset@example.com", sent.first[:user]["email"]
    assert_match(%r{/reset-password/[^?]+\?callbackURL=%2Freset}, sent.first[:url])

    token = sent.first[:token]
    assert_equal({status: true}, auth.api.reset_password(body: {token: token, newPassword: "new-password"}))

    assert_equal ["reset@example.com"], reset
    assert_nil auth.context.internal_adapter.find_verification_value("reset-password:#{token}")
    assert_nil auth.context.internal_adapter.find_session(old_session)
    assert auth.api.sign_in_email(body: {email: "reset@example.com", password: "new-password"})[:token]
  end

  def test_reset_password_updates_credential_account_updated_at
    sent = []
    auth = build_auth(email_and_password: {send_reset_password: ->(data, _request = nil) { sent << data }})
    cookie = sign_up_cookie(auth, email: "reset-updated-at@example.com", password: "old-password")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "credential" }
    original_updated_at = account.fetch("updatedAt")

    auth.api.request_password_reset(body: {email: "reset-updated-at@example.com"})
    auth.api.reset_password(body: {token: sent.first.fetch(:token), newPassword: "new-password"})

    updated_account = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "credential" }
    assert_operator updated_account.fetch("updatedAt"), :>, original_updated_at
  end

  def test_request_password_reset_does_not_leak_missing_users
    sent = []
    auth = build_auth(email_and_password: {send_reset_password: ->(data, _request = nil) { sent << data }})

    response = auth.api.request_password_reset(body: {email: "missing@example.com"})

    assert_equal true, response[:status]
    assert_empty sent
  end

  def test_request_password_reset_rejects_untrusted_redirect_to
    sent = []
    auth = build_auth(email_and_password: {send_reset_password: ->(data, _request = nil) { sent << data }})
    auth.api.sign_up_email(body: {email: "unsafe-redirect@example.com", password: "password123", name: "Reset"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.request_password_reset(body: {email: "unsafe-redirect@example.com", redirectTo: "https://evil.example/reset"})
    end

    assert_equal 403, error.status_code
    assert_equal "FORBIDDEN", error.code
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_REDIRECT_URL"], error.message
    assert_empty sent
  end

  def test_request_password_reset_uses_upstream_disabled_error_code
    auth = build_auth

    error = assert_raises(BetterAuth::APIError) do
      auth.api.request_password_reset(body: {email: "reset-disabled@example.com"})
    end

    assert_equal 400, error.status_code
    assert_equal "RESET_PASSWORD_DISABLED", error.code
    assert_equal "Reset password isn't enabled", error.message
  end

  def test_request_password_reset_hides_sender_errors
    auth = build_auth(
      email_and_password: {
        send_reset_password: ->(_data, _request = nil) { raise "smtp down" }
      }
    )
    auth.api.sign_up_email(body: {email: "sender-error@example.com", password: "password123", name: "Reset"})

    response = auth.api.request_password_reset(body: {email: "sender-error@example.com", redirectTo: "/reset"})

    assert_equal({status: true, message: "If this email exists in our system, check your email for the reset link"}, response)
  end

  def test_request_password_reset_rejects_missing_or_invalid_email
    sent = []
    auth = build_auth(email_and_password: {send_reset_password: ->(data, _request = nil) { sent << data }})

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.request_password_reset(body: {})
    end
    assert_equal 400, missing.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["VALIDATION_ERROR"], missing.message

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.request_password_reset(body: {email: "not-an-email"})
    end
    assert_equal 400, invalid.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["VALIDATION_ERROR"], invalid.message
    assert_empty sent
  end

  def test_reset_password_callback_redirects_with_token_or_invalid_token_error
    auth = build_auth(email_and_password: {send_reset_password: ->(_data, _request = nil) {}})
    auth.api.sign_up_email(body: {email: "callback-reset@example.com", password: "old-password", name: "Reset"})
    auth.api.request_password_reset(body: {email: "callback-reset@example.com", redirectTo: "/reset"})
    verification = auth.context.adapter.find_many(model: "verification").first
    token = verification["identifier"].delete_prefix("reset-password:")

    status, headers, _body = auth.api.request_password_reset_callback(
      params: {token: token},
      query: {callbackURL: "/reset"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/reset?token=#{token}", headers["location"]

    status, headers, _body = auth.api.request_password_reset_callback(
      params: {token: "bad-token"},
      query: {callbackURL: "/reset"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/reset?error=INVALID_TOKEN", headers["location"]
  end

  def test_reset_password_callback_rejects_untrusted_callback_url
    auth = build_auth(email_and_password: {send_reset_password: ->(_data, _request = nil) {}})
    auth.api.sign_up_email(body: {email: "unsafe-reset@example.com", password: "old-password", name: "Reset"})
    auth.api.request_password_reset(body: {email: "unsafe-reset@example.com", redirectTo: "/reset"})
    verification = auth.context.adapter.find_many(model: "verification").first
    token = verification["identifier"].delete_prefix("reset-password:")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.request_password_reset_callback(
        params: {token: token},
        query: {callbackURL: "https://evil.example/reset"}
      )
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_CALLBACK_URL"], error.message
  end

  def test_reset_password_callback_requires_callback_url
    auth = build_auth(email_and_password: {send_reset_password: ->(_data, _request = nil) {}})
    auth.api.sign_up_email(body: {email: "missing-callback-reset@example.com", password: "old-password", name: "Reset"})
    auth.api.request_password_reset(body: {email: "missing-callback-reset@example.com", redirectTo: "/reset"})
    verification = auth.context.adapter.find_many(model: "verification").first
    token = verification["identifier"].delete_prefix("reset-password:")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.request_password_reset_callback(params: {token: token})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["VALIDATION_ERROR"], error.message
  end

  def test_reset_password_rejects_invalid_password_and_cannot_reuse_token
    sent = []
    auth = build_auth(email_and_password: {send_reset_password: ->(data, _request = nil) { sent << data }})
    auth.api.sign_up_email(body: {email: "single-use-reset@example.com", password: "old-password", name: "Reset"})
    auth.api.request_password_reset(body: {email: "single-use-reset@example.com"})
    token = sent.first.fetch(:token)

    short_password = assert_raises(BetterAuth::APIError) do
      auth.api.reset_password(body: {token: token, newPassword: "short"})
    end
    assert_equal 400, short_password.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["PASSWORD_TOO_SHORT"], short_password.message

    assert_equal({status: true}, auth.api.reset_password(body: {token: token, newPassword: "new-password"}))
    reused = assert_raises(BetterAuth::APIError) do
      auth.api.reset_password(body: {token: token, newPassword: "newer-password"})
    end
    assert_equal 400, reused.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_TOKEN"], reused.message
  end

  def test_reset_password_rejects_missing_new_password_before_token_lookup
    sent = []
    auth = build_auth(email_and_password: {send_reset_password: ->(data, _request = nil) { sent << data }})
    auth.api.sign_up_email(body: {email: "missing-new-password@example.com", password: "old-password", name: "Reset"})
    auth.api.request_password_reset(body: {email: "missing-new-password@example.com"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.reset_password(body: {token: sent.first.fetch(:token)})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["VALIDATION_ERROR"], error.message
  end

  def test_reset_password_does_not_revoke_sessions_by_default
    sent = []
    auth = build_auth(email_and_password: {send_reset_password: ->(data, _request = nil) { sent << data }})
    cookie = sign_up_cookie(auth, email: "keep-session-reset@example.com", password: "old-password")
    old_session = auth.api.get_session(headers: {"cookie" => cookie})[:session]["token"]

    auth.api.request_password_reset(body: {email: "keep-session-reset@example.com"})
    auth.api.reset_password(body: {token: sent.first.fetch(:token), newPassword: "new-password"})

    assert auth.context.internal_adapter.find_session(old_session)
  end

  def test_verify_password_requires_current_password_for_session_user
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "verify-password@example.com", password: "password123")

    assert_equal({status: true}, auth.api.verify_password(headers: {"cookie" => cookie}, body: {password: "password123"}))

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_password(headers: {"cookie" => cookie}, body: {password: "bad-password"})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_PASSWORD"], error.message
  end

  def test_verify_password_is_server_only_for_rack_requests
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "verify-password-rack@example.com", password: "password123")

    status, _headers, _body = auth.call(rack_env("POST", "/api/auth/verify-password", body: {password: "password123"}, cookie: cookie))

    assert_equal 403, status
  end

  def test_verify_password_requires_session
    auth = build_auth

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_password(body: {password: "password123"})
    end

    assert_equal 401, error.status_code
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:, password:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: password, name: "Password User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end

  def rack_env(method, path, body: nil, cookie: nil)
    payload = body ? JSON.generate(body) : ""
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
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
end

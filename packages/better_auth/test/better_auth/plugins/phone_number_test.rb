# frozen_string_literal: true

require "json"
require "rack/mock"
require_relative "../../test_helper"

class BetterAuthPluginsPhoneNumberTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"

  def test_send_otp_and_verify_creates_user_and_session
    sent = []
    verified = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.phone_number(
          send_otp: ->(data, _ctx = nil) { sent << data },
          callback_on_verification: ->(data, _ctx = nil) { verified << data },
          sign_up_on_verification: {
            get_temp_email: ->(phone_number) { "temp-#{phone_number}@example.test" },
            get_temp_name: ->(phone_number) { "Phone #{phone_number}" }
          }
        )
      ]
    )

    assert_equal({message: "code sent"}, auth.api.send_phone_number_otp(body: {phoneNumber: "+251911121314"}))
    assert_match(/\A\d{6}\z/, sent.first[:code])

    status, headers, body = auth.api.verify_phone_number(
      body: {phoneNumber: "+251911121314", code: sent.first[:code]},
      as_response: true
    )
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_equal true, data.fetch("status")
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("token"))
    assert_equal "+251911121314", data.fetch("user").fetch("phoneNumber")
    assert_equal true, data.fetch("user").fetch("phoneNumberVerified")
    assert_equal "temp-+251911121314@example.test", data.fetch("user").fetch("email")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_equal "+251911121314", verified.first[:phone_number]

    reused = assert_raises(BetterAuth::APIError) do
      auth.api.verify_phone_number(body: {phoneNumber: "+251911121314", code: sent.first[:code]})
    end
    assert_equal 400, reused.status_code
    assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["OTP_NOT_FOUND"], reused.message
  end

  def test_verify_can_update_current_session_phone_number_and_blocks_update_user
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.phone_number(
          send_otp: ->(data, _ctx = nil) { sent << data },
          sign_up_on_verification: {
            get_temp_email: ->(phone_number) { "temp-#{phone_number}@example.test" }
          }
        )
      ]
    )
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "phone-owner@example.com", password: "password123", name: "Phone Owner"},
      as_response: true
    )
    cookie = cookie_header(headers.fetch("set-cookie"))

    auth.api.send_phone_number_otp(body: {phoneNumber: "+15551234567"})
    result = auth.api.verify_phone_number(
      headers: {"cookie" => cookie},
      body: {phoneNumber: "+15551234567", code: sent.last[:code], updatePhoneNumber: true}
    )

    assert_equal true, result[:status]
    assert_equal "+15551234567", result[:user]["phoneNumber"]
    assert_equal true, result[:user]["phoneNumberVerified"]
    assert_equal "+15551234567", auth.api.get_session(headers: {"cookie" => cookie})[:user]["phoneNumber"]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_user(headers: {"cookie" => cookie}, body: {phoneNumber: "+19998887777"})
    end
    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["PHONE_NUMBER_CANNOT_BE_UPDATED"], error.message
  end

  def test_update_user_rejects_phone_number_through_rack_request
    auth = build_auth(plugins: [BetterAuth::Plugins.phone_number(send_otp: ->(_data, _ctx = nil) {})])
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "phone-rack-update@example.com", password: "password123", name: "Rack Update"},
      as_response: true
    )

    response = Rack::MockRequest.new(auth).post(
      "/api/auth/update-user",
      "CONTENT_TYPE" => "application/json",
      "HTTP_COOKIE" => cookie_header(headers.fetch("set-cookie")),
      "HTTP_ORIGIN" => "http://localhost:3000",
      :input => JSON.generate(phoneNumber: "+19998887777")
    )
    body = JSON.parse(response.body)

    assert_equal 400, response.status
    assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["PHONE_NUMBER_CANNOT_BE_UPDATED"], body.fetch("message")
  end

  def test_sign_in_with_phone_number_and_password
    sent = []
    auth = build_auth(
      user: {change_email: {enabled: true, update_email_without_verification: true}},
      plugins: [
        BetterAuth::Plugins.phone_number(
          send_otp: ->(data, _ctx = nil) { sent << data },
          sign_up_on_verification: {
            get_temp_email: ->(phone_number) { "temp-#{phone_number}@example.test" }
          }
        )
      ]
    )
    auth.api.send_phone_number_otp(body: {phoneNumber: "+251900000001"})
    verify_cookie = cookie_header(auth.api.verify_phone_number(body: {phoneNumber: "+251900000001", code: sent.last[:code]}, as_response: true)[1].fetch("set-cookie"))
    auth.api.set_password(headers: {"cookie" => verify_cookie}, body: {newPassword: "password123"})

    sign_in = auth.api.sign_in_phone_number(body: {phoneNumber: "+251900000001", password: "password123"})

    assert_match(/\A[0-9a-f]{32}\z/, sign_in[:token])
    assert_equal "+251900000001", sign_in[:user]["phoneNumber"]
  end

  def test_require_verification_sends_otp_and_rejects_unverified_phone_sign_in
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.phone_number(
          require_verification: true,
          send_otp: ->(data, _ctx = nil) { sent << data }
        )
      ]
    )
    auth.api.sign_up_email(body: {email: "unverified-phone@example.com", password: "password123", name: "Unverified", phoneNumber: "+18005550199"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_phone_number(body: {phoneNumber: "+18005550199", password: "password123"})
    end

    assert_equal 401, error.status_code
    assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["PHONE_NUMBER_NOT_VERIFIED"], error.message
    assert_equal "+18005550199", sent.first[:phone_number]
    assert_match(/\A\d{6}\z/, sent.first[:code])
  end

  def test_sign_up_rejects_duplicate_phone_number_in_memory_adapter
    auth = build_auth(plugins: [BetterAuth::Plugins.phone_number(send_otp: ->(_data, _ctx = nil) {})])
    auth.api.sign_up_email(
      body: {email: "phone-duplicate-one@example.com", password: "password123", name: "One", phoneNumber: "+18005550200"}
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_up_email(
        body: {email: "phone-duplicate-two@example.com", password: "password123", name: "Two", phoneNumber: "+18005550200"}
      )
    end

    assert_equal 422, error.status_code
    assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["PHONE_NUMBER_EXIST"], error.message
  end

  def test_verify_uses_latest_phone_otp
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.phone_number(
          send_otp: ->(data, _ctx = nil) { sent << data },
          sign_up_on_verification: {
            get_temp_email: ->(phone_number) { "temp-#{phone_number}@example.test" }
          }
        )
      ]
    )
    auth.api.send_phone_number_otp(body: {phoneNumber: "+18005550201"})
    first_code = sent.last[:code]
    auth.api.send_phone_number_otp(body: {phoneNumber: "+18005550201"})
    latest_code = sent.last[:code]

    old_code = assert_raises(BetterAuth::APIError) do
      auth.api.verify_phone_number(body: {phoneNumber: "+18005550201", code: first_code})
    end
    assert_equal 400, old_code.status_code
    assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["INVALID_OTP"], old_code.message

    result = auth.api.verify_phone_number(body: {phoneNumber: "+18005550201", code: latest_code})
    assert_equal true, result[:status]
    assert_equal "+18005550201", result[:user]["phoneNumber"]
  end

  def test_attempt_limits_apply_to_verification_and_password_reset
    sent = []
    reset_sent = []
    auth = build_auth(
      email_and_password: {revoke_sessions_on_password_reset: true},
      plugins: [
        BetterAuth::Plugins.phone_number(
          allowed_attempts: 2,
          send_otp: ->(data, _ctx = nil) { sent << data },
          send_password_reset_otp: ->(data, _ctx = nil) { reset_sent << data },
          sign_up_on_verification: {
            get_temp_email: ->(phone_number) { "temp-#{phone_number}@example.test" }
          }
        )
      ]
    )

    auth.api.send_phone_number_otp(body: {phoneNumber: "+14085550100"})
    2.times do
      error = assert_raises(BetterAuth::APIError) do
        auth.api.verify_phone_number(body: {phoneNumber: "+14085550100", code: "000000"})
      end
      assert_equal 400, error.status_code
      assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["INVALID_OTP"], error.message
    end
    blocked = assert_raises(BetterAuth::APIError) do
      auth.api.verify_phone_number(body: {phoneNumber: "+14085550100", code: sent.first[:code]})
    end
    assert_equal 403, blocked.status_code
    assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["TOO_MANY_ATTEMPTS"], blocked.message

    auth.api.send_phone_number_otp(body: {phoneNumber: "+14085550101"})
    _status, headers, _body = auth.api.verify_phone_number(
      body: {phoneNumber: "+14085550101", code: sent.last[:code]},
      as_response: true
    )
    cookie = cookie_header(headers.fetch("set-cookie"))
    auth.api.set_password(headers: {"cookie" => cookie}, body: {newPassword: "password123"})

    auth.api.request_password_reset_phone_number(body: {phoneNumber: "+14085550101"})
    2.times do
      error = assert_raises(BetterAuth::APIError) do
        auth.api.reset_password_phone_number(body: {phoneNumber: "+14085550101", otp: "111111", newPassword: "newpassword123"})
      end
      assert_equal 400, error.status_code
    end

    blocked_reset = assert_raises(BetterAuth::APIError) do
      auth.api.reset_password_phone_number(body: {phoneNumber: "+14085550101", otp: reset_sent.first[:code], newPassword: "newpassword123"})
    end
    assert_equal 403, blocked_reset.status_code
  end

  def test_expired_phone_otp_is_rejected_and_consumed
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.phone_number(
          expires_in: -1,
          send_otp: ->(data, _ctx = nil) { sent << data },
          sign_up_on_verification: {
            get_temp_email: ->(phone_number) { "temp-#{phone_number}@example.test" }
          }
        )
      ]
    )
    auth.api.send_phone_number_otp(body: {phoneNumber: "+14085550102"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_phone_number(body: {phoneNumber: "+14085550102", code: sent.first[:code]})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["OTP_EXPIRED"], error.message
    assert_nil auth.context.internal_adapter.find_verification_value("+14085550102")
  end

  def test_password_reset_updates_password_revokes_sessions_and_does_not_leak_unknown_numbers
    sent = []
    reset_sent = []
    auth = build_auth(
      email_and_password: {revoke_sessions_on_password_reset: true},
      plugins: [
        BetterAuth::Plugins.phone_number(
          send_otp: ->(data, _ctx = nil) { sent << data },
          send_password_reset_otp: ->(data, _ctx = nil) { reset_sent << data },
          sign_up_on_verification: {
            get_temp_email: ->(phone_number) { "temp-#{phone_number}@example.test" }
          }
        )
      ]
    )
    auth.api.send_phone_number_otp(body: {phoneNumber: "+15105550123"})
    _status, headers, _body = auth.api.verify_phone_number(
      body: {phoneNumber: "+15105550123", code: sent.last[:code]},
      as_response: true
    )
    cookie = cookie_header(headers.fetch("set-cookie"))
    auth.api.set_password(headers: {"cookie" => cookie}, body: {newPassword: "password123"})

    assert_equal({status: true}, auth.api.request_password_reset_phone_number(body: {phoneNumber: "+19990000000"}))
    assert_empty reset_sent

    assert_equal({status: true}, auth.api.request_password_reset_phone_number(body: {phoneNumber: "+15105550123"}))
    assert_equal "+15105550123", reset_sent.first[:phone_number]
    assert_equal({status: true}, auth.api.reset_password_phone_number(body: {phoneNumber: "+15105550123", otp: reset_sent.first[:code], newPassword: "newpassword123"}))
    assert_nil auth.api.get_session(headers: {"cookie" => cookie})
    assert_match(/\A[0-9a-f]{32}\z/, auth.api.sign_in_phone_number(body: {phoneNumber: "+15105550123", password: "newpassword123"})[:token])
  end

  def test_password_reset_keeps_otp_after_password_validation_failure
    sent = []
    reset_sent = []
    auth = build_auth(
      email_and_password: {min_password_length: 8},
      plugins: [
        BetterAuth::Plugins.phone_number(
          send_otp: ->(data, _ctx = nil) { sent << data },
          send_password_reset_otp: ->(data, _ctx = nil) { reset_sent << data },
          sign_up_on_verification: {
            get_temp_email: ->(phone_number) { "temp-#{phone_number}@example.test" }
          }
        )
      ]
    )
    auth.api.send_phone_number_otp(body: {phoneNumber: "+15105550124"})
    _status, headers, _body = auth.api.verify_phone_number(
      body: {phoneNumber: "+15105550124", code: sent.last[:code]},
      as_response: true
    )
    auth.api.set_password(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))}, body: {newPassword: "password123"})

    auth.api.request_password_reset_phone_number(body: {phoneNumber: "+15105550124"})
    too_short = assert_raises(BetterAuth::APIError) do
      auth.api.reset_password_phone_number(body: {phoneNumber: "+15105550124", otp: reset_sent.last[:code], newPassword: "short"})
    end
    assert_equal 400, too_short.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["PASSWORD_TOO_SHORT"], too_short.message
    refute_nil auth.context.internal_adapter.find_verification_value("+15105550124-request-password-reset")

    assert_equal(
      {status: true},
      auth.api.reset_password_phone_number(body: {phoneNumber: "+15105550124", otp: reset_sent.last[:code], newPassword: "newpassword123"})
    )
    assert_nil auth.context.internal_adapter.find_verification_value("+15105550124-request-password-reset")
    assert_match(/\A[0-9a-f]{32}\z/, auth.api.sign_in_phone_number(body: {phoneNumber: "+15105550124", password: "newpassword123"})[:token])
  end

  def test_sign_up_on_verification_preserves_additional_user_fields
    sent = []
    auth = build_auth(
      user: {
        additional_fields: {
          lastName: {type: "string", required: true, returned: true}
        }
      },
      plugins: [
        BetterAuth::Plugins.phone_number(
          send_otp: ->(data, _ctx = nil) { sent << data },
          sign_up_on_verification: {
            get_temp_email: ->(phone_number) { "temp-#{phone_number}@example.test" }
          }
        )
      ]
    )
    auth.api.send_phone_number_otp(body: {phoneNumber: "+15105550125"})

    result = auth.api.verify_phone_number(
      body: {phoneNumber: "+15105550125", code: sent.last[:code], lastName: "Doe"}
    )

    assert_equal true, result[:status]
    assert_equal "Doe", result[:user]["lastName"]
  end

  def test_custom_validator_and_verify_otp_are_used
    verify_calls = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.phone_number(
          send_otp: ->(_data, _ctx = nil) {},
          phone_number_validator: ->(phone_number) { phone_number.start_with?("+1") },
          verify_otp: lambda { |data, _ctx = nil|
            verify_calls << data
            data[:code] == "external-code"
          },
          sign_up_on_verification: {
            get_temp_email: ->(phone_number) { "temp-#{phone_number}@example.test" }
          }
        )
      ]
    )

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.send_phone_number_otp(body: {phoneNumber: "+442071838750"})
    end
    assert_equal 400, invalid.status_code
    assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["INVALID_PHONE_NUMBER"], invalid.message

    result = auth.api.verify_phone_number(body: {phoneNumber: "+14155550100", code: "external-code"})

    assert_equal true, result[:status]
    assert_equal({phone_number: "+14155550100", code: "external-code"}, verify_calls.first)

    rejected = assert_raises(BetterAuth::APIError) do
      auth.api.verify_phone_number(body: {phoneNumber: "+14155550101", code: "wrong-code"})
    end
    assert_equal 400, rejected.status_code
    assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["INVALID_OTP"], rejected.message
  end

  def test_send_otp_requires_configured_delivery_callback
    auth = build_auth(plugins: [BetterAuth::Plugins.phone_number])

    error = assert_raises(BetterAuth::APIError) do
      auth.api.send_phone_number_otp(body: {phoneNumber: "+14155550123"})
    end

    assert_equal 501, error.status_code
    assert_equal BetterAuth::Plugins::PHONE_NUMBER_ERROR_CODES["SEND_OTP_NOT_IMPLEMENTED"], error.message
  end

  def test_schema_adds_phone_number_fields_to_user
    auth = build_auth(plugins: [BetterAuth::Plugins.phone_number(send_otp: ->(_data, _ctx = nil) {})])
    fields = BetterAuth::Schema.auth_tables(auth.context.options).fetch("user").fetch(:fields)

    assert_equal "string", fields.fetch("phoneNumber").fetch(:type)
    assert_equal true, fields.fetch("phoneNumber").fetch(:unique)
    assert_equal "boolean", fields.fetch("phoneNumberVerified").fetch(:type)
    assert_equal true, fields.fetch("phoneNumberVerified").fetch(:returned)
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options).merge(email_and_password: email_and_password))
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end

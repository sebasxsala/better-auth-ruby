# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsTwoFactorTest < Minitest::Test
  SECRET = "phase-nine-two-factor-secret-with-enough-entropy"

  def test_enable_then_verify_totp_requires_second_factor_on_next_sign_in
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "totp@example.com")

    enabled = auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})
    assert_match(/\Aotpauth:\/\/totp\//, enabled[:totpURI])
    assert_equal 10, enabled[:backupCodes].length

    record = auth.context.adapter.find_one(model: "twoFactor", where: [{field: "userId", value: user_id(auth, cookie)}])
    secret = BetterAuth::Crypto.symmetric_decrypt(key: SECRET, data: record.fetch("secret"))
    code = BetterAuth::Plugins.two_factor_totp(secret)

    verified = auth.api.verify_totp(headers: {"cookie" => cookie}, body: {code: code})
    assert_equal "totp@example.com", verified[:user]["email"]

    status, headers, body = auth.api.sign_in_email(
      body: {email: "totp@example.com", password: "password123"},
      as_response: true
    )
    assert_equal 200, status
    assert_equal({"twoFactorRedirect" => true, "twoFactorMethods" => ["totp", "otp"]}, JSON.parse(body.join))
    assert_includes headers.fetch("set-cookie"), "better-auth.two_factor="
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token=;"
    assert_includes headers.fetch("set-cookie"), "Max-Age=0"
  end

  def test_enable_marks_totp_unverified_then_verify_marks_verified
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "verified-state@example.com")
    auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})

    record = auth.context.adapter.find_one(model: "twoFactor", where: [{field: "userId", value: user_id(auth, cookie)}])
    assert_equal false, record.fetch("verified")

    secret = BetterAuth::Crypto.symmetric_decrypt(key: SECRET, data: record.fetch("secret"))
    verified = auth.api.verify_totp(headers: {"cookie" => cookie}, body: {code: BetterAuth::Plugins.two_factor_totp(secret)}, return_headers: true)
    cookie = cookie_header(verified.fetch(:headers).fetch("set-cookie"))

    updated = auth.context.adapter.find_one(model: "twoFactor", where: [{field: "userId", value: user_id(auth, cookie)}])
    assert_equal true, updated.fetch("verified")
  end

  def test_nil_verified_totp_row_completes_enrollment
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "nil-verified@example.com")
    auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})
    record = auth.context.adapter.find_one(model: "twoFactor", where: [{field: "userId", value: user_id(auth, cookie)}])
    auth.context.adapter.update(model: "twoFactor", where: [{field: "id", value: record.fetch("id")}], update: {verified: nil})

    secret = BetterAuth::Crypto.symmetric_decrypt(key: SECRET, data: record.fetch("secret"))
    verified = auth.api.verify_totp(headers: {"cookie" => cookie}, body: {code: BetterAuth::Plugins.two_factor_totp(secret)}, return_headers: true)
    cookie = cookie_header(verified.fetch(:headers).fetch("set-cookie"))

    user = auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true})[:user]
    updated = auth.context.adapter.find_one(model: "twoFactor", where: [{field: "userId", value: user.fetch("id")}])
    assert_equal true, user["twoFactorEnabled"]
    assert_equal true, updated.fetch("verified")
  end

  def test_verified_state_is_preserved_when_re_enrolling_totp
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "reenroll@example.com")
    auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})

    record = auth.context.adapter.find_one(model: "twoFactor", where: [{field: "userId", value: user_id(auth, cookie)}])
    secret = BetterAuth::Crypto.symmetric_decrypt(key: SECRET, data: record.fetch("secret"))
    verified = auth.api.verify_totp(headers: {"cookie" => cookie}, body: {code: BetterAuth::Plugins.two_factor_totp(secret)}, return_headers: true)
    cookie = cookie_header(verified.fetch(:headers).fetch("set-cookie"))

    auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})
    reenrolled = auth.context.adapter.find_one(model: "twoFactor", where: [{field: "userId", value: user_id(auth, cookie)}])
    assert_equal true, reenrolled.fetch("verified")
  end

  def test_unverified_totp_is_rejected_during_sign_in_but_otp_fallback_works
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.two_factor(
          otp_options: {send_otp: ->(data, _ctx = nil) { sent << data }}
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "otp-fallback@example.com")
    auth.api.send_two_factor_otp(headers: {"cookie" => cookie})
    enrolled = auth.api.verify_two_factor_otp(headers: {"cookie" => cookie}, body: {code: sent.last.fetch(:otp)}, return_headers: true)
    cookie = cookie_header(enrolled.fetch(:headers).fetch("set-cookie"))
    auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})

    sign_in = auth.api.sign_in_email(body: {email: "otp-fallback@example.com", password: "password123"}, return_headers: true)
    assert_equal({twoFactorRedirect: true, twoFactorMethods: ["otp"]}, sign_in.fetch(:response))

    two_factor_cookie = cookie_header(sign_in.fetch(:headers).fetch("set-cookie"))
    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_totp(headers: {"cookie" => two_factor_cookie}, body: {code: "000000"})
    end
    assert_equal BetterAuth::Plugins::TWO_FACTOR_ERROR_CODES["TOTP_NOT_ENABLED"], error.message

    auth.api.send_two_factor_otp(headers: {"cookie" => two_factor_cookie})
    verified = auth.api.verify_two_factor_otp(headers: {"cookie" => two_factor_cookie}, body: {code: sent.last.fetch(:otp)})
    assert_equal "otp-fallback@example.com", verified[:user]["email"]
  end

  def test_second_factor_verification_rejects_missing_or_invalid_two_factor_cookie
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.two_factor(otp_options: {send_otp: ->(_data, _ctx = nil) {}})
      ]
    )

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.verify_two_factor_otp(body: {code: "000000"})
    end
    assert_equal 401, missing.status_code
    assert_equal BetterAuth::Plugins::TWO_FACTOR_ERROR_CODES["INVALID_TWO_FACTOR_COOKIE"], missing.message

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.verify_totp(headers: {"cookie" => "better-auth.two_factor=not-signed"}, body: {code: "000000"})
    end
    assert_equal 401, invalid.status_code
    assert_equal BetterAuth::Plugins::TWO_FACTOR_ERROR_CODES["INVALID_TWO_FACTOR_COOKIE"], invalid.message
  end

  def test_sign_in_response_includes_available_two_factor_methods
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.two_factor(
          skip_verification_on_enable: true,
          otp_options: {send_otp: ->(_data, _ctx = nil) {}}
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "methods@example.com")
    auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})

    sign_in = auth.api.sign_in_email(body: {email: "methods@example.com", password: "password123"})
    assert_equal true, sign_in[:twoFactorRedirect]
    assert_equal ["totp", "otp"], sign_in[:twoFactorMethods]
  end

  def test_totp_is_excluded_from_sign_in_methods_when_disabled
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.two_factor(
          skip_verification_on_enable: true,
          totp_options: {disable: true},
          otp_options: {send_otp: ->(_data, _ctx = nil) {}}
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "totp-disabled@example.com")
    auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})

    sign_in = auth.api.sign_in_email(body: {email: "totp-disabled@example.com", password: "password123"})
    assert_equal true, sign_in[:twoFactorRedirect]
    assert_equal ["otp"], sign_in[:twoFactorMethods]
  end

  def test_password_validated_two_factor_management_allows_stale_session
    auth = build_auth(
      session: {fresh_age: 60, cookie_cache: {enabled: true, strategy: "jwe", max_age: 300}},
      plugins: [BetterAuth::Plugins.two_factor(skip_verification_on_enable: true)]
    )
    cookie = sign_up_cookie(auth, email: "stale-two-factor@example.com")
    stale_session!(auth, cookie)

    enabled = auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"}, return_headers: true)
    assert_equal 10, enabled.fetch(:response)[:backupCodes].length

    cookie = cookie_header(enabled.fetch(:headers).fetch("set-cookie"))
    stale_session!(auth, cookie)
    assert_match(/\Aotpauth:\/\/totp\//, auth.api.get_totp_uri(headers: {"cookie" => cookie}, body: {password: "password123"})[:totpURI])
    assert_equal 10, auth.api.generate_backup_codes(headers: {"cookie" => cookie}, body: {password: "password123"})[:backupCodes].length

    disabled = auth.api.disable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"}, return_headers: true)
    assert_equal({status: true}, disabled.fetch(:response))
  end

  def test_passwordless_users_can_manage_two_factor_when_allowed
    auth = build_auth(plugins: [BetterAuth::Plugins.two_factor(allow_passwordless: true)])
    cookie = sign_up_cookie(auth, email: "passwordless@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true})[:user]
    auth.context.adapter.delete(model: "account", where: [{field: "userId", value: user.fetch("id")}])

    enabled = auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {})
    assert_equal 10, enabled[:backupCodes].length

    record = auth.context.adapter.find_one(model: "twoFactor", where: [{field: "userId", value: user.fetch("id")}])
    secret = BetterAuth::Crypto.symmetric_decrypt(key: SECRET, data: record.fetch("secret"))
    verified = auth.api.verify_totp(headers: {"cookie" => cookie}, body: {code: BetterAuth::Plugins.two_factor_totp(secret)}, return_headers: true)
    cookie = cookie_header(verified.fetch(:headers).fetch("set-cookie"))

    assert_match(/\Aotpauth:\/\/totp\//, auth.api.get_totp_uri(headers: {"cookie" => cookie}, body: {})[:totpURI])
    assert_equal 10, auth.api.generate_backup_codes(headers: {"cookie" => cookie}, body: {})[:backupCodes].length
    disabled = auth.api.disable_two_factor(headers: {"cookie" => cookie}, body: {}, return_headers: true)
    assert_equal({status: true}, disabled.fetch(:response))
  end

  def test_allow_passwordless_still_requires_password_for_credential_users
    auth = build_auth(plugins: [BetterAuth::Plugins.two_factor(allow_passwordless: true)])
    cookie = sign_up_cookie(auth, email: "credential-required@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {})
    end
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_PASSWORD"], error.message
  end

  def test_custom_two_factor_table_option_maps_schema_model_name
    plugin = BetterAuth::Plugins.two_factor(two_factor_table: "custom_two_factors")
    config = BetterAuth::Configuration.new(secret: SECRET, plugins: [plugin])
    schema = BetterAuth::Schema.auth_tables(config)

    assert schema.key?("twoFactor")
    assert_equal "custom_two_factors", schema.fetch("twoFactor").fetch(:model_name)
    assert_equal "boolean", schema.fetch("twoFactor").fetch(:fields).fetch("verified").fetch(:type)
  end

  def test_encrypted_two_factor_values_survive_secret_rotation
    old_auth = build_auth(
      secrets: [{version: 1, value: "old-two-factor-secret-with-enough-entropy"}],
      plugins: [BetterAuth::Plugins.two_factor]
    )
    cookie = sign_up_cookie(old_auth, email: "rotated-2fa@example.com")
    old_auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})

    new_auth = build_auth(
      database: old_auth.context.adapter,
      secrets: [
        {version: 2, value: "new-two-factor-secret-with-enough-entropy"},
        {version: 1, value: "old-two-factor-secret-with-enough-entropy"}
      ],
      plugins: [BetterAuth::Plugins.two_factor]
    )
    record = new_auth.context.adapter.find_one(model: "twoFactor", where: [{field: "userId", value: user_id(old_auth, cookie)}])
    secret = BetterAuth::Crypto.symmetric_decrypt(key: new_auth.context.secret_config, data: record.fetch("secret"))
    backup_codes = BetterAuth::Plugins.two_factor_read_backup_codes(
      new_auth.context.secret_config,
      record.fetch("backupCodes"),
      {store_backup_codes: "encrypted"}
    )

    assert_match(/\A[A-Z2-7]+=*\z/, secret)
    assert_equal 10, backup_codes.length
  end

  def test_second_factor_verification_preserves_dont_remember_me_session
    auth = build_auth(plugins: [BetterAuth::Plugins.two_factor(skip_verification_on_enable: true)])
    cookie = sign_up_cookie(auth, email: "dont-remember-2fa@example.com")
    auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})

    sign_in = auth.api.sign_in_email(
      body: {email: "dont-remember-2fa@example.com", password: "password123", rememberMe: false},
      return_headers: true
    )
    two_factor_cookie = cookie_header(sign_in.fetch(:headers).fetch("set-cookie"))
    record = auth.context.adapter.find_one(model: "twoFactor", where: [{field: "userId", value: user_id_from_email(auth, "dont-remember-2fa@example.com")}])
    secret = BetterAuth::Crypto.symmetric_decrypt(key: SECRET, data: record.fetch("secret"))
    verify = auth.api.verify_totp(headers: {"cookie" => two_factor_cookie}, body: {code: BetterAuth::Plugins.two_factor_totp(secret)}, return_headers: true)

    set_cookie = verify.fetch(:headers).fetch("set-cookie")
    session_cookie = set_cookie.lines.find { |line| line.include?("better-auth.session_token=") }
    assert session_cookie
    refute_includes session_cookie, "Max-Age="
    assert_includes set_cookie, "better-auth.dont_remember="
  end

  def test_two_factor_cookie_max_age_options_are_applied
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.two_factor(
          skip_verification_on_enable: true,
          two_factor_cookie_max_age: 15 * 60,
          trust_device_max_age: 7 * 24 * 60 * 60,
          otp_options: {send_otp: ->(_data, _ctx = nil) {}}
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "cookie-age@example.com")
    auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})

    sign_in = auth.api.sign_in_email(body: {email: "cookie-age@example.com", password: "password123"}, return_headers: true)
    assert_cookie_max_age sign_in.fetch(:headers).fetch("set-cookie"), "better-auth.two_factor", 15 * 60

    two_factor_cookie = cookie_header(sign_in.fetch(:headers).fetch("set-cookie"))
    auth.api.send_two_factor_otp(headers: {"cookie" => two_factor_cookie})
    verification = auth.context.adapter.find_many(model: "verification").find { |entry| entry["identifier"].to_s.start_with?("2fa-otp-") }
    code = verification.fetch("value").split(":").first
    verified = auth.api.verify_two_factor_otp(headers: {"cookie" => two_factor_cookie}, body: {code: code, trustDevice: true}, return_headers: true)
    assert_cookie_max_age verified.fetch(:headers).fetch("set-cookie"), "better-auth.trust_device", 7 * 24 * 60 * 60
  end

  def test_otp_verification_supports_hashed_storage_and_attempt_limits
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.two_factor(
          skip_verification_on_enable: true,
          otp_options: {
            store_otp: "hashed",
            allowed_attempts: 1,
            send_otp: ->(data, _ctx = nil) { sent << data }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "otp@example.com")
    auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})

    sign_in = auth.api.sign_in_email(body: {email: "otp@example.com", password: "password123"}, return_headers: true)
    two_factor_cookie = cookie_header(sign_in.fetch(:headers).fetch("set-cookie"))
    auth.api.send_two_factor_otp(headers: {"cookie" => two_factor_cookie})

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.verify_two_factor_otp(headers: {"cookie" => two_factor_cookie}, body: {code: "000000"})
    end
    assert_equal BetterAuth::Plugins::TWO_FACTOR_ERROR_CODES["INVALID_CODE"], invalid.message

    too_many = assert_raises(BetterAuth::APIError) do
      auth.api.verify_two_factor_otp(headers: {"cookie" => two_factor_cookie}, body: {code: sent.last.fetch(:otp)})
    end
    assert_equal BetterAuth::Plugins::TWO_FACTOR_ERROR_CODES["TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"], too_many.message
  end

  def test_backup_code_use_consumes_code_and_trusting_device_skips_next_challenge
    auth = build_auth(plugins: [BetterAuth::Plugins.two_factor(skip_verification_on_enable: true)])
    cookie = sign_up_cookie(auth, email: "backup@example.com")
    existing_user_id = user_id(auth, cookie)
    enabled = auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})
    code = enabled[:backupCodes].first

    sign_in = auth.api.sign_in_email(body: {email: "backup@example.com", password: "password123"}, return_headers: true)
    two_factor_cookie = cookie_header(sign_in.fetch(:headers).fetch("set-cookie"))
    verified = auth.api.verify_backup_code(
      headers: {"cookie" => two_factor_cookie},
      body: {code: code, trustDevice: true},
      return_headers: true
    )
    trusted_cookie = cookie_header(verified.fetch(:headers).fetch("set-cookie"))
    refute_includes auth.api.view_backup_codes(body: {userId: existing_user_id})[:backupCodes], code

    trusted = auth.api.sign_in_email(
      headers: {"cookie" => trusted_cookie},
      body: {email: "backup@example.com", password: "password123"}
    )
    assert_equal "backup@example.com", trusted[:user]["email"]
  end

  def test_disable_two_factor_revokes_trusted_device
    auth = build_auth(plugins: [BetterAuth::Plugins.two_factor(skip_verification_on_enable: true)])
    cookie = sign_up_cookie(auth, email: "disable-2fa@example.com")
    enabled = auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"}, return_headers: true)
    cookie = cookie_header(enabled.fetch(:headers).fetch("set-cookie"))

    result = auth.api.disable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"}, return_headers: true)
    assert_equal({status: true}, result.fetch(:response))
    assert_includes result.fetch(:headers).fetch("set-cookie"), "better-auth.session_token="

    session = auth.api.get_session(headers: {"cookie" => cookie_header(result.fetch(:headers).fetch("set-cookie"))}, query: {disableCookieCache: true})
    assert_equal false, session[:user]["twoFactorEnabled"]
  end

  def test_otp_verification_supports_encrypted_and_custom_hash_storage
    encrypted_sent = []
    encrypted_auth = build_auth(
      plugins: [
        BetterAuth::Plugins.two_factor(
          skip_verification_on_enable: true,
          otp_options: {
            store_otp: "encrypted",
            send_otp: ->(data, _ctx = nil) { encrypted_sent << data }
          }
        )
      ]
    )
    encrypted_cookie = sign_up_cookie(encrypted_auth, email: "encrypted-otp@example.com")
    encrypted_auth.api.enable_two_factor(headers: {"cookie" => encrypted_cookie}, body: {password: "password123"})
    encrypted_sign_in = encrypted_auth.api.sign_in_email(body: {email: "encrypted-otp@example.com", password: "password123"}, return_headers: true)
    encrypted_two_factor_cookie = cookie_header(encrypted_sign_in.fetch(:headers).fetch("set-cookie"))
    encrypted_auth.api.send_two_factor_otp(headers: {"cookie" => encrypted_two_factor_cookie})
    encrypted_verified = encrypted_auth.api.verify_two_factor_otp(headers: {"cookie" => encrypted_two_factor_cookie}, body: {code: encrypted_sent.last.fetch(:otp)})
    assert_equal "encrypted-otp@example.com", encrypted_verified[:user]["email"]

    custom_sent = []
    custom_auth = build_auth(
      plugins: [
        BetterAuth::Plugins.two_factor(
          skip_verification_on_enable: true,
          otp_options: {
            store_otp: {hash: ->(token) { "custom_#{token.reverse}" }},
            send_otp: ->(data, _ctx = nil) { custom_sent << data }
          }
        )
      ]
    )
    custom_cookie = sign_up_cookie(custom_auth, email: "custom-otp@example.com")
    custom_auth.api.enable_two_factor(headers: {"cookie" => custom_cookie}, body: {password: "password123"})
    custom_sign_in = custom_auth.api.sign_in_email(body: {email: "custom-otp@example.com", password: "password123"}, return_headers: true)
    custom_two_factor_cookie = cookie_header(custom_sign_in.fetch(:headers).fetch("set-cookie"))
    custom_auth.api.send_two_factor_otp(headers: {"cookie" => custom_two_factor_cookie})
    custom_verified = custom_auth.api.verify_two_factor_otp(headers: {"cookie" => custom_two_factor_cookie}, body: {code: custom_sent.last.fetch(:otp)})
    assert_equal "custom-otp@example.com", custom_verified[:user]["email"]
  end

  def build_auth(options = {})
    plugin_list = options.delete(:plugins) || [BetterAuth::Plugins.two_factor(otp_options: {send_otp: ->(_data, _ctx = nil) {}})]
    BetterAuth.auth({
      secret: SECRET,
      plugins: plugin_list,
      email_and_password: {enabled: true}
    }.merge(options))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Two Factor"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def user_id(auth, cookie)
    auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true})[:user]["id"]
  end

  def user_id_from_email(auth, email)
    auth.context.adapter.find_one(model: "user", where: [{field: "email", value: email}]).fetch("id")
  end

  def stale_session!(auth, cookie)
    session = auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true})
    auth.context.adapter.update(
      model: "session",
      where: [{field: "token", value: session[:session]["token"]}],
      update: {createdAt: Time.now - 300, updatedAt: Time.now - 300}
    )
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def assert_cookie_max_age(set_cookie, name, max_age)
    line = set_cookie.lines.find { |candidate| candidate.include?("#{name}=") }
    assert line, "expected #{name} Set-Cookie line in #{set_cookie.inspect}"
    assert_includes line.downcase, "max-age=#{max_age}"
  end
end

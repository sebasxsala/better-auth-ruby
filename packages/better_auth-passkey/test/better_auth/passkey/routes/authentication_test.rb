# frozen_string_literal: true

require "json"
require "forwardable"
require "webauthn/fake_client"
require_relative "../support"

class BetterAuthPasskeyRoutesAuthenticationTest < Minitest::Test
  include BetterAuthPasskeyTestSupport

  def test_generate_authentication_options_omits_allow_credentials_without_session
    auth = build_auth

    options = auth.api.generate_passkey_authentication_options
    verification = JSON.parse(auth.context.adapter.find_many(model: "verification").last.fetch("value"))

    assert_includes options.keys, :challenge
    assert_includes options.keys, :rpId
    assert_equal "preferred", options.fetch(:userVerification)
    refute_includes options.keys, :allowCredentials
    assert_equal "", verification.fetch("userData").fetch("id")
    refute_includes options.keys, :extensions
    refute_includes options.keys, "extensions"
  end

  def test_generate_authentication_options_includes_current_user_passkeys
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "authentication-route@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    create_passkey(auth, user_id: user.fetch("id"), name: "Route key", credential_id: "route-credential", transports: "internal,usb")

    options = auth.api.generate_passkey_authentication_options(headers: {"cookie" => cookie})

    assert_equal [{id: "route-credential", type: "public-key", transports: ["internal", "usb"]}], options.fetch(:allowCredentials)
  end

  def test_after_verification_receives_upstream_payload_keys
    captured = {}
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          authentication: {
            after_verification: lambda do |data|
              captured[:keys] = data.keys
              captured[:ctx] = data.fetch(:ctx)
              captured[:verification] = data.fetch(:verification)
              captured[:client_data] = data.fetch(:client_data)
            end
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "after-authentication-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    registration_cookie = [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; ")
    registration_response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    auth.api.verify_passkey_registration(
      headers: {"cookie" => registration_cookie, "origin" => ORIGIN},
      body: {response: registration_response}
    )
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")

    auth.api.verify_passkey_authentication(
      headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
      body: {response: assertion}
    )

    assert_equal [:ctx, :verification, :client_data], captured.fetch(:keys)
    assert captured.fetch(:ctx)
    assert captured.fetch(:verification)
    assert_equal assertion.fetch("id"), captured.fetch(:client_data).fetch("id")
  end

  def test_verify_authentication_invalidates_challenge_after_webauthn_error
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "bad-authentication-route@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    create_passkey(auth, user_id: user.fetch("id"), name: "Bad auth", credential_id: "bad-auth-credential")
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last

    error = assert_raises(BetterAuth::APIError) do
      WebAuthn::Credential.stub(:from_get, ->(*) { raise WebAuthn::Error, "bad authentication" }) do
        auth.api.verify_passkey_authentication(
          headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
          body: {response: {id: "bad-auth-credential", response: {client_data_json: "bad"}}}
        )
      end
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("AUTHENTICATION_FAILED"), error.message
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_verify_authentication_rejects_expired_challenge
    auth = build_auth
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last
    auth.context.adapter.update(
      model: "verification",
      where: [{field: "id", value: verification.fetch("id")}],
      update: {expiresAt: Time.now - 1}
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_authentication(
        headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
        body: {response: {id: "missing-credential", response: {client_data_json: "bad"}}}
      )
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND"), error.message
  end

  def test_verify_authentication_invalidates_challenge_when_passkey_is_missing
    auth = build_auth
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_authentication(
        headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
        body: {response: {id: "missing-credential", response: {client_data_json: "bad"}}}
      )
    end

    assert_equal 401, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND"), error.message
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_verify_authentication_invalidates_challenge_after_callback_error
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          authentication: {
            after_verification: ->(_data) { raise "callback failed" }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "callback-error-authentication-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    registration_response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {response: registration_response}
    )
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last
    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_authentication(
        headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
        body: {response: assertion}
      )
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("AUTHENTICATION_FAILED"), error.message
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_verify_authentication_invalidates_challenge_after_malformed_response
    auth = build_auth
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_authentication(
        headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
        body: {response: {response: {client_data_json: "bad"}}}
      )
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("AUTHENTICATION_FAILED"), error.message
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_verify_authentication_invalidates_challenge_after_passkey_update_error
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "update-error-authentication-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    registration_response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {response: registration_response}
    )
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last
    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")

    error = assert_raises(BetterAuth::APIError) do
      auth.context.adapter.stub(:update, ->(*) { raise "update failed" }) do
        auth.api.verify_passkey_authentication(
          headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
          body: {response: assertion}
        )
      end
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("AUTHENTICATION_FAILED"), error.message
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_verify_authentication_does_not_create_session_when_passkey_update_returns_nil
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "nil-update-authentication-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    registration_response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {response: registration_response}
    )
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last
    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")
    session_count = auth.context.adapter.find_many(model: "session").length

    error = assert_raises(BetterAuth::APIError) do
      auth.context.adapter.stub(:update, ->(**_kwargs) {}) do
        auth.api.verify_passkey_authentication(
          headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
          body: {response: assertion}
        )
      end
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("AUTHENTICATION_FAILED"), error.message
    assert_equal session_count, auth.context.adapter.find_many(model: "session").length
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_verify_authentication_does_not_create_session_when_user_is_missing
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "missing-user-authentication-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    registration_response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {response: registration_response}
    )
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last
    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")
    session_count = auth.context.adapter.find_many(model: "session").length

    error = assert_raises(BetterAuth::APIError) do
      auth.context.internal_adapter.stub(:find_user_by_id, nil) do
        auth.api.verify_passkey_authentication(
          headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
          body: {response: assertion}
        )
      end
    end

    assert_equal 500, error.status_code
    assert_equal "User not found", error.message
    assert_equal session_count, auth.context.adapter.find_many(model: "session").length
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_verify_authentication_consumes_successful_challenge
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "success-replay-authentication-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    registration_response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {response: registration_response}
    )
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last
    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")
    headers = {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN}

    auth.api.verify_passkey_authentication(headers: headers, body: {response: assertion})

    replay = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_authentication(headers: headers, body: {response: assertion})
    end

    assert_equal 400, replay.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND"), replay.message
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_verify_authentication_invalidates_challenge_after_session_creation_failure
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "session-error-authentication-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    registration_response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {response: registration_response}
    )
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last
    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")

    error = assert_raises(BetterAuth::APIError) do
      auth.context.internal_adapter.stub(:create_session, nil) do
        auth.api.verify_passkey_authentication(
          headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
          body: {response: assertion}
        )
      end
    end

    assert_equal 500, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("UNABLE_TO_CREATE_SESSION"), error.message
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end
end

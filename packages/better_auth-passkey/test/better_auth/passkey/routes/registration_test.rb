# frozen_string_literal: true

require "json"
require "forwardable"
require "webauthn/fake_client"
require_relative "../support"

class BetterAuthPasskeyRoutesRegistrationTest < Minitest::Test
  include BetterAuthPasskeyTestSupport

  def test_generate_registration_options_uses_session_user_and_stores_context
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "registration-route@example.com")

    result = auth.api.generate_passkey_registration_options(
      headers: {"cookie" => cookie},
      query: {context: "route-context", name: "Work laptop"},
      return_headers: true
    )
    options = result.fetch(:response)
    verification = auth.context.adapter.find_many(model: "verification").last

    assert_equal "Work laptop", options.fetch(:user).fetch(:name)
    assert_equal "none", options.fetch(:attestation)
    assert_includes result.fetch(:headers).fetch("set-cookie"), "better-auth-passkey"
    assert_includes verification.fetch("value"), "route-context"
  end

  def test_generate_registration_options_supports_passkey_first_resolver
    captured = {}
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false,
            resolve_user: lambda do |data|
              captured[:resolve_keys] = data.keys
              captured[:resolve_ctx] = data.fetch(:ctx)
              captured[:resolve_context] = data.fetch(:context)
              {id: "route-user", name: data.fetch(:context)}
            end
          }
        )
      ]
    )

    options = auth.api.generate_passkey_registration_options(query: {context: "resolved@example.com"})

    assert_equal "resolved@example.com", options.fetch(:user).fetch(:name)
    assert_equal [:ctx, :context], captured.fetch(:resolve_keys)
    assert captured.fetch(:resolve_ctx)
    assert_equal "resolved@example.com", captured.fetch(:resolve_context)
  end

  def test_generate_registration_options_requires_session_by_default_with_passkey_error
    auth = build_auth

    error = assert_raises(BetterAuth::APIError) do
      auth.api.generate_passkey_registration_options
    end

    assert_equal 401, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("SESSION_REQUIRED"), error.message
  end

  def test_generate_registration_options_requires_fresh_session_by_default
    auth = build_auth(session: {fresh_age: 1})
    cookie = sign_up_cookie(auth, email: "stale-registration-route@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    session = auth.context.adapter.find_many(model: "session", where: [{field: "userId", value: user.fetch("id")}]).first
    auth.context.adapter.update(
      model: "session",
      where: [{field: "id", value: session.fetch("id")}],
      update: {createdAt: Time.now - 120}
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie})
    end

    assert_equal 403, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES.fetch("SESSION_NOT_FRESH"), error.message
  end

  def test_verify_registration_requires_fresh_session_by_default
    auth = build_auth(session: {fresh_age: 1})
    cookie = sign_up_cookie(auth, email: "stale-verify-registration-route@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    session = auth.context.adapter.find_many(model: "session", where: [{field: "userId", value: user.fetch("id")}]).first
    auth.context.adapter.update(
      model: "session",
      where: [{field: "id", value: session.fetch("id")}],
      update: {createdAt: Time.now}
    )
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    auth.context.adapter.update(
      model: "session",
      where: [{field: "id", value: session.fetch("id")}],
      update: {createdAt: Time.now - 120}
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
        body: {response: response}
      )
    end

    assert_equal 403, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES.fetch("SESSION_NOT_FRESH"), error.message
  end

  def test_verify_registration_maps_webauthn_error_to_bad_request_and_invalidates_challenge
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "bad-registration-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    verification = auth.context.adapter.find_many(model: "verification").last

    error = assert_raises(BetterAuth::APIError) do
      WebAuthn::Credential.stub(:from_create, ->(*) { raise WebAuthn::Error, "bad registration" }) do
        auth.api.verify_passkey_registration(
          headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
          body: {response: response}
        )
      end
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"), error.message
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_verify_registration_rejects_unconfigured_request_origin
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "evil-origin-registration-route@example.com")
    evil_origin = "http://evil.localhost:3000"
    client = WebAuthn::FakeClient.new(evil_origin)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => evil_origin},
        body: {response: response}
      )
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"), error.message
  end

  def test_verify_registration_invalidates_challenge_after_callback_error
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            after_verification: ->(_data) { raise "callback failed" }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "callback-error-registration-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
        body: {response: response}
      )
    end

    assert_equal 500, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"), error.message
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_verify_registration_invalidates_challenge_after_passkey_create_error
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "create-error-registration-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    error = assert_raises(BetterAuth::APIError) do
      auth.context.adapter.stub(:create, ->(**_kwargs) { raise "create failed" }) do
        auth.api.verify_passkey_registration(
          headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
          body: {response: response}
        )
      end
    end

    assert_equal 500, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"), error.message
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_verify_registration_rejects_known_duplicate_before_webauthn_verification
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "early-duplicate-registration-route@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    create_passkey(auth, user_id: user.fetch("id"), name: "Existing", credential_id: response.fetch("id"))

    error = assert_raises(BetterAuth::APIError) do
      WebAuthn::Credential.stub(:from_create, ->(*) { raise "from_create should not be called" }) do
        auth.api.verify_passkey_registration(
          headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
          body: {response: response}
        )
      end
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("PREVIOUSLY_REGISTERED"), error.message
  end

  def test_verify_registration_consumes_successful_challenge
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "success-replay-registration-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    verification = auth.context.adapter.find_many(model: "verification").last
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    headers = {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN}

    auth.api.verify_passkey_registration(headers: headers, body: {response: response})

    replay = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(headers: headers, body: {response: response})
    end

    assert_equal 400, replay.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND"), replay.message
    assert_nil auth.context.adapter.find_one(model: "verification", where: [{field: "id", value: verification.fetch("id")}])
  end

  def test_registration_extensions_are_omitted_when_absent
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "no-registration-extensions@example.com")

    options = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie})

    refute_includes options.keys, :extensions
    refute_includes options.keys, "extensions"
  end

  def test_after_verification_receives_upstream_payload_keys
    captured = {}
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false,
            resolve_user: ->(_data) { {id: captured.fetch(:user).fetch("id"), name: "after-registration-route@example.com", display_name: "After Route"} },
            after_verification: lambda do |data|
              captured[:after_keys] = data.keys
              captured[:after_ctx] = data.fetch(:ctx)
              captured[:after_verification] = data.fetch(:verification)
              captured[:after_user] = data.fetch(:user)
              captured[:after_client_data] = data.fetch(:client_data)
              captured[:after_context] = data.fetch(:context)
              nil
            end
          }
        )
      ]
    )
    captured[:user] = auth.context.internal_adapter.create_user(email: "after-registration-route@example.com", name: "After Route", emailVerified: true)
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(query: {context: "after-route-context"}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    auth.api.verify_passkey_registration(
      headers: {"cookie" => cookie_header(registration.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
      body: {response: response}
    )

    assert_equal [:ctx, :verification, :user, :client_data, :context], captured.fetch(:after_keys)
    assert captured.fetch(:after_ctx)
    assert captured.fetch(:after_verification)
    assert_equal "after-registration-route@example.com", captured.fetch(:after_user).fetch(:name)
    assert_equal response.fetch("id"), captured.fetch(:after_client_data).fetch("id")
    assert_equal "after-route-context", captured.fetch(:after_context)
  end

  def test_verify_registration_rejects_duplicate_credential_id
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "duplicate-registration-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    create_passkey(auth, user_id: user.fetch("id"), name: "Existing", credential_id: response.fetch("id"))

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
        body: {response: response}
      )
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("PREVIOUSLY_REGISTERED"), error.message
    assert_equal 1, auth.context.adapter.find_many(model: "passkey", where: [{field: "credentialID", value: response.fetch("id")}]).length
  end
end

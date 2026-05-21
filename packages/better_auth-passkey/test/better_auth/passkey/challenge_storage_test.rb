# frozen_string_literal: true

require_relative "support"

class BetterAuthPasskeyChallengeStorageTest < Minitest::Test
  include BetterAuthPasskeyTestSupport

  def test_secondary_storage_challenges_are_not_written_to_database_and_are_consumed
    storage = MemorySecondaryStorage.new
    auth = build_auth(secondary_storage: storage)
    cookie = sign_up_cookie(auth, email: "secondary-challenge@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)

    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    registration_keys = storage.data.keys.grep(/\Averification:/)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    assert_empty auth.context.adapter.find_many(model: "verification")
    refute_empty registration_keys

    auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {response: response}
    )

    assert_empty storage.data.keys.grep(/\Averification:/)

    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    authentication_keys = storage.data.keys.grep(/\Averification:/)
    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")

    assert_empty auth.context.adapter.find_many(model: "verification")
    refute_empty authentication_keys

    auth.api.verify_passkey_authentication(
      headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
      body: {response: assertion}
    )

    assert_empty storage.data.keys.grep(/\Averification:/)
  end

  def test_missing_challenge_cookie_returns_challenge_not_found
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "missing-challenge-cookie@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie})
    response = client.create(challenge: registration.fetch(:challenge), rp_id: "localhost")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => cookie, "origin" => ORIGIN},
        body: {response: response}
      )
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND"), error.message
  end

  def test_tampered_challenge_cookie_returns_challenge_not_found
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "tampered-challenge-cookie@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie})
    response = client.create(challenge: registration.fetch(:challenge), rp_id: "localhost")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => [cookie, "better-auth-passkey=tampered.bad-signature"].join("; "), "origin" => ORIGIN},
        body: {response: response}
      )
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND"), error.message
  end

  def test_custom_challenge_cookie_name_works_through_registration_verification
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          advanced: {web_authn_challenge_cookie: "custom-passkey-challenge"}
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "custom-challenge-cookie@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)

    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    assert_includes registration.fetch(:headers).fetch("set-cookie"), "custom-passkey-challenge="

    passkey = auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {response: response}
    )

    assert_equal "custom-challenge-cookie@example.com", auth.context.internal_adapter.find_user_by_id(passkey.fetch("userId")).fetch("email")
  end
end

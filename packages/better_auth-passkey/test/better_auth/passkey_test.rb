# frozen_string_literal: true

require "json"
require "forwardable"
require "webauthn"
require "webauthn/fake_client"
require_relative "../test_helper"

class BetterAuthPluginsPasskeyTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"
  ORIGIN = "http://localhost:3000"

  def test_generate_passkey_registration_options_returns_upstream_shape_and_cookie
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "register-shape@example.com")

    registration = auth.api.generate_passkey_registration_options(
      headers: {"cookie" => cookie},
      return_headers: true
    )
    options = registration.fetch(:response)

    assert_includes options.keys, :challenge
    assert_includes options.keys, :rp
    assert_includes options.keys, :user
    assert_includes options.keys, :pubKeyCredParams
    assert_includes registration.fetch(:headers).fetch("set-cookie"), "better-auth-passkey"
  end

  def test_generate_passkey_authentication_options_returns_upstream_shape
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "authenticate-shape@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    create_passkey(auth, user_id: user.fetch("id"), name: "Existing")

    options = auth.api.generate_passkey_authentication_options(headers: {"cookie" => cookie})

    assert_includes options.keys, :challenge
    assert_includes options.keys, :rpId
    assert_includes options.keys, :allowCredentials
    assert_includes options.keys, :userVerification
  end

  def test_generate_passkey_authentication_options_without_session_returns_discoverable_shape
    auth = build_auth

    options = auth.api.generate_passkey_authentication_options

    assert_includes options.keys, :challenge
    assert_includes options.keys, :rpId
    assert_includes options.keys, :userVerification
    refute_includes options.keys, :allowCredentials
  end

  def test_list_passkeys_returns_upstream_passkey_shape
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "list-shape@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    create_passkey(auth, user_id: user.fetch("id"), name: "Listed", aaguid: "mockAAGUID")

    passkeys = auth.api.list_passkeys(headers: {"cookie" => cookie})

    assert_instance_of Array, passkeys
    assert_includes passkeys.first.keys, "id"
    assert_includes passkeys.first.keys, "userId"
    assert_includes passkeys.first.keys, "publicKey"
    assert_includes passkeys.first.keys, "credentialID"
    assert_includes passkeys.first.keys, "aaguid"
  end

  def test_registration_challenge_expiration_is_computed_per_request
    init_time = Time.utc(2026, 1, 1, 12, 0, 0)
    request_time = init_time + (6 * 60)
    auth = nil

    with_time_now(init_time) do
      auth = build_auth
    end

    with_time_now(request_time) do
      cookie = sign_up_cookie(auth, email: "registration-expiration@example.com")
      auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie})
    end

    verification = latest_passkey_verification(auth)
    assert_operator Time.parse(verification.fetch("expiresAt").to_s), :>, request_time
  end

  def test_authentication_challenge_expiration_is_computed_per_request
    init_time = Time.utc(2026, 1, 1, 12, 0, 0)
    request_time = init_time + (6 * 60)
    auth = nil

    with_time_now(init_time) do
      auth = build_auth
    end

    with_time_now(request_time) do
      auth.api.generate_passkey_authentication_options
    end

    verification = latest_passkey_verification(auth)
    assert_operator Time.parse(verification.fetch("expiresAt").to_s), :>, request_time
  end

  def test_registers_and_authenticates_with_real_webauthn_challenges
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "passkey@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)

    registration = auth.api.generate_passkey_registration_options(
      headers: {"cookie" => cookie},
      return_headers: true
    )
    registration_options = registration.fetch(:response)
    registration_cookie = [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; ")

    credential_response = client.create(
      challenge: registration_options.fetch(:challenge),
      rp_id: "localhost"
    )
    passkey = auth.api.verify_passkey_registration(
      headers: {"cookie" => registration_cookie, "origin" => ORIGIN},
      body: {name: "Laptop Touch ID", response: credential_response}
    )

    assert_equal "Laptop Touch ID", passkey.fetch("name")
    assert_equal "passkey@example.com", auth.context.internal_adapter.find_user_by_id(passkey.fetch("userId")).fetch("email")
    assert_equal credential_response.fetch("id"), passkey.fetch("credentialID")
    assert passkey.fetch("publicKey")
    assert_equal 0, passkey.fetch("counter")
    assert_equal "singleDevice", passkey.fetch("deviceType")
    assert_equal "internal", passkey.fetch("transports")

    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    authentication_options = authentication.fetch(:response)
    authentication_cookie = cookie_header(authentication.fetch(:headers).fetch("set-cookie"))
    assertion_response = client.get(
      challenge: authentication_options.fetch(:challenge),
      rp_id: "localhost"
    )

    status, headers, body = auth.api.verify_passkey_authentication(
      headers: {"cookie" => authentication_cookie, "origin" => ORIGIN},
      body: {response: assertion_response},
      as_response: true
    )
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("session").fetch("token"))
    assert_equal "passkey@example.com", data.fetch("user").fetch("email")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="

    updated_passkey = auth.context.adapter.find_one(model: "passkey", where: [{field: "id", value: passkey.fetch("id")}])
    assert_operator updated_passkey.fetch("counter"), :>, 0
  end

  def test_passkey_first_registration_resolves_user_context_extensions_and_callback
    captured = {}
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false,
            extensions: {credProps: true},
            resolve_user: lambda do |data|
              captured[:resolve_context] = data.fetch(:context)
              {id: captured.fetch(:user).fetch("id"), name: "resolved@example.com", display_name: "Resolved User"}
            end,
            after_verification: lambda do |data|
              captured[:after_context] = data.fetch(:context)
              captured[:after_user] = data.fetch(:user)
              captured[:after_client_data] = data.fetch(:client_data)
              nil
            end
          }
        )
      ]
    )
    captured[:user] = auth.context.internal_adapter.create_user(email: "resolved@example.com", name: "Resolved User", emailVerified: true)
    client = WebAuthn::FakeClient.new(ORIGIN)

    registration = auth.api.generate_passkey_registration_options(
      query: {context: "signed-registration-token", name: "Primary"},
      return_headers: true
    )
    registration_options = registration.fetch(:response)
    challenge = latest_passkey_verification(auth)

    assert_equal "signed-registration-token", captured[:resolve_context]
    assert_equal({credProps: true}, registration_options.fetch(:extensions))
    stored_challenge = JSON.parse(challenge.fetch("value"))
    assert_equal "signed-registration-token", stored_challenge.fetch("context")
    assert_equal "resolved@example.com", stored_challenge.fetch("userData").fetch("name")
    assert_equal "Resolved User", stored_challenge.fetch("userData").fetch("displayName")

    response = client.create(challenge: registration_options.fetch(:challenge), rp_id: "localhost")
    passkey = auth.api.verify_passkey_registration(
      headers: {"cookie" => cookie_header(registration.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
      body: {name: "Primary", response: response}
    )

    assert_equal captured.fetch(:user).fetch("id"), passkey.fetch("userId")
    assert_equal "signed-registration-token", captured[:after_context]
    assert_equal "resolved@example.com", captured.fetch(:after_user).fetch(:name)
    assert_equal response.fetch("id"), captured.fetch(:after_client_data).fetch("id")
  end

  def test_passkey_first_registration_requires_resolver_and_valid_user
    missing_resolver = build_auth(
      plugins: [BetterAuth::Plugins.passkey(registration: {require_session: false})]
    )

    missing = assert_raises(BetterAuth::APIError) do
      missing_resolver.api.generate_passkey_registration_options
    end
    assert_equal 400, missing.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("RESOLVE_USER_REQUIRED"), missing.message

    invalid_resolver = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false,
            resolve_user: ->(_data) { {id: "resolved-user-id"} }
          }
        )
      ]
    )

    invalid = assert_raises(BetterAuth::APIError) do
      invalid_resolver.api.generate_passkey_registration_options
    end
    assert_equal 400, invalid.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("RESOLVED_USER_INVALID"), invalid.message
  end

  def test_passkey_first_registration_rejects_invalid_after_verification_user_id
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false,
            resolve_user: ->(_data) { {id: "resolved-user-id", name: "resolved@example.com"} },
            after_verification: ->(_data) { {user_id: 123} }
          }
        )
      ]
    )
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => cookie_header(registration.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
        body: {response: response}
      )
    end
    assert_equal 400, invalid.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("RESOLVED_USER_INVALID"), invalid.message
  end

  def test_passkey_first_registration_allows_after_verification_user_id_override
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false,
            resolve_user: ->(_data) { {id: "pending-user-id", name: "pending@example.com"} },
            after_verification: ->(_data) { {user_id: @linked_user.fetch("id")} }
          }
        )
      ]
    )
    @linked_user = auth.context.internal_adapter.create_user(email: "linked-passkey@example.com", name: "Linked User", emailVerified: true)
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    passkey = auth.api.verify_passkey_registration(
      headers: {"cookie" => cookie_header(registration.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
      body: {response: response}
    )

    assert_equal @linked_user.fetch("id"), passkey.fetch("userId")
  end

  def test_passkey_first_registration_with_optional_stale_session_does_not_require_fresh_session
    auth = build_auth(
      session: {fresh_age: 1},
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "optional-stale-session@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    session = auth.context.adapter.find_many(model: "session", where: [{field: "userId", value: user.fetch("id")}]).first
    auth.context.adapter.update(
      model: "session",
      where: [{field: "id", value: session.fetch("id")}],
      update: {createdAt: Time.now - 120}
    )
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    passkey = auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {response: response}
    )

    assert_equal user.fetch("id"), passkey.fetch("userId")
  end

  def test_session_registration_rejects_after_verification_user_id_mismatch
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            after_verification: ->(_data) { {user_id: "different-user-id"} }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "session-mismatch@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
        body: {response: response}
      )
    end

    assert_equal 401, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"), error.message
    assert_empty auth.context.adapter.find_many(model: "passkey")
  end

  def test_authentication_extensions_callback_and_array_origin
    captured = {}
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          origin: ["https://app.example.test", ORIGIN],
          authentication: {
            extensions: ->(data) {
              captured[:extensions_ctx] = data.fetch(:ctx)
              {appid: "https://legacy.example.test"}
            },
            after_verification: ->(data) {
              captured[:auth_client_data] = data.fetch(:client_data)
              captured[:auth_verification] = data.fetch(:verification)
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "array-origin@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    passkey = auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {response: response}
    )

    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)

    assert_equal({appid: "https://legacy.example.test"}, authentication.fetch(:response).fetch(:extensions))
    assert captured[:extensions_ctx]

    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")
    result = auth.api.verify_passkey_authentication(
      headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
      body: {response: assertion}
    )

    assert_equal passkey.fetch("userId"), result.fetch(:user).fetch("id")
    assert_equal assertion.fetch("id"), captured.fetch(:auth_client_data).fetch("id")
    assert captured[:auth_verification]
  end

  def test_lists_updates_and_deletes_only_the_current_users_passkeys
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "first-passkey@example.com")
    second_cookie = sign_up_cookie(auth, email: "second-passkey@example.com")
    first_user = auth.api.get_session(headers: {"cookie" => first_cookie})[:user]
    second_user = auth.api.get_session(headers: {"cookie" => second_cookie})[:user]
    first = create_passkey(auth, user_id: first_user["id"], name: "First")
    second = create_passkey(auth, user_id: second_user["id"], name: "Second")

    listed = auth.api.list_passkeys(headers: {"cookie" => first_cookie})

    assert_equal [first.fetch("id")], listed.map { |passkey| passkey.fetch("id") }

    updated = auth.api.update_passkey(
      headers: {"cookie" => first_cookie},
      body: {id: first.fetch("id"), name: "Renamed"}
    )
    assert_equal "Renamed", updated.fetch(:passkey).fetch("name")

    unauthorized = assert_raises(BetterAuth::APIError) do
      auth.api.delete_passkey(headers: {"cookie" => first_cookie}, body: {id: second.fetch("id")})
    end
    assert_equal 404, unauthorized.status_code
    assert auth.context.adapter.find_one(model: "passkey", where: [{field: "id", value: second.fetch("id")}])

    update_unauthorized = assert_raises(BetterAuth::APIError) do
      auth.api.update_passkey(headers: {"cookie" => first_cookie}, body: {id: second.fetch("id"), name: "Hacked"})
    end
    assert_equal 404, update_unauthorized.status_code
    assert_equal "Second", auth.context.adapter.find_one(model: "passkey", where: [{field: "id", value: second.fetch("id")}]).fetch("name")

    deleted = auth.api.delete_passkey(headers: {"cookie" => first_cookie}, body: {id: first.fetch("id")})

    assert_equal({status: true}, deleted)
    assert_empty auth.api.list_passkeys(headers: {"cookie" => first_cookie})
  end

  def test_option_shapes_include_transport_details_and_per_request_expiration
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "shape@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    create_passkey(auth, user_id: user.fetch("id"), name: "Security Key", credential_id: "credential-one", transports: "internal,usb")

    before_registration = Time.now
    registration = auth.api.generate_passkey_registration_options(
      headers: {"cookie" => cookie},
      query: {authenticatorAttachment: "platform", name: "Work laptop"},
      return_headers: true
    )
    registration_options = registration.fetch(:response)
    registration_verification = latest_passkey_verification(auth)

    assert_equal "Work laptop", registration_options.fetch(:user).fetch(:name)
    assert_equal "none", registration_options.fetch(:attestation)
    assert_equal "platform", registration_options.fetch(:authenticatorSelection).fetch(:authenticatorAttachment)
    assert_equal [{id: "credential-one", transports: ["internal", "usb"]}], registration_options.fetch(:excludeCredentials)
    assert_operator Time.parse(registration_verification.fetch("expiresAt").to_s), :>, before_registration

    before_authentication = Time.now
    authentication = auth.api.generate_passkey_authentication_options(headers: {"cookie" => cookie})
    authentication_verification = latest_passkey_verification(auth)

    assert_equal [{id: "credential-one", type: "public-key", transports: ["internal", "usb"]}], authentication.fetch(:allowCredentials)
    assert_equal "preferred", authentication.fetch(:userVerification)
    assert_operator Time.parse(authentication_verification.fetch("expiresAt").to_s), :>, before_authentication

    discoverable = auth.api.generate_passkey_authentication_options
    refute_includes discoverable.keys, :allowCredentials
  end

  def test_custom_schema_deep_merges_with_base_passkey_schema
    plugin = BetterAuth::Plugins.passkey(
      schema: {
        passkey: {
          fields: {
            name: {required: true},
            publicKey: {required: false}
          }
        }
      }
    )

    fields = plugin.schema.fetch(:passkey).fetch(:fields)

    assert_equal true, fields.fetch(:name).fetch(:required)
    assert_equal({type: "string", required: false}, fields.fetch(:public_key))
    assert_equal({type: "number", required: true}, fields.fetch(:counter))
  end

  def test_passkey_uses_scoped_webauthn_relying_party_per_auth_instance
    WebAuthn.configuration.rp_id = "global.example"
    WebAuthn.configuration.rp_name = "Global App"
    WebAuthn.configuration.allowed_origins = ["https://global.example"]

    first = build_auth(
      base_url: "https://first.example",
      plugins: [
        BetterAuth::Plugins.passkey(
          rp_id: "first.example",
          rp_name: "First App",
          origin: "https://first.example"
        )
      ]
    )
    second = build_auth(
      base_url: "https://second.example",
      plugins: [
        BetterAuth::Plugins.passkey(
          rp_id: "second.example",
          rp_name: "Second App",
          origin: "https://second.example"
        )
      ]
    )
    first_cookie = sign_up_cookie(first, email: "first-scoped-passkey@example.com")
    second_cookie = sign_up_cookie(second, email: "second-scoped-passkey@example.com")

    first_options = first.api.generate_passkey_registration_options(headers: {"cookie" => first_cookie})
    second_options = second.api.generate_passkey_registration_options(headers: {"cookie" => second_cookie})
    second_auth_options = second.api.generate_passkey_authentication_options

    assert_equal({id: "first.example", name: "First App"}, first_options.fetch(:rp))
    assert_equal({id: "second.example", name: "Second App"}, second_options.fetch(:rp))
    assert_equal "second.example", second_auth_options.fetch(:rpId)
    assert_equal "global.example", WebAuthn.configuration.rp_id
    assert_equal "Global App", WebAuthn.configuration.rp_name
    assert_equal ["https://global.example"], WebAuthn.configuration.allowed_origins
  ensure
    WebAuthn.configuration.rp_id = nil
    WebAuthn.configuration.rp_name = nil
    WebAuthn.configuration.allowed_origins = []
  end

  def test_update_passkey_requires_name
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "update-validation@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    passkey = create_passkey(auth, user_id: user.fetch("id"), name: "Original")

    missing_name = assert_raises(BetterAuth::APIError) do
      auth.api.update_passkey(headers: {"cookie" => cookie}, body: {id: passkey.fetch("id")})
    end

    assert_equal 400, missing_name.status_code
    assert_equal "Original", auth.context.adapter.find_one(model: "passkey", where: [{field: "id", value: passkey.fetch("id")}]).fetch("name")
  end

  def test_validates_passkey_request_shapes
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "validation@example.com")

    invalid_attachment = assert_raises(BetterAuth::APIError) do
      auth.api.generate_passkey_registration_options(
        headers: {"cookie" => cookie},
        query: {authenticatorAttachment: "phone"}
      )
    end
    assert_equal 400, invalid_attachment.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES.fetch("VALIDATION_ERROR"), invalid_attachment.message

    missing_delete_id = assert_raises(BetterAuth::APIError) do
      auth.api.delete_passkey(headers: {"cookie" => cookie}, body: {})
    end
    assert_equal 400, missing_delete_id.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES.fetch("VALIDATION_ERROR"), missing_delete_id.message

    missing_auth_response = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_authentication(headers: {"origin" => ORIGIN}, body: {})
    end
    assert_equal 400, missing_auth_response.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES.fetch("VALIDATION_ERROR"), missing_auth_response.message
  end

  def test_sql_schema_includes_passkey_table
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.passkey]
    )

    sql = BetterAuth::Schema::SQL.create_statements(config, dialect: :postgres).join("\n")

    assert_includes sql, 'CREATE TABLE IF NOT EXISTS "passkeys"'
    assert_includes sql, '"credential_id" text NOT NULL'
    assert_includes sql, 'UNIQUE ("credential_id")'
    assert_includes sql, 'CREATE INDEX IF NOT EXISTS "index_passkeys_on_user_id" ON "passkeys" ("user_id")'
    refute_includes sql, "index_passkeys_on_credential_id"
  end

  def test_rejects_expired_challenge_and_delete_not_found_message
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "expired-challenge@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    challenge_cookie = cookie_header(registration.fetch(:headers).fetch("set-cookie"))
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    verification = latest_passkey_verification(auth)
    auth.context.adapter.update(
      model: "verification",
      where: [{field: "id", value: verification.fetch("id")}],
      update: {expiresAt: Time.now - 1}
    )

    expired = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => [cookie, challenge_cookie].join("; "), "origin" => ORIGIN},
        body: {response: response}
      )
    end
    assert_equal 400, expired.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND"), expired.message

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.delete_passkey(headers: {"cookie" => cookie}, body: {id: "missing-passkey"})
    end
    assert_equal 404, missing.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND"), missing.message
  end

  def test_rejects_missing_challenge_and_wrong_registration_user
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "first-challenge@example.com")
    second_cookie = sign_up_cookie(auth, email: "second-challenge@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => first_cookie, "origin" => ORIGIN},
        body: {response: client.create(challenge: WebAuthn::Credential.options_for_create(user: {id: "u", name: "u"}).challenge)}
      )
    end
    assert_equal 400, missing.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND"), missing.message

    registration = auth.api.generate_passkey_registration_options(
      headers: {"cookie" => first_cookie},
      return_headers: true
    )
    registration_cookie = cookie_header(registration.fetch(:headers).fetch("set-cookie"))
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    wrong_user = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => [second_cookie, registration_cookie].join("; "), "origin" => ORIGIN},
        body: {response: response}
      )
    end
    assert_equal 401, wrong_user.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"), wrong_user.message
  end

  def test_delete_passkey_for_another_user_returns_not_found_message
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "first-delete-message@example.com")
    second_cookie = sign_up_cookie(auth, email: "second-delete-message@example.com")
    second_user = auth.api.get_session(headers: {"cookie" => second_cookie})[:user]
    other_passkey = create_passkey(auth, user_id: second_user.fetch("id"), name: "Their Passkey", credential_id: "delete-msg-cred")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_passkey(headers: {"cookie" => first_cookie}, body: {id: other_passkey.fetch("id")})
    end

    assert_equal "NOT_FOUND", error.code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND"), error.message
  end

  def test_register_options_exclude_credentials_match_upstream_shape
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "exclude-shape@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    create_passkey(auth, user_id: user.fetch("id"), name: "Existing", credential_id: "shape-cred", transports: "internal,usb")

    options = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie})
    refute_empty options.fetch(:excludeCredentials)
    options.fetch(:excludeCredentials).each do |entry|
      refute_includes entry.keys, :type
      refute_includes entry.keys, "type"
      assert_kind_of String, entry[:id]
      assert(entry[:transports].nil? || entry[:transports].is_a?(Array))
    end
  end

  def test_register_options_omit_transports_when_passkey_has_none
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "no-transports@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    create_passkey(auth, user_id: user.fetch("id"), name: "No Transports", credential_id: "no-transports-cred", transports: nil)

    options = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie})
    refute_empty options.fetch(:excludeCredentials)
    options.fetch(:excludeCredentials).each do |entry|
      refute_includes entry.keys, :transports
      refute_includes entry.keys, "transports"
    end
  end

  def test_rp_id_falls_back_to_hostname_with_port_stripped
    ctx = build_passkey_ctx(base_url: "https://example.com:8443/api/auth")
    rp_id = BetterAuth::Plugins.send(:passkey_rp_id, {}, ctx)
    assert_equal "example.com", rp_id
  end

  def test_rp_id_rejects_invalid_base_url
    ctx = build_passkey_ctx(base_url: "not a url")

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.send(:passkey_rp_id, {}, ctx)
    end

    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"), error.message
  end

  def test_rp_id_returns_localhost_when_base_url_is_blank
    ctx = build_passkey_ctx(base_url: "")
    rp_id = BetterAuth::Plugins.send(:passkey_rp_id, {}, ctx)
    assert_equal "localhost", rp_id
  end

  def test_rp_id_explicit_config_takes_precedence_over_base_url
    ctx = build_passkey_ctx(base_url: "https://ignored.example")
    rp_id = BetterAuth::Plugins.send(:passkey_rp_id, {rp_id: "explicit.example"}, ctx)
    assert_equal "explicit.example", rp_id
  end

  def test_after_verification_user_id_matrix_accepts_nil_and_empty_string
    nil_passkey = perform_passkey_first_registration(returning_user_id: nil)
    assert_equal "matrix-pending-user-id", nil_passkey.fetch("userId")

    empty_passkey = perform_passkey_first_registration(returning_user_id: "")
    assert_equal "matrix-pending-user-id", empty_passkey.fetch("userId")
  end

  def test_after_verification_user_id_matrix_accepts_non_empty_string
    linked_passkey = perform_passkey_first_registration(returning_user_id: "matrix-linked-user-id")
    assert_equal "matrix-linked-user-id", linked_passkey.fetch("userId")
  end

  def test_after_verification_user_id_matrix_rejects_integer
    error = assert_raises(BetterAuth::APIError) do
      perform_passkey_first_registration(returning_user_id: 123)
    end
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("RESOLVED_USER_INVALID"), error.message
  end

  def test_after_verification_user_id_matrix_rejects_boolean
    error = assert_raises(BetterAuth::APIError) do
      perform_passkey_first_registration(returning_user_id: true)
    end
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("RESOLVED_USER_INVALID"), error.message
  end

  def test_update_passkey_allows_empty_name_to_match_upstream
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "update-empty-name@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    passkey = create_passkey(auth, user_id: user.fetch("id"), name: "Original", credential_id: "empty-name-cred")

    result = auth.api.update_passkey(
      headers: {"cookie" => cookie},
      body: {id: passkey.fetch("id"), name: ""}
    )

    assert_equal "", result.fetch(:passkey).fetch("name")
  end

  def test_registration_missing_origin_uses_failed_registration_error
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "missing-origin@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; ")},
        body: {response: response}
      )
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"), error.message
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({
      base_url: ORIGIN,
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.passkey]
    }.merge(options).merge(email_and_password: email_and_password))
  end

  def build_passkey_ctx(base_url:)
    options = Struct.new(:base_url).new(base_url)
    context = Struct.new(:options).new(options)
    Struct.new(:context).new(context)
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Passkey User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def create_passkey(auth, user_id:, name:, credential_id: "#{name}-credential", transports: "internal", aaguid: nil)
    auth.context.adapter.create(
      model: "passkey",
      data: {
        userId: user_id,
        name: name,
        publicKey: "mock-public-key",
        credentialID: credential_id,
        counter: 0,
        deviceType: "singleDevice",
        backedUp: false,
        transports: transports,
        createdAt: Time.now,
        aaguid: aaguid
      }
    )
  end

  def perform_passkey_first_registration(returning_user_id:)
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false,
            resolve_user: ->(_data) { {id: "matrix-pending-user-id", name: "matrix-pending@example.com"} },
            after_verification: ->(_data) { {user_id: returning_user_id} }
          }
        )
      ]
    )
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    auth.api.verify_passkey_registration(
      headers: {"cookie" => cookie_header(registration.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
      body: {response: response}
    )
  end

  def latest_passkey_verification(auth)
    auth.context.adapter.find_many(model: "verification").max_by { |entry| entry.fetch("createdAt") || Time.at(0) }
  end

  def with_time_now(fixed_time)
    singleton = class << Time; self; end
    original_now = Time.method(:now)

    singleton.remove_method(:now)
    singleton.define_method(:now) { fixed_time }
    yield
  ensure
    singleton.remove_method(:now)
    singleton.define_method(:now, original_now)
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end
end

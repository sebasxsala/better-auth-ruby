# frozen_string_literal: true

require "json"
require "rack/mock"
require_relative "../../test_helper"

class BetterAuthPluginsDeviceAuthorizationTest < Minitest::Test
  SECRET = "phase-eleven-secret-with-enough-entropy-123"

  def test_device_code_polling_approval_and_token_exchange
    auth = build_auth

    issued = auth.api.device_code(body: {client_id: "cli", scope: "openid profile"})
    assert_equal "device-code-123", issued[:device_code]
    assert_equal "ABCD-EFGH", issued[:user_code]
    assert_equal "http://localhost:3000/api/auth/device", issued[:verification_uri]
    assert_equal "http://localhost:3000/api/auth/device?user_code=ABCD-EFGH", issued[:verification_uri_complete]

    pending = assert_raises(BetterAuth::APIError) do
      auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "cli"})
    end
    assert_equal "authorization_pending", pending.code
    assert_equal "Authorization pending", pending.message

    slow_down = assert_raises(BetterAuth::APIError) do
      auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "cli"})
    end
    assert_equal "slow_down", slow_down.code
    assert_equal "Polling too frequently", slow_down.message

    verified = auth.api.device_verify(query: {user_code: "ABCDEFGH"})
    assert_equal "pending", verified[:status]

    cookie = sign_up_cookie(auth)
    approved = auth.api.device_approve(headers: {"cookie" => cookie}, body: {user_code: "ABCD-EFGH"})
    assert_equal({success: true}, approved)
    record = auth.context.adapter.find_one(model: "deviceCode", where: [{field: "deviceCode", value: issued[:device_code]}])
    auth.context.adapter.update(model: "deviceCode", where: [{field: "id", value: record["id"]}], update: {"lastPolledAt" => Time.now - 6})

    token = auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "cli"})
    assert_equal "Bearer", token[:token_type]
    assert token[:access_token]
    assert_equal "openid profile", token[:scope]

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "cli"})
    end
    assert_equal "invalid_grant", invalid.code
    assert_equal "Invalid device code", invalid.message
  end

  def test_client_validation_and_custom_verification_uri
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.device_authorization(
          verification_uri: "/activate",
          validate_client: ->(client_id) { client_id == "valid-client" }
        )
      ]
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.device_code(body: {client_id: "bad-client"})
    end
    assert_equal "invalid_client", error.code
    assert_equal "Invalid client ID", error.message

    issued = auth.api.device_code(body: {client_id: "valid-client"})
    assert_equal "http://localhost:3000/api/auth/activate", issued[:verification_uri]
  end

  def test_device_authorization_validates_options_on_plugin_creation
    assert_raises(BetterAuth::Error) { BetterAuth::Plugins.device_authorization(expires_in: "nope") }
    assert_raises(BetterAuth::Error) { BetterAuth::Plugins.device_authorization(interval: "nope") }
    assert_raises(BetterAuth::Error) { BetterAuth::Plugins.device_authorization(device_code_length: 0) }
    assert_raises(BetterAuth::Error) { BetterAuth::Plugins.device_authorization(user_code_length: -1) }
    assert_raises(BetterAuth::Error) { BetterAuth::Plugins.device_authorization(generate_device_code: "not-callable") }
    assert_raises(BetterAuth::Error) { BetterAuth::Plugins.device_authorization(generate_user_code: "not-callable") }
    assert_raises(BetterAuth::Error) { BetterAuth::Plugins.device_authorization(validate_client: "not-callable") }
    assert_raises(BetterAuth::Error) { BetterAuth::Plugins.device_authorization(on_device_auth_request: "not-callable") }
    assert_raises(BetterAuth::Error) { BetterAuth::Plugins.device_authorization(verification_uri: 123) }

    plugin = BetterAuth::Plugins.device_authorization(expires_in: "1m", interval: "2s", device_code_length: 50, user_code_length: 10)

    assert_equal "1m", plugin[:options][:expires_in]
    assert_equal "2s", plugin[:options][:interval]
    assert_equal 50, plugin[:options][:device_code_length]
    assert_equal 10, plugin[:options][:user_code_length]
  end

  def test_device_authorization_returns_oauth_error_codes_and_descriptions
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.device_authorization(
          validate_client: ->(client_id) { %w[valid-client valid-client-2].include?(client_id) }
        )
      ]
    )

    invalid_client = assert_raises(BetterAuth::APIError) do
      auth.api.device_code(body: {client_id: "invalid-client"})
    end
    assert_equal 400, invalid_client.status_code
    assert_equal "invalid_client", invalid_client.code
    assert_equal "Invalid client ID", invalid_client.message

    issued = auth.api.device_code(body: {client_id: "valid-client"})
    invalid_token_client = assert_raises(BetterAuth::APIError) do
      auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "invalid-client"})
    end
    assert_equal 400, invalid_token_client.status_code
    assert_equal "invalid_grant", invalid_token_client.code
    assert_equal "Invalid client ID", invalid_token_client.message

    mismatched_client = assert_raises(BetterAuth::APIError) do
      auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "valid-client-2"})
    end
    assert_equal 400, mismatched_client.status_code
    assert_equal "invalid_grant", mismatched_client.code
    assert_equal "Client ID mismatch", mismatched_client.message

    invalid_code = assert_raises(BetterAuth::APIError) do
      auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: "missing", client_id: "valid-client"})
    end
    assert_equal "invalid_grant", invalid_code.code
    assert_equal "Invalid device code", invalid_code.message
  end

  def test_device_authorization_rack_errors_use_oauth_response_shape
    auth = build_auth
    response = Rack::MockRequest.new(auth).post(
      "/api/auth/device/token",
      "CONTENT_TYPE" => "application/json",
      :input => JSON.generate({grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: "missing", client_id: "cli"})
    )
    body = JSON.parse(response.body)

    assert_equal 400, response.status
    assert_equal "invalid_grant", body.fetch("error")
    assert_equal "Invalid device code", body.fetch("error_description")
  end

  def test_device_approval_uses_camel_case_body_and_rejects_processed_or_wrong_user
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "device-first@example.com")
    issued = auth.api.device_code(body: {client_id: "cli"})

    assert_equal({success: true}, auth.api.device_approve(headers: {"cookie" => first_cookie}, body: {userCode: issued[:user_code]}))

    processed = assert_raises(BetterAuth::APIError) do
      auth.api.device_approve(headers: {"cookie" => first_cookie}, body: {userCode: issued[:user_code]})
    end
    assert_equal 400, processed.status_code
    assert_equal "invalid_request", processed.code
    assert_equal "Device code already processed", processed.message

    other_auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.device_authorization(generate_device_code: -> { "device-code-forbidden" }, generate_user_code: -> { "DENYCODE" })
      ]
    )
    first_cookie = sign_up_cookie(other_auth, email: "device-first@example.com")
    second_cookie = sign_up_cookie(other_auth, email: "device-second@example.com")
    pending = other_auth.api.device_code(body: {client_id: "cli"})
    record = other_auth.context.adapter.find_one(model: "deviceCode", where: [{field: "deviceCode", value: pending[:device_code]}])
    other_auth.context.adapter.update(model: "deviceCode", where: [{field: "id", value: record["id"]}], update: {"userId" => other_auth.api.get_session(headers: {"cookie" => first_cookie})[:user]["id"]})

    forbidden = assert_raises(BetterAuth::APIError) do
      other_auth.api.device_deny(headers: {"cookie" => second_cookie}, body: {userCode: pending[:user_code]})
    end
    assert_equal 403, forbidden.status_code
    assert_equal "access_denied", forbidden.code
    assert_equal "You are not authorized to deny this device authorization", forbidden.message
  end

  def test_device_token_exchange_sets_new_session_for_hooks_without_session_cookie
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.device_authorization(generate_device_code: -> { "device-code-hook" }, generate_user_code: -> { "HOOKCODE" }),
        BetterAuth::Plugins.one_time_token(set_ott_header_on_new_session: true)
      ]
    )
    cookie = sign_up_cookie(auth, email: "device-hook@example.com")
    issued = auth.api.device_code(body: {client_id: "cli", scope: "read write"})
    auth.api.device_approve(headers: {"cookie" => cookie}, body: {userCode: issued[:user_code]})

    status, headers, body = auth.api.device_token(
      body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "cli"},
      as_response: true
    )
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("access_token"))
    assert_equal "Bearer", data.fetch("token_type")
    assert_equal "read write", data.fetch("scope")
    refute data.key?("user")
    refute headers.fetch("set-cookie", "").include?("better-auth.session_token=")
    assert_match(/\A[A-Za-z0-9_-]{32}\z/, headers.fetch("set-ott"))
  end

  def test_device_token_exchange_stores_session_in_secondary_storage
    storage = StringStorage.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      secondary_storage: storage,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.device_authorization(
          interval: "5s",
          generate_device_code: -> { "device-code-secondary" },
          generate_user_code: -> { "SECNDRY1" }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "device-secondary@example.com")
    issued = auth.api.device_code(body: {client_id: "cli", scope: "openid profile"})
    auth.api.device_approve(headers: {"cookie" => cookie}, body: {userCode: issued[:user_code]})
    record = auth.context.adapter.find_one(model: "deviceCode", where: [{field: "deviceCode", value: issued[:device_code]}])
    auth.context.adapter.update(model: "deviceCode", where: [{field: "id", value: record["id"]}], update: {"lastPolledAt" => Time.now - 6})

    token = auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "cli"})
    stored = JSON.parse(storage.get(token[:access_token]))

    assert_equal "Bearer", token[:token_type]
    assert_equal "device-secondary@example.com", stored.fetch("user").fetch("email")
    assert_equal token[:access_token], stored.fetch("session").fetch("token")
    assert storage.get("active-sessions-#{stored.fetch("user").fetch("id")}")
  end

  def test_verification_uri_preserves_existing_query_params_and_encodes_user_code
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.device_authorization(
          verification_uri: "/device?lang=en",
          generate_user_code: -> { "ABC-123" }
        )
      ]
    )

    issued = auth.api.device_code(body: {client_id: "cli"})

    assert_equal "http://localhost:3000/api/auth/device?lang=en", issued[:verification_uri]
    assert_equal "http://localhost:3000/api/auth/device?lang=en&user_code=ABC-123", issued[:verification_uri_complete]
  end

  def test_custom_user_code_is_preserved_and_verify_response_matches_upstream_shape
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.device_authorization(
          generate_device_code: -> { "custom-device-code" },
          generate_user_code: -> { "abc-123xy" }
        )
      ]
    )

    issued = auth.api.device_code(body: {client_id: "cli", scope: "openid"})
    verified = auth.api.device_verify(query: {user_code: issued[:user_code]})

    assert_equal "abc-123xy", issued[:user_code]
    assert_equal ["status", "user_code"], verified.transform_keys(&:to_s).keys.sort
    assert_equal "pending", verified[:status]
  end

  def test_custom_expiration_and_interval_are_stored_as_seconds_and_milliseconds
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.device_authorization(
          expires_in: "2m",
          interval: "7s",
          generate_device_code: -> { "device-code-timing" },
          generate_user_code: -> { "TIMING1" }
        )
      ]
    )

    issued = auth.api.device_code(body: {client_id: "cli"})
    record = auth.context.adapter.find_one(model: "deviceCode", where: [{field: "deviceCode", value: issued.fetch(:device_code)}])

    assert_equal 120, issued.fetch(:expires_in)
    assert_equal 7, issued.fetch(:interval)
    assert_equal 7_000, record.fetch("pollingInterval")
    assert_in_delta Time.now + 120, record.fetch("expiresAt"), 5
  end

  def test_device_auth_request_hook_runs_before_persistence
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.device_authorization(
          generate_device_code: -> { "should-not-persist" },
          on_device_auth_request: ->(_client_id, _scope) { raise BetterAuth::APIError.new("BAD_REQUEST", code: "invalid_request", message: "hook rejected") }
        )
      ]
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.device_code(body: {client_id: "cli"})
    end
    persisted = auth.context.adapter.find_one(model: "deviceCode", where: [{field: "deviceCode", value: "should-not-persist"}])

    assert_equal "invalid_request", error.code
    assert_nil persisted
  end

  def test_unauthenticated_device_decisions_use_oauth_error_shape
    auth = build_auth
    issued = auth.api.device_code(body: {client_id: "cli"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.device_approve(body: {user_code: issued[:user_code]})
    end

    assert_equal 401, error.status_code
    assert_equal "unauthorized", error.code
    assert_equal "Authentication required", error.message
  end

  private

  def build_auth
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.device_authorization(
          interval: "5s",
          generate_device_code: -> { "device-code-123" },
          generate_user_code: -> { "ABCD-EFGH" }
        )
      ]
    )
  end

  def sign_up_cookie(auth, email: "device@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Device User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
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
  end
end

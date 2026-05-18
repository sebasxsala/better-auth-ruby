# frozen_string_literal: true

require_relative "../test_support"

class BetterAuthAPIKeyCreateRouteTest < Minitest::Test
  include APIKeyTestSupport

  def test_create_route_uses_upstream_record_shape
    auth = build_api_key_auth(default_key_length: 12, enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "create-route-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    created = auth.api.create_api_key(body: {userId: user_id, name: "route", metadata: {plan: "pro"}})

    assert_equal "route", created[:name]
    assert_equal user_id, created[:referenceId]
    refute created.key?(:userId)
    assert_equal({"plan" => "pro"}, created[:metadata])
  end

  def test_create_route_applies_defaults_hashing_start_and_rate_limit
    auth = build_api_key_auth(default_key_length: 12, default_prefix: "ba_", rate_limit: {enabled: false, time_window: 1000, max_requests: 25})
    cookie = sign_up_cookie(auth, email: "create-route-defaults-key@example.com")

    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})
    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])

    assert_match(/\Aba_[A-Za-z]{12}\z/, created[:key])
    assert_equal "ba_", created[:prefix]
    assert_equal created[:key][0, 6], created[:start]
    assert_equal false, created[:rateLimitEnabled]
    assert_equal 1000, created[:rateLimitTimeWindow]
    assert_equal 25, created[:rateLimitMax]
    refute_equal created[:key], stored.fetch("key")
  end

  def test_create_route_rejects_authenticated_client_server_only_fields
    auth = build_api_key_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "create-route-server-only-key@example.com")

    %i[permissions refillAmount refillInterval rateLimitMax rateLimitTimeWindow rateLimitEnabled remaining].each do |field|
      error = assert_raises(BetterAuth::APIError) do
        auth.api.create_api_key(headers: {"cookie" => cookie}, body: {field => 10})
      end

      assert_equal "BAD_REQUEST", error.status
      assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("SERVER_ONLY_PROPERTY"), error.message
    end
  end

  def test_create_route_rejects_request_mode_user_id_without_session
    auth = build_api_key_auth(default_key_length: 12)

    status, body = rack_json_response(auth, "POST", "/api-key/create", body: {userId: "target-user-id"})

    assert_equal 401, status
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("UNAUTHORIZED_SESSION"), body.fetch("message")
    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "referenceId", value: "target-user-id"}])
  end

  def test_create_route_rejects_request_mode_user_id_mismatch_with_session
    auth = build_api_key_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "create-route-user-id-mismatch-key@example.com")

    status, body = request_mode_api_response(auth, :create_api_key, body: {userId: "someone-else"}, cookie: cookie)

    assert_equal 401, status
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("UNAUTHORIZED_SESSION"), body.fetch("message")
    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "referenceId", value: "someone-else"}])
  end

  def test_create_route_respects_nil_expiration_and_refill_without_remaining
    auth = build_api_key_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "create-route-nil-expiration-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    no_expiration = auth.api.create_api_key(body: {userId: user_id, expiresIn: nil})
    refill = auth.api.create_api_key(body: {userId: user_id, refillAmount: 10, refillInterval: 1000})

    assert_nil no_expiration[:expiresAt]
    assert_nil refill[:remaining]
    assert_equal 10, refill[:refillAmount]
    assert_equal 1000, refill[:refillInterval]
  end

  def test_create_route_deletes_expired_database_keys_like_upstream
    BetterAuth::APIKey::Routes.instance_variable_set(:@last_expired_check, nil)
    auth = build_api_key_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "create-route-cleanup-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    expired = auth.api.create_api_key(body: {userId: user_id})
    auth.context.adapter.update(
      model: "apikey",
      where: [{field: "id", value: expired[:id]}],
      update: {expiresAt: Time.now - 60}
    )
    BetterAuth::APIKey::Routes.instance_variable_set(:@last_expired_check, nil)

    auth.api.create_api_key(body: {userId: user_id})

    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: expired[:id]}])
  end
end

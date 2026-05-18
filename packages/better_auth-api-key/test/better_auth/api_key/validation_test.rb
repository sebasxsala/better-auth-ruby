# frozen_string_literal: true

require_relative "test_support"

class BetterAuthAPIKeyValidationTest < Minitest::Test
  include APIKeyTestSupport

  def test_validate_create_update_rejects_client_server_only_fields
    config = BetterAuth::APIKey::Configuration.normalize({})

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::APIKey::Validation.validate_create_update!(
        {permissions: {repo: ["read"]}},
        config,
        create: true,
        client: true
      )
    end

    assert_equal "BAD_REQUEST", error.status
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("SERVER_ONLY_PROPERTY"), error.message
  end

  def test_validate_create_update_allows_server_remaining_zero_on_create
    config = BetterAuth::APIKey::Configuration.normalize({})

    BetterAuth::APIKey::Validation.validate_create_update!({remaining: 0}, config, create: true, client: false)
  end

  def test_validate_create_update_rejects_mismatched_refill_fields
    config = BetterAuth::APIKey::Configuration.normalize({})

    interval_error = assert_raises(BetterAuth::APIError) do
      BetterAuth::APIKey::Validation.validate_create_update!({refill_interval: 1000}, config, create: true, client: false)
    end
    amount_error = assert_raises(BetterAuth::APIError) do
      BetterAuth::APIKey::Validation.validate_create_update!({refill_amount: 10}, config, create: true, client: false)
    end

    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("REFILL_INTERVAL_AND_AMOUNT_REQUIRED"), interval_error.message
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("REFILL_AMOUNT_AND_INTERVAL_REQUIRED"), amount_error.message
  end

  def test_update_payload_preserves_false_zero_nil_and_encodes_objects
    config = BetterAuth::APIKey::Configuration.normalize(enable_metadata: true)

    update = BetterAuth::APIKey::Validation.update_payload({
      enabled: false,
      remaining: 0,
      expires_in: nil,
      metadata: {tier: "pro"},
      permissions: {repo: ["read"]}
    }, config)

    assert_equal false, update.fetch(:enabled)
    assert_equal 0, update.fetch(:remaining)
    assert_nil update.fetch(:expiresAt)
    assert_equal({"tier" => "pro"}, JSON.parse(update.fetch(:metadata)))
    assert_equal({"repo" => ["read"]}, JSON.parse(update.fetch(:permissions)))
  end

  def test_usage_update_refills_remaining_after_interval_then_decrements
    config = BetterAuth::APIKey::Configuration.normalize(rate_limit: {enabled: false})
    record = {
      "remaining" => 0,
      "refillAmount" => 3,
      "refillInterval" => 1,
      "lastRefillAt" => Time.now - 60,
      "createdAt" => Time.now - 120
    }

    update = BetterAuth::APIKey::Validation.usage_update(record, config)

    assert_equal 2, update.fetch(:remaining)
    assert update.fetch(:lastRefillAt)
    refute update.key?(:requestCount)
  end

  def test_check_permissions_matches_upstream_key_not_found_failure
    record = {"permissions" => JSON.generate({"repo" => ["read"]})}

    BetterAuth::APIKey::Validation.check_permissions!(record, {repo: ["read"]})
    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::APIKey::Validation.check_permissions!(record, {repo: ["write"]})
    end

    assert_equal "UNAUTHORIZED", error.status
    assert_equal "KEY_NOT_FOUND", error.code
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("KEY_NOT_FOUND"), error.message
  end

  def test_validate_api_key_does_not_defer_quota_updates
    deferred = []
    auth = build_api_key_auth(
      default_key_length: 12,
      defer_updates: true,
      rate_limit: {enabled: false},
      advanced: {background_tasks: {handler: ->(task) { deferred << task }}}
    )
    cookie = sign_up_cookie(auth, email: "validation-quota-defer-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 1})

    first = auth.api.verify_api_key(body: {key: created[:key]})
    second = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal true, first[:valid]
    assert_equal false, second[:valid]
    assert_equal "USAGE_EXCEEDED", second[:error][:code]
  end

  def test_validate_api_key_serializes_quota_updates_in_process
    auth = build_api_key_auth(default_key_length: 12, rate_limit: {enabled: false})
    cookie = sign_up_cookie(auth, email: "validation-quota-thread-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 1})
    original_update = auth.context.adapter.method(:update)
    auth.context.adapter.define_singleton_method(:update) do |**kwargs|
      sleep 0.02 if kwargs[:model].to_s == "apikey"
      original_update.call(**kwargs)
    end
    start = Queue.new
    results = 2.times.map do
      Thread.new do
        start.pop
        auth.api.verify_api_key(body: {key: created[:key]})
      end
    end

    2.times { start << true }
    responses = results.map(&:value)

    assert_equal 1, responses.count { |response| response[:valid] == true }
    assert_equal 1, responses.count { |response| response[:valid] == false }
    assert_equal ["USAGE_EXCEEDED"], responses.filter_map { |response| response.dig(:error, :code) }
  end

  def test_validate_api_key_uses_bounded_lock_stripes_for_invalid_keys
    auth = build_api_key_auth(default_key_length: 12, rate_limit: {enabled: false})

    20.times do |index|
      auth.api.verify_api_key(body: {key: "missing-key-#{index}"})
    end

    refute BetterAuth::APIKey::Validation.instance_variable_defined?(:@usage_locks)
  end

  def test_validate_api_key_rejects_when_usage_update_cannot_persist
    auth = build_api_key_auth(default_key_length: 12, rate_limit: {enabled: false})
    cookie = sign_up_cookie(auth, email: "validation-update-nil-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 2})
    original_update = auth.context.adapter.method(:update)
    auth.context.adapter.define_singleton_method(:update) do |**kwargs|
      next nil if kwargs[:model].to_s == "apikey"

      original_update.call(**kwargs)
    end

    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal false, result[:valid]
    assert_equal "FAILED_TO_UPDATE_API_KEY", result[:error][:code]
  end
end

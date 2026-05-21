# frozen_string_literal: true

require "json"
require_relative "support"

class BetterAuthPasskeyRateLimitTest < Minitest::Test
  include BetterAuthPasskeyTestSupport

  def test_memory_rate_limiter_limits_real_passkey_route
    auth = build_auth(rate_limit: {enabled: true, window: 60, max: 1})

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/passkey/generate-authenticate-options")).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/passkey/generate-authenticate-options")).first
  end

  def test_custom_storage_uses_passkey_route_path_without_query_parameters
    storage = RateLimitStorage.new
    auth = build_auth(rate_limit: {enabled: true, window: 60, max: 1, custom_storage: storage})

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/passkey/generate-authenticate-options", query: "nonce=one")).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/passkey/generate-authenticate-options", query: "nonce=two")).first

    assert_equal ["127.0.0.1|/passkey/generate-authenticate-options"], storage.data.keys
  end

  def test_database_storage_writes_rate_limit_record_for_passkey_route
    auth = build_auth(rate_limit: {enabled: true, window: 60, max: 1, storage: "database"})

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/passkey/generate-authenticate-options")).first

    stored = auth.context.adapter.find_one(
      model: "rateLimit",
      where: [{field: "key", value: "127.0.0.1|/passkey/generate-authenticate-options"}]
    )
    assert_equal 1, stored.fetch("count")
    assert_kind_of Integer, stored.fetch("lastRequest")
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/passkey/generate-authenticate-options")).first
  end

  def test_secondary_storage_rate_limit_uses_upstream_shape
    storage = MemorySecondaryStorage.new
    auth = build_auth(
      secondary_storage: storage,
      rate_limit: {enabled: true, window: 60, max: 1, storage: "secondary-storage"}
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/passkey/generate-authenticate-options")).first

    key = "127.0.0.1|/passkey/generate-authenticate-options"
    stored = JSON.parse(storage.data.fetch(key))
    assert_equal ["count", "key", "lastRequest"], stored.keys.sort
    assert_equal key, stored.fetch("key")
    assert_kind_of Integer, stored.fetch("lastRequest")
    assert_equal 60, storage.ttls.fetch(key)
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/passkey/generate-authenticate-options")).first
  end

  def test_custom_rules_can_disable_one_passkey_route_while_limiting_another
    auth = build_auth(
      rate_limit: {
        enabled: true,
        window: 60,
        max: 100,
        custom_rules: {
          "/passkey/*authenticate*" => false,
          "/passkey/*register*" => {window: 60, max: 1}
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "passkey-rate-rule@example.com")

    3.times do
      assert_equal 200, auth.call(rack_env("GET", "/api/auth/passkey/generate-authenticate-options")).first
    end

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/passkey/generate-register-options", headers: {"HTTP_COOKIE" => cookie})).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/passkey/generate-register-options", headers: {"HTTP_COOKIE" => cookie})).first
  end
end

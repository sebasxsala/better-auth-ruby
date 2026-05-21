# frozen_string_literal: true

require "json"
require_relative "../../test_helper"
require_relative "../../support/stripe_helpers"

class BetterAuthPluginsStripeRateLimitTest < Minitest::Test
  include BetterAuthStripeTestHelpers

  SECRET = "phase-twelve-secret-with-enough-entropy-123"
  FakeStripeClient = BetterAuthStripeTestHelpers::FakeStripeClient

  def test_memory_rate_limiter_applies_to_stripe_webhook_route
    auth = build_rate_limited_auth(rate_limit: {enabled: true, window: 60, max: 1})

    first_status, = auth.call(rack_env("POST", "/api/auth/stripe/webhook", raw_body: "{}"))
    second_status, second_headers, second_body = auth.call(rack_env("POST", "/api/auth/stripe/webhook", raw_body: "{}"))

    assert_equal 400, first_status
    assert_equal 429, second_status
    assert_equal "60", second_headers.fetch("x-retry-after")
    assert_equal "Too many requests. Please try again later.", JSON.parse(second_body.join).fetch("message")
  end

  def test_database_rate_limiter_persists_stripe_webhook_keys
    auth = build_rate_limited_auth(rate_limit: {enabled: true, window: 60, max: 1, storage: "database"})

    first_status, = auth.call(rack_env("POST", "/api/auth/stripe/webhook", raw_body: "{}"))
    stored = auth.context.adapter.find_one(model: "rateLimit", where: [{field: "key", value: "127.0.0.1|/stripe/webhook"}])
    second_status, = auth.call(rack_env("POST", "/api/auth/stripe/webhook", raw_body: "{}"))

    assert_equal 400, first_status
    assert_equal 1, stored.fetch("count")
    assert_kind_of Integer, stored.fetch("lastRequest")
    assert_equal 429, second_status
  end

  def test_secondary_storage_rate_limiter_persists_stripe_webhook_keys_with_ttl
    storage = SecondaryStorage.new
    auth = build_rate_limited_auth(
      secondary_storage: storage,
      rate_limit: {enabled: true, window: 60, max: 1, storage: "secondary-storage"}
    )

    first_status, = auth.call(rack_env("POST", "/api/auth/stripe/webhook", raw_body: "{}"))
    stored = JSON.parse(storage.data.fetch("127.0.0.1|/stripe/webhook"))
    second_status, = auth.call(rack_env("POST", "/api/auth/stripe/webhook", raw_body: "{}"))

    assert_equal 400, first_status
    assert_equal 1, stored.fetch("count")
    assert_kind_of Integer, stored.fetch("lastRequest")
    assert_equal 60, storage.ttls.fetch("127.0.0.1|/stripe/webhook")
    assert_equal 429, second_status
  end

  private

  def build_rate_limited_auth(rate_limit:, secondary_storage: nil)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      rate_limit: rate_limit,
      secondary_storage: secondary_storage,
      plugins: [
        BetterAuth::Plugins.stripe(
          stripe_client: FakeStripeClient.new,
          stripe_webhook_secret: "whsec_test",
          subscription: {enabled: false}
        )
      ]
    )
  end

  class SecondaryStorage
    attr_reader :data, :ttls

    def initialize
      @data = {}
      @ttls = {}
    end

    def get(key)
      data[key]
    end

    def set(key, value, ttl)
      data[key] = value
      ttls[key] = ttl
    end
  end
end

# frozen_string_literal: true

require "securerandom"
require_relative "test_support"

class BetterAuthAPIKeyRedisSecondaryStorageIntegrationTest < Minitest::Test
  include APIKeyTestSupport

  SECRET = APIKeyTestSupport::SECRET

  def setup
    skip "set REDIS_INTEGRATION=1 to run real Redis-backed api-key storage tests" unless ENV["REDIS_INTEGRATION"] == "1"

    require "redis"
    require "better_auth/redis_storage"
    @redis_url = ENV.fetch("REDIS_URL", "redis://localhost:6379/15")
    @client = Redis.new(url: @redis_url)
    @client.ping
    @prefix = "better-auth-api-key-test:#{SecureRandom.hex(6)}:"
  rescue LoadError
    skip "redis or better_auth-redis-storage is not installed"
  rescue => error
    raise unless defined?(Redis::BaseConnectionError) && error.is_a?(Redis::BaseConnectionError)

    skip "Redis is not reachable at #{@redis_url}"
  end

  def teardown
    @storages&.each(&:clear)
    @client&.close if @client.respond_to?(:close)
  end

  def test_real_redis_pure_secondary_storage_api_key_lifecycle_and_ttl
    storage = isolated_storage("pure")
    auth = build_redis_auth(storage: storage, fallback_to_database: false)
    cookie = sign_up_cookie(auth, email: "redis-pure-api-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie}).fetch(:user).fetch("id")

    created = auth.api.create_api_key(
      body: {userId: user_id, name: "redis-pure", expiresIn: 86_400, rateLimitEnabled: true, rateLimitMax: 2, rateLimitTimeWindow: 60_000}
    )
    assert storage.get("api-key:by-id:#{created.fetch(:id)}")
    assert_operator redis_ttl(storage, "api-key:by-id:#{created.fetch(:id)}"), :>, 0
    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created.fetch(:id)}])

    first_verify = auth.api.verify_api_key(body: {key: created.fetch(:key)})
    second_verify = auth.api.verify_api_key(body: {key: created.fetch(:key)})
    rate_limited = auth.api.verify_api_key(body: {key: created.fetch(:key)})

    assert_equal true, first_verify.fetch(:valid)
    assert_equal true, second_verify.fetch(:valid)
    assert_equal false, rate_limited.fetch(:valid)
    assert_equal "RATE_LIMITED", rate_limited.fetch(:error).fetch(:code)

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    assert_includes listed.fetch(:apiKeys).map { |entry| entry.fetch(:id) }, created.fetch(:id)

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created.fetch(:id), name: "redis-updated"})
    assert_equal "redis-updated", updated.fetch(:name)

    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: created.fetch(:id)}))
    assert_nil storage.get("api-key:by-id:#{created.fetch(:id)}")
    assert_nil storage.get("api-key:by-ref:#{user_id}")
  end

  def test_real_redis_fallback_storage_warms_cache_and_persists_quota_updates
    storage = isolated_storage("fallback")
    auth = build_redis_auth(storage: storage, fallback_to_database: true, rate_limit: {enabled: false})
    cookie = sign_up_cookie(auth, email: "redis-fallback-api-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie}).fetch(:user).fetch("id")

    created = auth.api.create_api_key(body: {userId: user_id, name: "redis-fallback", remaining: 2})
    hashed = BetterAuth::Plugins.default_api_key_hasher(created.fetch(:key))
    storage.delete("api-key:by-id:#{created.fetch(:id)}")
    storage.delete("api-key:#{hashed}")
    storage.delete("api-key:by-ref:#{user_id}")

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created.fetch(:id)})
    assert_equal created.fetch(:id), fetched.fetch(:id)
    assert storage.get("api-key:by-id:#{created.fetch(:id)}")
    assert storage.get("api-key:#{hashed}")

    verified = auth.api.verify_api_key(body: {key: created.fetch(:key)})
    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created.fetch(:id)}])

    assert_equal true, verified.fetch(:valid)
    assert_equal 1, verified.fetch(:key).fetch(:remaining)
    assert_equal 1, stored.fetch("remaining")

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    assert_includes listed.fetch(:apiKeys).map { |entry| entry.fetch(:id) }, created.fetch(:id)
    assert storage.get("api-key:by-ref:#{user_id}")

    auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: created.fetch(:id)})
    assert_nil storage.get("api-key:by-id:#{created.fetch(:id)}")
    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created.fetch(:id)}])
  end

  private

  def isolated_storage(name)
    storage = BetterAuth::RedisStorage.new(client: @client, key_prefix: "#{@prefix}#{name}:")
    (@storages ||= []) << storage
    storage.clear
    storage
  end

  def build_redis_auth(storage:, fallback_to_database:, rate_limit: {enabled: true, time_window: 60_000, max_requests: 2})
    BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      secondary_storage: storage,
      plugins: [
        BetterAuth::Plugins.api_key(
          storage: "secondary-storage",
          fallback_to_database: fallback_to_database,
          default_key_length: 12,
          rate_limit: rate_limit
        )
      ]
    )
  end

  def redis_ttl(storage, key)
    @client.ttl("#{storage.key_prefix}#{key}")
  end
end

# frozen_string_literal: true

require "json"
require "base64"
require "securerandom"
require "stringio"
require "uri"
require "test_helper"

class RedisStorageIntegrationTest < Minitest::Test
  def setup
    skip "set REDIS_INTEGRATION=1 to run real Redis integration" unless ENV["REDIS_INTEGRATION"] == "1"

    redis_url = ENV["REDIS_URL"] || "redis://localhost:6379/15"
    require "redis"
    @client = Redis.new(url: redis_url)
    @client.ping
    @prefix_root = "better-auth-test:#{SecureRandom.hex(6)}"
    @storage = BetterAuth::RedisStorage.new(client: @client, key_prefix: "#{@prefix_root}:")
    @storage.clear
  rescue LoadError
    skip "redis gem is not available"
  rescue => error
    raise unless defined?(Redis::BaseConnectionError) && error.is_a?(Redis::BaseConnectionError)

    skip "Redis is not reachable at #{redis_url}"
  end

  def teardown
    @storage&.clear
    @client&.del("#{@prefix_root}:outside") if @client && @prefix_root
    @client&.close if @client.respond_to?(:close)
  end

  def test_real_redis_round_trip_on_get_set_delete
    @storage.set("a", "one")
    @storage.set("b", "two", 60)

    assert_equal "one", @storage.get("a")
    assert_equal "two", @storage.get("b")

    @storage.delete("a")

    assert_nil @storage.get("a")
  end

  def test_real_redis_expires_direct_ttl_values
    @storage.set("short", "one", 1)

    assert_operator @client.ttl("#{@prefix_root}:short"), :>, 0

    sleep 1.2

    assert_nil @storage.get("short")
  end

  def test_real_redis_stores_session_data_after_email_signup
    @client.set("#{@prefix_root}:outside", "outside")
    storage = isolated_storage("email-signup")
    auth = build_auth(storage, store_session_in_database: false)

    result = auth.api.sign_up_email(
      body: {
        email: "redis-false-#{SecureRandom.hex(4)}@example.com",
        password: "password123",
        name: "Redis User"
      }
    )

    assert result[:token]
    keys = storage.listKeys
    assert_equal 2, keys.length
    assert keys.any? { |key| key.start_with?("active-sessions-") }
    refute_includes keys, "#{@prefix_root}:outside"
    session_data = session_payload_from_storage(storage)
    assert session_data.fetch("user").fetch("id")
    assert session_data.fetch("session").fetch("id")
    assert_equal result[:token], session_data.fetch("session").fetch("token")
  ensure
    storage&.clear
  end

  def test_real_redis_stores_session_id_when_store_session_in_database_is_true
    storage = isolated_storage("database-session")
    auth = build_auth(storage, store_session_in_database: true)

    result = auth.api.sign_up_email(
      body: {
        email: "redis-true-#{SecureRandom.hex(4)}@example.com",
        password: "password123",
        name: "Redis User"
      }
    )

    assert result[:token]
    keys = storage.listKeys
    assert_equal 2, keys.length
    assert keys.any? { |key| key.start_with?("active-sessions-") }
    session_data = session_payload_from_storage(storage)
    assert session_data.fetch("user").fetch("id")
    assert session_data.fetch("session").fetch("id")
    assert_equal result[:token], session_data.fetch("session").fetch("token")
  ensure
    storage&.clear
  end

  def test_real_redis_stores_stateless_google_oauth_session
    storage = isolated_storage("stateless-google")
    auth = build_stateless_google_auth(storage)
    token_exchange = lambda do |_url, _form|
      {
        "accessToken" => "test-access-token",
        "refreshToken" => "test-refresh-token",
        "idToken" => fake_jwt("sub" => "google-1234567890")
      }
    end

    BetterAuth::SocialProviders::Base.stub(:post_form, token_exchange) do
      status, _headers, body = auth.api.sign_in_social(
        body: {provider: "google", callbackURL: "/callback"},
        as_response: true
      )
      sign_in_data = JSON.parse(body.join)
      state = extract_state(sign_in_data.fetch("url"))

      callback_status, callback_headers, _callback_body = auth.api.callback_oauth(
        params: {providerId: "google"},
        query: {state: state, code: "test-authorization-code"},
        as_response: true
      )

      assert_equal 200, status
      assert_equal 302, callback_status
      assert_includes callback_headers.fetch("location"), "/callback"
      keys = storage.listKeys
      assert_equal 2, keys.length
      session_data = session_payload_from_storage(storage)
      assert session_data.fetch("user").fetch("id")
      assert session_data.fetch("session").fetch("id")
      assert_equal "google-user@example.com", session_data.fetch("user").fetch("email")
    end
  ensure
    storage&.clear
  end

  def test_real_redis_google_oauth_uses_custom_authorization_endpoint
    storage = isolated_storage("custom-google-endpoint")
    custom_auth_endpoint = "http://localhost:8080/custom-oauth/authorize"
    auth = build_stateless_google_auth(storage, authorization_endpoint: custom_auth_endpoint)

    status, _headers, body = auth.api.sign_in_social(
      body: {provider: "google", callbackURL: "/dashboard"},
      as_response: true
    )
    sign_in_data = JSON.parse(body.join)
    url = sign_in_data.fetch("url")

    assert_equal 200, status
    assert_includes url, custom_auth_endpoint
    refute_includes url, "accounts.google.com"
    assert_includes url, "localhost:8080"
  ensure
    storage&.clear
  end

  def test_real_redis_rate_limiting_persists_under_secondary_storage
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: @storage,
      rate_limit: {storage: "secondary-storage", enabled: true, max: 1, window: 60},
      plugins: [
        {
          id: "redis-storage-integration",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/limited")).first

    key = @storage.list_keys.find { |entry| entry == "127.0.0.1|/limited" }
    refute_nil key
    stored = JSON.parse(@storage.get(key))
    assert_equal 1, stored.fetch("count")
    assert_operator @client.ttl("#{@prefix_root}:#{key}"), :>, 0
  end

  def test_real_redis_verification_values_get_ttl
    auth = build_auth(@storage, store_session_in_database: false)

    verification = auth.context.internal_adapter.create_verification_value(
      identifier: "verify-ttl",
      value: "secret",
      expiresAt: Time.now + 60
    )

    assert_operator @client.ttl("#{@prefix_root}:verification:verify-ttl"), :>, 0
    assert_operator @client.ttl("#{@prefix_root}:verification-id:#{verification.fetch("id")}"), :>, 0
  end

  def test_scan_count_round_trip_lists_keys
    storage = BetterAuth::RedisStorage.new(
      client: @client,
      key_prefix: "#{@prefix_root}:scan:",
      scan_count: 50
    )
    storage.clear
    storage.set("x", "1")
    storage.set("y", "2")

    assert_equal ["x", "y"], storage.list_keys.sort
  ensure
    storage&.clear
  end

  def test_real_redis_scan_count_lists_unique_many_keys_and_clear_removes_all
    storage = BetterAuth::RedisStorage.new(
      client: @client,
      key_prefix: "#{@prefix_root}:many-scan:",
      scan_count: 5
    )
    storage.clear
    300.times { |i| storage.set("k#{i}", "v") }
    @client.set("#{@prefix_root}:many-scan-outside", "outside")

    keys = storage.list_keys

    assert_equal 300, keys.length
    assert_equal keys.uniq.sort, keys.sort

    storage.clear

    assert_empty storage.list_keys
    assert_equal "outside", @client.get("#{@prefix_root}:many-scan-outside")
  ensure
    storage&.clear
    @client&.del("#{@prefix_root}:many-scan-outside") if @client && @prefix_root
  end

  def test_atomic_clear_logically_hides_previous_generation
    storage = BetterAuth::RedisStorage.new(
      client: @client,
      key_prefix: "#{@prefix_root}:atomic:",
      scan_count: 50,
      atomic_clear: true
    )
    storage.clear
    storage.set("x", "1")
    previous_generation = @client.get("#{@prefix_root}:atomic:__generation__")

    storage.clear
    @client.set("#{@prefix_root}:atomic:v#{previous_generation}:late", "stale")

    assert_nil storage.get("x")
    assert_nil storage.get("late")
    assert_nil @client.get("#{@prefix_root}:atomic:v#{previous_generation}:x")
    assert_equal [], storage.list_keys
    storage.set("x", "2")
    assert_equal "2", storage.get("x")
  ensure
    storage&.clear
  end

  def test_real_redis_hashed_verification_identifier_does_not_expose_raw_identifier
    storage = isolated_storage("hashed-verification")
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: storage,
      verification: {store_identifier: "hashed"}
    )
    raw_identifier = "sensitive-token@example.com"

    verification = auth.context.internal_adapter.create_verification_value(
      identifier: raw_identifier,
      value: "secret",
      expiresAt: Time.now + 120
    )

    keys = storage.list_keys
    refute keys.any? { |key| key.include?(raw_identifier) }
    assert_equal "secret", auth.context.internal_adapter.find_verification_value(raw_identifier).fetch("value")

    auth.context.internal_adapter.update_verification_value(verification.fetch("id"), value: "updated")
    assert_equal "updated", auth.context.internal_adapter.find_verification_value(raw_identifier).fetch("value")

    auth.context.internal_adapter.delete_verification_value(verification.fetch("id"))
    assert_nil auth.context.internal_adapter.find_verification_value(raw_identifier)
    assert_empty storage.list_keys
  ensure
    storage&.clear
  end

  private

  def isolated_storage(name)
    BetterAuth::RedisStorage.new(
      client: @client,
      key_prefix: "#{@prefix_root}:#{name}:"
    ).tap(&:clear)
  end

  def build_auth(storage, store_session_in_database:)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: storage,
      email_and_password: {enabled: true},
      session: {store_session_in_database: store_session_in_database}
    )
  end

  def build_stateless_google_auth(storage, authorization_endpoint: nil)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: nil,
      secondary_storage: storage,
      session: {
        cookie_cache: {
          enabled: true,
          max_age: 7 * 24 * 60 * 60,
          strategy: "jwe",
          refresh_cache: true
        }
      },
      account: {
        store_state_strategy: "cookie",
        store_account_cookie: true
      },
      social_providers: {
        google: BetterAuth::SocialProviders.google(
          client_id: "demo",
          client_secret: "demo-secret",
          authorization_endpoint: authorization_endpoint,
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "google-1234567890",
                email: "google-user@example.com",
                name: "Google Test User",
                image: "https://lh3.googleusercontent.com/a-/test",
                emailVerified: true
              }
            }
          }
        )
      }
    )
  end

  def extract_state(url)
    Rack::Utils.parse_query(URI.parse(url).query).fetch("state")
  end

  def session_payload_from_storage(storage)
    session_key = storage.listKeys.find { |key| !key.start_with?("active-sessions-") }
    assert session_key
    session_data_string = storage.get(session_key)
    assert session_data_string
    JSON.parse(session_data_string)
  end

  def fake_jwt(payload)
    encoded_header = Base64.urlsafe_encode64(JSON.generate({"alg" => "none"}), padding: false)
    encoded_payload = Base64.urlsafe_encode64(JSON.generate(payload), padding: false)
    "#{encoded_header}.#{encoded_payload}."
  end

  def rack_env(method, path)
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(""),
      "CONTENT_LENGTH" => "0"
    }
  end
end

# frozen_string_literal: true

require "stringio"
require "test_helper"

class RedisStorageTest < Minitest::Test
  # Real Redis coverage lives in redis_storage_integration_test.rb and is gated
  # by REDIS_INTEGRATION=1.

  def setup
    @client = FakeRedisClient.new
    @storage = BetterAuth::RedisStorage.new(client: @client)
  end

  def test_set_and_get_use_default_key_prefix
    @storage.set("session-token", "payload")

    assert_equal "payload", @storage.get("session-token")
    assert_equal "payload", @client.data.fetch("better-auth:session-token")
  end

  def test_nil_key_prefix_uses_default_prefix
    storage = BetterAuth::RedisStorage.new(client: @client, key_prefix: nil)

    storage.set("session-token", "payload")

    assert_equal "payload", @client.data.fetch("better-auth:session-token")
  end

  def test_key_prefix_can_use_upstream_camel_case_keyword
    storage = BetterAuth::RedisStorage.new(client: @client, keyPrefix: "auth:")

    storage.set("session-token", "payload")

    assert_equal "auth:", storage.key_prefix
    assert_equal "payload", @client.data.fetch("auth:session-token")
  end

  def test_conflicting_prefix_keywords_raise
    error = assert_raises(ArgumentError) do
      BetterAuth::RedisStorage.new(client: @client, key_prefix: "auth:", keyPrefix: "other:")
    end

    assert_match(/key_prefix.*keyPrefix/i, error.message)
  end

  def test_atomic_clear_scopes_keys_by_generation
    storage = BetterAuth::RedisStorage.new(client: @client, atomic_clear: true)

    storage.set("session-token", "payload")

    assert_equal "payload", storage.get("session-token")
    assert_equal "payload", @client.data.fetch("better-auth:v1:session-token")
  end

  def test_set_with_positive_ttl_uses_setex
    result = @storage.set("rate-limit", "payload", 60)

    assert_nil result
    assert_equal [["better-auth:rate-limit", 60, "payload"]], @client.setex_calls
  end

  def test_set_with_zero_or_nil_ttl_uses_plain_set
    @storage.set("without-ttl", "one", nil)
    @storage.set("zero-ttl", "two", 0)

    assert_equal [["better-auth:without-ttl", "one"], ["better-auth:zero-ttl", "two"]], @client.set_calls
  end

  def test_set_treats_string_ttl_as_seconds_when_positive
    @storage.set("string-ttl", "payload", "60")

    assert_equal [["better-auth:string-ttl", 60, "payload"]], @client.setex_calls
  end

  def test_set_falls_back_to_plain_set_for_non_numeric_or_negative_ttl
    @storage.set("bad-ttl", "payload", "abc")
    @storage.set("partial-ttl", "payload", "60abc")
    @storage.set("neg-ttl", "payload", -5)
    @storage.set("float-zero-ttl", "payload", 0.0)

    assert_equal [
      ["better-auth:bad-ttl", "payload"],
      ["better-auth:partial-ttl", "payload"],
      ["better-auth:neg-ttl", "payload"],
      ["better-auth:float-zero-ttl", "payload"]
    ], @client.set_calls
  end

  def test_set_with_float_positive_ttl_truncates_to_integer
    @storage.set("float-ttl", "payload", 1.9)

    assert_equal [["better-auth:float-ttl", 1, "payload"]], @client.setex_calls
  end

  def test_set_with_rational_ttl_uses_setex
    @storage.set("rational-ttl", "payload", Rational(241, 2))

    assert_equal [["better-auth:rational-ttl", 120, "payload"]], @client.setex_calls
  end

  def test_set_with_sub_second_numeric_ttl_falls_back_to_plain_set
    @storage.set("float-sub-second-ttl", "payload", 0.5)
    @storage.set("rational-sub-second-ttl", "payload", Rational(1, 2))

    assert_empty @client.setex_calls
    assert_equal [
      ["better-auth:float-sub-second-ttl", "payload"],
      ["better-auth:rational-sub-second-ttl", "payload"]
    ], @client.set_calls
  end

  def test_non_finite_numeric_ttl_falls_back_to_set
    @storage.set("nan-ttl", "payload", Float::NAN)
    @storage.set("infinite-ttl", "payload", Float::INFINITY)

    assert_equal [
      ["better-auth:nan-ttl", "payload"],
      ["better-auth:infinite-ttl", "payload"]
    ], @client.set_calls
  end

  def test_delete_removes_prefixed_key
    @storage.set("session-token", "payload")
    result = @storage.delete("session-token")

    assert_nil result
    refute @client.data.key?("better-auth:session-token")
  end

  def test_nil_logical_key_raises
    assert_raises(ArgumentError) { @storage.get(nil) }
    assert_raises(ArgumentError) { @storage.set(nil, "v") }
    assert_raises(ArgumentError) { @storage.delete(nil) }
  end

  def test_list_keys_returns_unprefixed_keys_for_configured_prefix
    storage = BetterAuth::RedisStorage.new(client: @client, key_prefix: "auth:")
    storage.set("a", "one")
    storage.set("nested:b", "two")
    @client.set("other:c", "three")

    assert_equal ["a", "nested:b"], storage.list_keys.sort
  end

  def test_clear_deletes_only_prefixed_keys
    @storage.set("a", "one")
    @storage.set("b", "two")
    @client.set("other:c", "three")

    result = @storage.clear

    assert_nil result
    assert_empty @storage.list_keys
    assert_equal "three", @client.get("other:c")
  end

  def test_clear_does_not_call_del_when_no_keys_match
    result = @storage.clear

    assert_nil result
    assert_empty @client.del_calls
  end

  def test_atomic_clear_hides_existing_keys_without_deleting_new_generation
    storage = BetterAuth::RedisStorage.new(client: @client, atomic_clear: true)
    storage.set("a", "one")

    result = storage.clear
    storage.set("a", "two")

    assert_nil result
    assert_equal "two", storage.get("a")
    assert_equal ["a"], storage.list_keys
    assert_nil @client.data["better-auth:v1:a"]
    assert_equal "two", @client.data.fetch("better-auth:v2:a")
    assert_equal [["better-auth:v1:a"]], @client.del_calls
  end

  def test_atomic_clear_makes_late_old_generation_writes_logically_invisible
    storage = BetterAuth::RedisStorage.new(client: @client, atomic_clear: true)
    storage.set("before", "old")

    storage.clear
    @client.set("better-auth:v1:late", "stale")

    assert_nil storage.get("late")
    assert_empty storage.list_keys
    assert_equal "stale", @client.data.fetch("better-auth:v1:late")
  end

  def test_clear_deletes_in_chunks_when_many_keys
    client = FakeRedisClient.new
    storage = BetterAuth::RedisStorage.new(client: client)
    600.times { |i| storage.set("k#{i}", "v") }

    storage.clear

    assert_operator client.del_calls.length, :>=, 2
    assert_equal 0, client.data.keys.count { |key| key.start_with?("better-auth:") }
  end

  def test_list_keys_returns_all_logical_keys
    @storage.set("first", "one")
    @storage.set("second", "two")
    @storage.set("third", "three")

    assert_equal ["first", "second", "third"].sort, @storage.list_keys.sort
  end

  def test_prefixed_storage_never_bleeds_into_unprefixed_keys
    storage = BetterAuth::RedisStorage.new(client: @client, key_prefix: "auth:")
    storage.set("session", "inside")
    @client.set("session", "outside")

    assert_equal ["session"], storage.list_keys
    assert_equal "inside", storage.get("session")
    assert_equal "outside", @client.get("session")
  end

  def test_list_keys_uses_scan_when_scan_count_is_provided
    scan_client = ScanCapableFakeRedisClient.new
    scan_client.set("better-auth:a", "one")
    scan_client.set("better-auth:b", "two")
    scan_client.set("other:c", "three")

    storage = BetterAuth::RedisStorage.new(client: scan_client, scan_count: 50)

    assert_equal ["a", "b"], storage.list_keys.sort
    assert_empty scan_client.keys_calls
    assert_equal [["0", {match: "better-auth:*", count: 50}]], scan_client.scan_calls.first(1)
  end

  def test_clear_with_scan_count_scans_all_pages_before_deleting
    scan_client = ScanCapableFakeRedisClient.new
    600.times { |i| scan_client.set("better-auth:k#{i}", "v") }
    scan_client.set("other:c", "three")

    storage = BetterAuth::RedisStorage.new(client: scan_client, scan_count: 50)

    storage.clear

    assert_empty scan_client.keys_calls
    assert_equal 0, scan_client.data.keys.count { |key| key.start_with?("better-auth:") }
    assert_equal "three", scan_client.get("other:c")
    first_del_index = scan_client.events.index { |event| event.first == :del }
    last_scan_index = scan_client.events.each_index.reverse_each.find { |index| scan_client.events[index].first == :scan }
    assert_operator first_del_index, :>, last_scan_index
  end

  def test_scan_keys_deduplicates_repeated_cursor_results
    scan_client = DuplicateScanFakeRedisClient.new
    scan_client.set("better-auth:a", "one")
    scan_client.set("better-auth:b", "two")

    storage = BetterAuth::RedisStorage.new(client: scan_client, scan_count: 50)

    assert_equal ["a", "b"], storage.list_keys
  end

  def test_atomic_clear_with_scan_count_cleans_previous_generation_with_scan
    scan_client = ScanCapableFakeRedisClient.new
    storage = BetterAuth::RedisStorage.new(client: scan_client, scan_count: 50, atomic_clear: true)
    storage.set("a", "one")
    storage.set("b", "two")

    storage.clear

    assert_empty scan_client.keys_calls
    assert_equal ["better-auth:v1:*"], scan_client.scan_calls.map { |(_cursor, options)| options.fetch(:match) }.uniq
    assert_empty scan_client.data.keys.grep(/\Abetter-auth:v1:/)
  end

  def test_scan_count_must_be_nil_or_positive_integer
    [0, -1, "100"].each do |scan_count|
      error = assert_raises(ArgumentError) do
        BetterAuth::RedisStorage.new(client: FakeRedisClient.new, scan_count: scan_count)
      end
      assert_match(/scan_count/i, error.message)
    end
  end

  def test_scan_count_accepts_positive_integer
    storage = BetterAuth::RedisStorage.new(client: FakeRedisClient.new, scan_count: 100)

    assert_equal 100, storage.scan_count
  end

  def test_default_scan_count_uses_scan_default
    storage = BetterAuth::RedisStorage.new(client: FakeRedisClient.new)

    assert_equal BetterAuth::RedisStorage::SCAN_DEFAULT_COUNT, storage.scan_count
  end

  def test_default_list_keys_uses_scan_not_keys
    client = FakeRedisClient.new
    storage = BetterAuth::RedisStorage.new(client: client)

    storage.set("a", "1")
    storage.list_keys

    assert_empty client.keys_calls
    assert_equal [["0", {match: "better-auth:*", count: BetterAuth::RedisStorage::SCAN_DEFAULT_COUNT}]], client.scan_calls.first(1)
  end

  def test_scan_count_nil_uses_keys_not_scan
    client = FakeRedisClient.new
    storage = BetterAuth::RedisStorage.new(client: client, scan_count: nil)

    storage.set("a", "1")
    storage.list_keys

    assert_equal ["better-auth:*"], client.keys_calls
  end

  def test_key_prefix_glob_metacharacters_are_escaped_for_scan
    client = FakeRedisClient.new
    storage = BetterAuth::RedisStorage.new(client: client, key_prefix: 'auth*?[x]\:')
    storage.set("inside", "one")
    client.set("authABCx\\:outside", "two")

    assert_equal ["inside"], storage.list_keys
    assert_equal 'auth\*\?\[x\]\\\\:*', client.scan_calls.last.fetch(1).fetch(:match)
  end

  def test_key_prefix_glob_metacharacters_are_escaped_for_legacy_keys
    client = FakeRedisClient.new
    storage = BetterAuth::RedisStorage.new(client: client, key_prefix: 'auth*?[x]\:', scan_count: nil)
    storage.set("inside", "one")
    client.set("authABCx\\:outside", "two")

    assert_equal ["inside"], storage.list_keys
    assert_equal ['auth\*\?\[x\]\\\\:*'], client.keys_calls
  end

  def test_build_returns_storage_instance
    storage = BetterAuth::RedisStorage.build(client: @client)

    assert_instance_of BetterAuth::RedisStorage, storage
  end

  def test_build_forwards_key_prefix_and_scan_count
    storage = BetterAuth::RedisStorage.build(client: @client, keyPrefix: "auth:", scan_count: 25)

    assert_equal "auth:", storage.key_prefix
    assert_equal 25, storage.scan_count
  end

  def test_build_forwards_atomic_clear
    storage = BetterAuth::RedisStorage.build(client: @client, atomic_clear: true)

    assert_equal true, storage.atomic_clear
  end

  def test_module_level_redis_storage_builder_returns_storage_instance
    storage = BetterAuth.redis_storage(client: @client, key_prefix: "auth:")

    assert_instance_of BetterAuth::RedisStorage, storage
    assert_equal "auth:", storage.key_prefix

    storage.set("k", "v")
    assert_equal "v", @client.data.fetch("auth:k")
  end

  def test_module_level_redis_storage_builder_forwards_key_prefix_and_scan_count
    storage = BetterAuth.redis_storage(client: @client, keyPrefix: "auth:", scan_count: 25)

    assert_equal "auth:", storage.key_prefix
    assert_equal 25, storage.scan_count
  end

  def test_module_level_redis_storage_builder_forwards_atomic_clear
    storage = BetterAuth.redis_storage(client: @client, atomic_clear: true)

    assert_equal true, storage.atomic_clear
  end

  def test_module_level_camel_case_redis_storage_builder_returns_storage_instance
    storage = BetterAuth.redisStorage(client: @client, keyPrefix: "auth:", scan_count: 25)

    assert_instance_of BetterAuth::RedisStorage, storage
    assert_equal "auth:", storage.key_prefix
    assert_equal 25, storage.scan_count
  end

  def test_camel_case_redis_storage_class_method_alias_matches_upstream_name
    storage = BetterAuth::RedisStorage.redisStorage(client: @client)

    assert_instance_of BetterAuth::RedisStorage, storage
  end

  def test_camel_case_redis_storage_forwards_key_prefix_and_scan_count
    storage = BetterAuth::RedisStorage.redisStorage(client: @client, keyPrefix: "auth:", scan_count: 25)

    assert_equal "auth:", storage.key_prefix
    assert_equal 25, storage.scan_count
  end

  def test_camel_case_redis_storage_forwards_atomic_clear
    storage = BetterAuth::RedisStorage.redisStorage(client: @client, atomic_clear: true)

    assert_equal true, storage.atomic_clear
  end

  def test_camel_case_list_keys_alias_matches_upstream_name
    @storage.set("a", "one")

    assert_equal ["a"], @storage.listKeys
  end

  def test_secondary_storage_can_back_session_payload_when_session_not_in_database
    storage = BetterAuth::RedisStorage.new(client: FakeRedisClient.new)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: storage,
      email_and_password: {enabled: true},
      session: {store_session_in_database: false}
    )

    result = auth.api.sign_up_email(
      body: {email: "session-fake@example.com", password: "password123", name: "Fake User"}
    )

    assert result[:token]
    assert storage.get("active-sessions-#{result[:user]["id"]}")
    session_keys = storage.list_keys.reject { |key| key.start_with?("active-sessions-") }
    assert_equal 1, session_keys.length
    parsed = JSON.parse(storage.get(session_keys.first))
    assert_equal result[:token], parsed.fetch("session").fetch("token")
  end

  def test_secondary_storage_can_back_rate_limiting
    storage = BetterAuth::RedisStorage.new(client: FakeRedisClient.new)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: storage,
      rate_limit: {storage: "secondary-storage", enabled: true, max: 1, window: 60},
      plugins: [
        {
          id: "redis-storage-test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/limited")).first

    rate_limit_keys = storage.list_keys.select { |key| key == "127.0.0.1|/limited" }
    refute_empty rate_limit_keys
    parsed = JSON.parse(storage.get(rate_limit_keys.first))
    assert_equal ["count", "key", "lastRequest"], parsed.keys.sort
  end

  def test_secondary_storage_can_back_verification_values
    storage = BetterAuth::RedisStorage.new(client: FakeRedisClient.new)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: storage,
      email_and_password: {enabled: true},
      session: {store_session_in_database: false}
    )

    verification = auth.context.internal_adapter.create_verification_value(
      identifier: "verify-redis",
      value: "secret",
      expiresAt: Time.now + 120
    )

    assert verification["id"]
    assert storage.get("verification:verify-redis")
    assert storage.get("verification-id:#{verification["id"]}")
    assert_equal "secret", auth.context.internal_adapter.find_verification_value("verify-redis")["value"]
  end

  def test_redis_command_errors_are_not_rescued
    assert_raises(ExpectedRedisError) { BetterAuth::RedisStorage.new(client: RaisingRedisClient.new(:get)).get("key") }
    assert_raises(ExpectedRedisError) { BetterAuth::RedisStorage.new(client: RaisingRedisClient.new(:set)).set("key", "value") }
    assert_raises(ExpectedRedisError) { BetterAuth::RedisStorage.new(client: RaisingRedisClient.new(:setex)).set("key", "value", 60) }
    assert_raises(ExpectedRedisError) { BetterAuth::RedisStorage.new(client: RaisingRedisClient.new(:del)).delete("key") }
    assert_raises(ExpectedRedisError) { BetterAuth::RedisStorage.new(client: RaisingRedisClient.new(:keys), scan_count: nil).list_keys }
    assert_raises(ExpectedRedisError) { BetterAuth::RedisStorage.new(client: RaisingRedisClient.new(:scan)).list_keys }
    assert_raises(ExpectedRedisError) { BetterAuth::RedisStorage.new(client: RaisingRedisClient.new(:incr), atomic_clear: true).clear }
  end

  private

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

  class ExpectedRedisError < StandardError; end

  class FakeRedisClient
    attr_reader :data, :set_calls, :setex_calls, :del_calls, :keys_calls, :incr_calls, :scan_calls

    def initialize
      @data = {}
      @set_calls = []
      @setex_calls = []
      @del_calls = []
      @keys_calls = []
      @incr_calls = []
      @scan_calls = []
    end

    def get(key)
      data[key]
    end

    def set(key, value)
      set_calls << [key, value]
      data[key] = value
    end

    def setex(key, ttl, value)
      setex_calls << [key, ttl, value]
      data[key] = value
    end

    def del(*keys)
      del_calls << keys
      keys.each { |key| data.delete(key) }
    end

    def incr(key)
      incr_calls << key
      data[key] = data.fetch(key, 0).to_i + 1
    end

    def keys(pattern)
      keys_calls << pattern
      data.keys.select { |key| redis_glob_match?(pattern, key) }
    end

    def scan(cursor, match:, count:)
      scan_calls << [cursor, {match: match, count: count}]
      matching = data.keys.select { |key| redis_glob_match?(match, key) }
      midpoint = (matching.length / 2.0).ceil
      if cursor == "0" && matching.length > midpoint
        ["1", matching.first(midpoint)]
      else
        ["0", matching.drop((cursor == "0") ? 0 : midpoint)]
      end
    end

    private

    def redis_glob_match?(pattern, key)
      regex = +"\\A"
      index = 0
      while index < pattern.length
        character = pattern[index]
        if character == "\\"
          index += 1
          regex << Regexp.escape(pattern[index] || "\\")
        elsif character == "*"
          regex << ".*"
        elsif character == "?"
          regex << "."
        elsif character == "["
          closing = pattern.index("]", index + 1)
          if closing
            regex << pattern[index..closing]
            index = closing
          else
            regex << Regexp.escape(character)
          end
        else
          regex << Regexp.escape(character)
        end
        index += 1
      end
      regex << "\\z"
      Regexp.new(regex).match?(key)
    end
  end

  class ScanCapableFakeRedisClient < FakeRedisClient
    attr_reader :scan_calls, :events

    def initialize
      super
      @scan_calls = []
      @events = []
      @scan_snapshot = []
    end

    def del(*keys)
      events << [:del, keys]
      super
    end

    def scan(cursor, match:, count:)
      scan_calls << [cursor, {match: match, count: count}]
      events << [:scan, cursor]
      @scan_snapshot = keys_without_tracking(match) if cursor == "0"
      matching = @scan_snapshot
      midpoint = (matching.length / 2.0).ceil
      if cursor == "0" && matching.length > midpoint
        ["1", matching.first(midpoint)]
      else
        ["0", matching.drop((cursor == "0") ? 0 : midpoint)]
      end
    end

    private

    def keys_without_tracking(pattern)
      data.keys.select { |key| redis_glob_match?(pattern, key) }
    end
  end

  class DuplicateScanFakeRedisClient < ScanCapableFakeRedisClient
    def scan(cursor, match:, count:)
      scan_calls << [cursor, {match: match, count: count}]
      events << [:scan, cursor]
      case cursor
      when "0"
        ["1", ["better-auth:a", "better-auth:b"]]
      else
        ["0", ["better-auth:a"]]
      end
    end
  end

  class RaisingRedisClient
    def initialize(failing_command)
      @failing_command = failing_command
    end

    def get(_key)
      raise ExpectedRedisError if @failing_command == :get

      nil
    end

    def set(_key, _value)
      raise ExpectedRedisError if @failing_command == :set
    end

    def setex(_key, _ttl, _value)
      raise ExpectedRedisError if @failing_command == :setex
    end

    def del(*_keys)
      raise ExpectedRedisError if @failing_command == :del
    end

    def keys(_pattern)
      raise ExpectedRedisError if @failing_command == :keys

      []
    end

    def scan(_cursor, match:, count:)
      raise ExpectedRedisError if @failing_command == :scan

      ["0", []]
    end

    def incr(_key)
      raise ExpectedRedisError if @failing_command == :incr

      1
    end
  end
end

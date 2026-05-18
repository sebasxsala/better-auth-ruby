# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthPluginsAPIKeyTest < Minitest::Test
  SECRET = "phase-nine-api-key-secret-with-enough-entropy"

  def test_public_hasher_and_schema_match_upstream_package_contract
    plugin = BetterAuth::Plugins.api_key

    assert_equal BetterAuth::Crypto.sha256("api-key-value", encoding: :base64url), BetterAuth::Plugins.default_api_key_hasher("api-key-value")
    refute plugin.schema.fetch(:apikey).fetch(:fields).key?(:userId)
  end

  def test_plugin_exposes_package_version_like_upstream
    plugin = BetterAuth::Plugins.api_key

    assert_equal BetterAuth::APIKey::VERSION, plugin.version
  end

  def test_create_verify_get_list_update_and_delete_api_key
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "api-key@example.com")

    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(
      body: {userId: user_id, name: "primary", prefix: "ba_", metadata: {plan: "pro"}, permissions: {repo: ["read"]}}
    )

    assert_match(/\Aba_[A-Za-z]+\z/, created[:key])
    assert_equal "ba_", created[:prefix]
    assert_equal "primary", created[:name]
    assert_equal({"plan" => "pro"}, created[:metadata])

    verified = auth.api.verify_api_key(body: {key: created[:key], permissions: {repo: ["read"]}})
    assert_equal true, verified[:valid]
    assert_equal created[:id], verified[:key][:id]
    assert_nil verified[:error]
    refute verified[:key].key?("key")

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    assert_equal "primary", fetched[:name]

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    assert_equal [created[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] || entry["id"] }
    assert_equal 1, listed.fetch(:total)

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], name: "renamed", enabled: false})
    assert_equal "renamed", updated[:name]
    assert_equal false, updated[:enabled]

    disabled = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal false, disabled[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_DISABLED"], disabled[:error][:message]
    assert_nil disabled[:key]

    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id]}))
    assert_raises(BetterAuth::APIError) { auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]}) }
  end

  def test_expiration_remaining_refill_and_rate_limit
    auth = build_auth(rate_limit: {enabled: true, time_window: 60_000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "limits@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_SMALL"], assert_raises(BetterAuth::APIError) {
      auth.api.create_api_key(body: {userId: user_id, expiresIn: 60 * 60 * 12})
    }.message

    expired = auth.api.create_api_key(body: {userId: user_id})
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: expired[:id]}], update: {expiresAt: Time.now - 10})
    expired_result = auth.api.verify_api_key(body: {key: expired[:key]})
    assert_equal false, expired_result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_EXPIRED"], expired_result[:error][:message]

    limited = auth.api.create_api_key(body: {userId: user_id, remaining: 1})
    assert_equal true, auth.api.verify_api_key(body: {key: limited[:key]})[:valid]
    usage_exceeded = auth.api.verify_api_key(body: {key: limited[:key]})
    assert_equal false, usage_exceeded[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["USAGE_EXCEEDED"], usage_exceeded[:error][:message]

    rate_limited = auth.api.create_api_key(body: {userId: user_id, rateLimitEnabled: true, rateLimitMax: 1, rateLimitTimeWindow: 60_000})
    assert_equal true, auth.api.verify_api_key(body: {key: rate_limited[:key]})[:valid]
    rate_error = auth.api.verify_api_key(body: {key: rate_limited[:key]})
    assert_equal false, rate_error[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["RATE_LIMIT_EXCEEDED"], rate_error[:error][:message]

    refill = auth.api.create_api_key(body: {userId: user_id, remaining: 0, refillAmount: 2, refillInterval: 1})
    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: refill[:id]}])
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: stored["id"]}], update: {lastRequest: Time.now - 10, lastRefillAt: Time.now - 10})
    assert_equal true, auth.api.verify_api_key(body: {key: refill[:key]})[:valid]
  end

  def test_secondary_storage_and_api_key_session
    storage = MemoryStorage.new
    auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      fallback_to_database: true,
      enable_session_for_api_keys: true,
      session: {store_session_in_database: true}
    )
    cookie = sign_up_cookie(auth, email: "storage-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "storage"})
    second = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "storage-two"})
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    assert storage.keys.any? { |key| key.include?(created[:id]) }
    assert_nil storage.get("api-key:by-ref:#{user_id}")
    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    assert_equal [created[:id], second[:id]].sort, listed.fetch(:apiKeys).map { |entry| entry[:id] }.sort

    session = auth.api.get_session(headers: {"x-api-key" => created[:key]})

    assert_equal "storage-key@example.com", session[:user]["email"]
    assert_equal created[:id], session[:session]["id"]
    refute session[:session].key?("token")
    assert_equal BetterAuth::Plugins.default_api_key_hasher(created[:key]), session[:session]["tokenFingerprint"]

    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id]}))
    assert_nil storage.get("api-key:by-ref:#{user_id}")
  end

  def test_api_key_session_respects_disabled_ip_tracking
    storage = MemoryStorage.new
    auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      fallback_to_database: true,
      enable_session_for_api_keys: true,
      session: {store_session_in_database: true},
      advanced: {ip_address: {disable_ip_tracking: true}}
    )
    cookie = sign_up_cookie(auth, email: "ip-disabled-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "storage"})

    session = auth.api.get_session(headers: {"x-api-key" => created[:key], "x-forwarded-for" => "203.0.113.10"})

    assert_nil session[:session]["ipAddress"]
  end

  def test_api_key_session_is_not_created_when_disabled
    auth = build_auth(default_key_length: 12, enable_session_for_api_keys: false)
    cookie = sign_up_cookie(auth, email: "session-disabled-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    assert_nil auth.api.get_session(headers: {"x-api-key" => created[:key]})
  end

  def test_api_key_session_validation_statuses_match_upstream
    auth = build_auth(default_key_length: 12, enable_session_for_api_keys: true, rate_limit: {enabled: false})
    cookie = sign_up_cookie(auth, email: "session-status-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    disabled = auth.api.create_api_key(body: {userId: user_id})
    auth.api.update_api_key(body: {userId: user_id, keyId: disabled[:id], enabled: false})
    disabled_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_session(headers: {"x-api-key" => disabled[:key]})
    end
    assert_equal "UNAUTHORIZED", disabled_error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_DISABLED"], disabled_error.message

    expired = auth.api.create_api_key(body: {userId: user_id})
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: expired[:id]}], update: {expiresAt: Time.now - 10})
    expired_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_session(headers: {"x-api-key" => expired[:key]})
    end
    assert_equal "UNAUTHORIZED", expired_error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_EXPIRED"], expired_error.message

    limited = auth.api.create_api_key(body: {userId: user_id, remaining: 1})
    assert auth.api.get_session(headers: {"x-api-key" => limited[:key]})
    usage_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_session(headers: {"x-api-key" => limited[:key]})
    end
    assert_equal "TOO_MANY_REQUESTS", usage_error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["USAGE_EXCEEDED"], usage_error.message
  end

  def test_secondary_storage_reads_legacy_key_layout_but_writes_new_layout
    storage = MemoryStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "legacy-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    hashed = BetterAuth::Plugins.default_api_key_hasher(created[:key])
    legacy_payload = storage.values.fetch("api-key:by-id:#{created[:id]}")

    storage.values["api-key:key:#{hashed}"] = legacy_payload
    storage.values["api-key:id:#{created[:id]}"] = legacy_payload
    storage.values["api-key:user:#{user_id}"] = JSON.generate([created[:id]])
    storage.values.delete("api-key:#{hashed}")
    storage.values.delete("api-key:by-id:#{created[:id]}")
    storage.values.delete("api-key:by-ref:#{user_id}")

    result = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal true, result[:valid], "expected legacy api-key:key:* read fallback to validate"

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    assert_equal created[:id], fetched[:id], "expected legacy api-key:id:* read fallback to resolve"

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    assert_equal [created[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] },
      "expected legacy api-key:user:* ref list fallback to populate listing"
  end

  def test_secondary_storage_write_set_does_not_serialize_independent_keys
    storage = OrderTrackingStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "concurrency-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    hash_writes = storage.write_groups.last
    hashed_key = BetterAuth::Plugins.default_api_key_hasher(created[:key])

    assert_includes hash_writes, "api-key:#{hashed_key}", "expected per-hash write in last batch"
    assert_includes hash_writes, "api-key:by-id:#{created[:id]}", "expected per-id write in last batch"
    assert_includes hash_writes, "api-key:by-ref:#{auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]}",
      "expected ref-list write in same batch as hash and id writes (1.6.6 parity)"
  end

  def test_secondary_storage_fallback_invalidates_and_rebuilds_reference_list
    storage = MemoryStorage.new
    auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      fallback_to_database: true,
      default_key_length: 12
    )
    cookie = sign_up_cookie(auth, email: "fallback-ref-list-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    created = auth.api.create_api_key(body: {userId: user_id})

    assert_nil storage.get("api-key:by-ref:#{user_id}")

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})

    assert_equal [created[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] }
    assert_equal [created[:id]], JSON.parse(storage.get("api-key:by-ref:#{user_id}"))
  end

  def test_secondary_storage_fallback_get_warms_cache_from_database
    storage = MemoryStorage.new
    auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      fallback_to_database: true,
      default_key_length: 12
    )
    cookie = sign_up_cookie(auth, email: "fallback-get-warm-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "warm"})

    storage.clear
    assert_nil storage.get("api-key:by-id:#{created[:id]}")

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})

    assert_equal created[:id], fetched[:id]
    assert storage.get("api-key:by-id:#{created[:id]}")
    assert storage.get("api-key:#{auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])["key"]}")
  end

  def test_secondary_storage_pure_mode_crud_ttl_metadata_limits_and_custom_storage
    storage = MemoryStorage.new
    auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      enable_metadata: true,
      default_key_length: 12
    )
    cookie = sign_up_cookie(auth, email: "pure-storage-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    created = auth.api.create_api_key(
      body: {
        userId: user_id,
        name: "pure",
        expiresIn: 60 * 60 * 24 + 1,
        metadata: {plan: "premium"},
        rateLimitEnabled: true,
        rateLimitMax: 2,
        rateLimitTimeWindow: 60_000
      }
    )

    assert storage.get("api-key:by-id:#{created[:id]}")
    assert_equal [created[:id]], JSON.parse(storage.get("api-key:by-ref:#{user_id}"))
    assert storage.ttls.fetch("api-key:by-id:#{created[:id]}").positive?

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    first_verify = auth.api.verify_api_key(body: {key: created[:key]})
    second_verify = auth.api.verify_api_key(body: {key: created[:key]})
    rate_limited = auth.api.verify_api_key(body: {key: created[:key]})
    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], name: "updated-pure"})
    deleted = auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id]})

    assert_equal({"plan" => "premium"}, fetched[:metadata])
    assert_includes listed[:apiKeys].map { |entry| entry[:id] }, created[:id]
    assert_equal true, first_verify[:valid]
    assert_equal true, second_verify[:valid]
    assert_equal false, rate_limited[:valid]
    assert_equal "RATE_LIMITED", rate_limited[:error][:code]
    assert_equal "updated-pure", updated[:name]
    assert_equal({success: true}, deleted)
    assert_nil storage.get("api-key:by-id:#{created[:id]}")

    quota_key = auth.api.create_api_key(body: {userId: user_id, remaining: 2, rateLimitEnabled: false})
    quota_result = auth.api.verify_api_key(body: {key: quota_key[:key]})
    assert_equal true, quota_result[:valid]
    assert_equal 1, quota_result[:key][:remaining]

    global_storage = MemoryStorage.new
    custom_storage = MemoryStorage.new
    custom_auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: global_storage,
      custom_storage: custom_storage,
      default_key_length: 12
    )
    custom_cookie = sign_up_cookie(custom_auth, email: "custom-storage-key@example.com")
    custom_key = custom_auth.api.create_api_key(headers: {"cookie" => custom_cookie}, body: {})

    assert custom_storage.get("api-key:by-id:#{custom_key[:id]}")
    assert_nil global_storage.get("api-key:by-id:#{custom_key[:id]}")
    custom_auth.api.get_api_key(headers: {"cookie" => custom_cookie}, query: {id: custom_key[:id]})
    custom_auth.api.delete_api_key(headers: {"cookie" => custom_cookie}, body: {keyId: custom_key[:id]})
    assert custom_storage.get_calls.any? { |key| key == "api-key:by-id:#{custom_key[:id]}" }
    assert custom_storage.delete_calls.any? { |key| key == "api-key:by-id:#{custom_key[:id]}" }
  end

  def test_validation_errors_match_upstream
    auth = build_auth(require_name: true)
    cookie = sign_up_cookie(auth, email: "validation-key@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["NAME_REQUIRED"], error.message

    client_server_only = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "bad", userId: "someone-else"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"], client_server_only.message
  end

  def test_create_rejects_server_only_properties_from_authenticated_client
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "client-server-only-key@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {permissions: {repo: ["read"]}})
    end

    assert_equal "BAD_REQUEST", error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"], error.message
  end

  def test_create_allows_nil_metadata_and_remaining_from_authenticated_client
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "client-nil-fields-key@example.com")

    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {metadata: nil, remaining: nil})

    assert_nil created[:metadata]
    assert_nil created[:remaining]
  end

  def test_create_respects_nil_expiration_and_refill_without_remaining
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "create-nil-expiration-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    no_expiration = auth.api.create_api_key(body: {userId: user_id, expiresIn: nil})
    refill = auth.api.create_api_key(body: {userId: user_id, refillAmount: 10, refillInterval: 1000})

    assert_nil no_expiration[:expiresAt]
    assert_nil refill[:remaining]
    assert_equal 10, refill[:refillAmount]
    assert_equal 1000, refill[:refillInterval]
  end

  def test_create_defaults_match_upstream_record_shape
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "create-defaults-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    created = auth.api.create_api_key(body: {userId: user_id})
    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])

    assert_nil created[:lastRefillAt]
    assert_nil stored["lastRefillAt"]
    refute created.key?(:userId)
    refute stored.key?("userId")
    assert_match(/\A[A-Za-z]{12}\z/, created[:key])
  end

  def test_create_rate_limit_hashing_start_and_metadata_options_match_upstream
    rate_auth = build_auth(default_key_length: 12, rate_limit: {enabled: false, time_window: 1000, max_requests: 10})
    cookie = sign_up_cookie(rate_auth, email: "create-options-key@example.com")
    user_id = rate_auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    default_rate = rate_auth.api.create_api_key(body: {userId: user_id})
    disabled_rate = rate_auth.api.create_api_key(body: {userId: user_id, rateLimitEnabled: false})

    assert_equal false, default_rate[:rateLimitEnabled]
    assert_equal 1000, default_rate[:rateLimitTimeWindow]
    assert_equal 10, default_rate[:rateLimitMax]
    assert_equal false, disabled_rate[:rateLimitEnabled]

    raw_auth = build_auth(default_key_length: 12, disable_key_hashing: true)
    raw_cookie = sign_up_cookie(raw_auth, email: "raw-key@example.com")
    raw_key = raw_auth.api.create_api_key(headers: {"cookie" => raw_cookie}, body: {})
    raw_stored = raw_auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: raw_key[:id]}])
    assert_equal raw_key[:key], raw_stored["key"]
    assert_equal true, raw_auth.api.verify_api_key(body: {key: raw_key[:key]})[:valid]

    hidden_start_auth = build_auth(default_key_length: 12, starting_characters_config: {should_store: false})
    hidden_cookie = sign_up_cookie(hidden_start_auth, email: "hidden-start-key@example.com")
    assert_nil hidden_start_auth.api.create_api_key(headers: {"cookie" => hidden_cookie}, body: {})[:start]

    custom_start_auth = build_auth(default_key_length: 12, starting_characters_config: {should_store: true, characters_length: 3})
    custom_cookie = sign_up_cookie(custom_start_auth, email: "custom-start-key@example.com")
    custom_start = custom_start_auth.api.create_api_key(headers: {"cookie" => custom_cookie}, body: {})
    assert_equal custom_start[:key][0, 3], custom_start[:start]

    metadata_auth = build_auth(default_key_length: 12, enable_metadata: false)
    metadata_cookie = sign_up_cookie(metadata_auth, email: "metadata-disabled-create-key@example.com")
    metadata_error = assert_raises(BetterAuth::APIError) do
      metadata_auth.api.create_api_key(headers: {"cookie" => metadata_cookie}, body: {metadata: {test: "test-123"}})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["METADATA_DISABLED"], metadata_error.message
  end

  def test_create_rejects_upstream_server_only_fields_from_authenticated_client
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "client-server-only-fields-key@example.com")

    %i[refillAmount refillInterval rateLimitMax rateLimitTimeWindow].each do |field|
      error = assert_raises(BetterAuth::APIError) do
        auth.api.create_api_key(headers: {"cookie" => cookie}, body: {field => 10})
      end
      assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"], error.message
    end
  end

  def test_create_validates_name_prefix_expiration_refill_and_metadata_like_upstream
    auth = build_auth(default_key_length: 12, enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "create-validation-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    name_error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "test-api-key-that-is-longer-than-the-allowed-maximum"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_NAME_LENGTH"], name_error.message

    prefix_error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {prefix: "bad prefix"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_PREFIX_LENGTH"], prefix_error.message

    max_expiration_error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id, expiresIn: 60 * 60 * 24 * 365 * 10})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_LARGE"], max_expiration_error.message

    invalid_metadata = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {metadata: "invalid"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_METADATA_TYPE"], invalid_metadata.message

    interval_without_amount = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id, refillInterval: 1000})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["REFILL_INTERVAL_AND_AMOUNT_REQUIRED"], interval_without_amount.message

    amount_without_interval = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id, refillAmount: 10})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["REFILL_AMOUNT_AND_INTERVAL_REQUIRED"], amount_without_interval.message

    valid_metadata = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {metadata: {test: "test"}})
    assert_equal({"test" => "test"}, valid_metadata[:metadata])

    zero_remaining_refill = auth.api.create_api_key(body: {userId: user_id, remaining: 0, refillAmount: 10, refillInterval: 1000})
    assert_equal 0, zero_remaining_refill[:remaining]
    assert_equal 10, zero_remaining_refill[:refillAmount]
  end

  def test_multiple_configurations_default_prefix_and_config_filters
    auth = build_auth([
      {config_id: "public-api", default_prefix: "pub_", default_key_length: 12},
      {config_id: "internal-api", default_prefix: "int_", default_key_length: 12},
      {config_id: "default", default_prefix: "def_", default_key_length: 12}
    ])
    cookie = sign_up_cookie(auth, email: "multi-config-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    public_key = auth.api.create_api_key(body: {configId: "public-api", userId: user_id})
    internal_key = auth.api.create_api_key(body: {configId: "internal-api", userId: user_id})
    default_key = auth.api.create_api_key(body: {userId: user_id})

    assert_equal "public-api", public_key[:configId]
    assert_equal "pub_", public_key[:prefix]
    assert_match(/\Apub_[A-Za-z]+\z/, public_key[:key])
    assert_equal user_id, public_key[:referenceId]
    assert_equal "internal-api", internal_key[:configId]
    assert_equal "int_", internal_key[:prefix]
    assert_equal "default", default_key[:configId]
    assert_equal "def_", default_key[:prefix]

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {configId: "public-api"})
    assert_equal [public_key[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] }
    assert_equal 1, listed.fetch(:total)

    verified = auth.api.verify_api_key(body: {configId: "internal-api", key: internal_key[:key]})
    assert_equal true, verified[:valid]
    assert_equal "internal-api", verified[:key][:configId]
  end

  def test_multiple_configurations_resolve_correct_config_for_crud
    auth = build_auth([
      {config_id: "public-api", default_prefix: "pub_", default_key_length: 12, rate_limit: {enabled: true, max_requests: 100, time_window: 60_000}},
      {config_id: "internal-api", default_prefix: "int_", default_key_length: 12, rate_limit: {enabled: true, max_requests: 1000, time_window: 60_000}},
      {config_id: "default", default_prefix: "def_", default_key_length: 12}
    ])
    cookie = sign_up_cookie(auth, email: "multi-crud-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    public_key = auth.api.create_api_key(body: {configId: "public-api", userId: user_id, name: "public"})
    internal_key = auth.api.create_api_key(body: {configId: "internal-api", userId: user_id, name: "internal"})

    assert_equal 100, public_key[:rateLimitMax]
    assert_equal 1000, internal_key[:rateLimitMax]
    assert_equal 100, auth.api.verify_api_key(body: {key: public_key[:key], configId: "public-api"})[:key][:rateLimitMax]
    assert_equal "int_", auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: internal_key[:id], configId: "internal-api"})[:prefix]

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: public_key[:id], configId: "public-api", name: "updated-public"})
    assert_equal "public-api", updated[:configId]
    assert_equal "updated-public", updated[:name]

    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: internal_key[:id], configId: "internal-api"}))
    assert_raises(BetterAuth::APIError) do
      auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: internal_key[:id], configId: "internal-api"})
    end
  end

  def test_multiple_configuration_validation
    assert_raises(BetterAuth::Error) do
      BetterAuth::Plugins.api_key([{config_id: "duplicate"}, {config_id: "duplicate"}])
    end

    assert_raises(BetterAuth::Error) do
      BetterAuth::Plugins.api_key([{config_id: "valid"}, {}])
    end
  end

  def test_list_sort_accepts_camel_case_and_snake_case_keys
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "sort-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    first = auth.api.create_api_key(body: {userId: user_id, name: "alpha"})
    sleep 0.01
    second = auth.api.create_api_key(body: {userId: user_id, name: "beta"})

    asc_camel = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {sortBy: "createdAt", sortDirection: "asc"})
    asc_snake = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {sortBy: "created_at", sortDirection: "asc"})

    assert_equal [first[:id], second[:id]], asc_camel.fetch(:apiKeys).map { |entry| entry[:id] }
    assert_equal asc_camel.fetch(:apiKeys).map { |entry| entry[:id] }, asc_snake.fetch(:apiKeys).map { |entry| entry[:id] }
  end

  def test_list_paginates_sorts_and_returns_upstream_shape
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "list-shape-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.api.create_api_key(body: {userId: user_id, name: "zulu"})
    auth.api.create_api_key(body: {userId: user_id, name: "alpha"})
    auth.api.create_api_key(body: {userId: user_id, name: "mike"})

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {limit: 2, offset: 1, sortBy: "name", sortDirection: "asc"})

    assert_equal %w[mike zulu], listed.fetch(:apiKeys).map { |entry| entry[:name] }
    assert_equal 3, listed.fetch(:total)
    assert_equal 2, listed.fetch(:limit)
    assert_equal 1, listed.fetch(:offset)
  end

  def test_list_rejects_invalid_pagination_query
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "invalid-list-query-key@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {limit: -1})
    end

    assert_equal "BAD_REQUEST", error.status
  end

  def test_verify_invalid_key_returns_error_payload
    auth = build_auth(default_key_length: 12)

    result = auth.api.verify_api_key(body: {key: "missing-key"})

    assert_equal false, result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"], result[:error][:message]
    assert_equal "INVALID_API_KEY", result[:error][:code]
    assert_nil result[:key]
  end

  def test_verify_requires_key_in_body_and_does_not_fallback_to_headers
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "verify-header-fallback-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    result = auth.api.verify_api_key(headers: {"x-api-key" => created[:key]}, body: {})

    assert_equal false, result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"], result[:error][:message]
    assert_equal "INVALID_API_KEY", result[:error][:code]
    assert_nil result[:key]
  end

  def test_verify_runs_custom_validator_before_database_validation
    auth = build_auth(default_key_length: 12, custom_api_key_validator: ->(_options) { false })
    cookie = sign_up_cookie(auth, email: "validator-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal false, result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"], result[:error][:message]
    assert_equal "KEY_NOT_FOUND", result[:error][:code]
    assert_nil result[:key]
  end

  def test_verify_permission_failures_match_upstream_error_code
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "permission-failure-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, permissions: {repo: ["read"]}})

    result = auth.api.verify_api_key(body: {key: created[:key], permissions: {repo: ["write"]}})

    assert_equal false, result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], result[:error][:message]
    assert_equal "KEY_NOT_FOUND", result[:error][:code]
  end

  def test_verify_rate_limit_error_includes_upstream_code_and_retry_details
    auth = build_auth(default_key_length: 12, rate_limit: {enabled: true, time_window: 60_000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "rate-details-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    assert_equal true, auth.api.verify_api_key(body: {key: created[:key]})[:valid]
    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal false, result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["RATE_LIMIT_EXCEEDED"], result[:error][:message]
    assert_equal "RATE_LIMITED", result[:error][:code]
    assert result[:error][:details][:tryAgainIn].positive?
  end

  def test_verify_does_not_increment_request_count_when_rate_limit_is_disabled
    auth = build_auth(default_key_length: 12, rate_limit: {enabled: false, time_window: 60_000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "disabled-rate-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    assert_equal true, auth.api.verify_api_key(body: {key: created[:key]})[:valid]

    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert_equal 0, stored["requestCount"]
    assert stored["lastRequest"]
  end

  def test_verify_rate_limit_window_reset_and_permissions_metadata_shape
    auth = build_auth(default_key_length: 12, enable_metadata: true, rate_limit: {enabled: true, time_window: 60_000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "verify-shape-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, metadata: {scope: "read"}, permissions: {files: ["read", "write"]}})

    first = auth.api.verify_api_key(body: {key: created[:key], permissions: {files: ["read"]}})
    assert_equal true, first[:valid]
    assert_equal({"scope" => "read"}, first[:key][:metadata])
    assert_equal({"files" => ["read", "write"]}, first[:key][:permissions])

    limited = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal false, limited[:valid]
    assert_equal "RATE_LIMITED", limited[:error][:code]

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {lastRequest: Time.now - 120, requestCount: 1})
    reset = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal true, reset[:valid]
    assert_equal 1, reset[:key][:requestCount]

    no_permissions = auth.api.create_api_key(body: {userId: user_id, permissions: nil})
    permission_result = auth.api.verify_api_key(body: {key: no_permissions[:key], permissions: {files: ["write"]}})
    assert_equal false, permission_result[:valid]
    assert_equal "KEY_NOT_FOUND", permission_result[:error][:code]
  end

  def test_verify_remaining_refill_cycles_match_upstream
    auth = build_auth(default_key_length: 12, rate_limit: {enabled: false})
    cookie = sign_up_cookie(auth, email: "refill-cycles-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 1, refillAmount: 3, refillInterval: 3_600_000})

    first = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal true, first[:valid]
    assert_equal 0, first[:key][:remaining]

    before_refill = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal false, before_refill[:valid]
    assert_equal "USAGE_EXCEEDED", before_refill[:error][:code]

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {createdAt: Time.now - 3700, lastRefillAt: Time.now - 3700})
    refilled = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal true, refilled[:valid]
    assert_equal 2, refilled[:key][:remaining]

    2.times { assert_equal true, auth.api.verify_api_key(body: {key: created[:key]})[:valid] }
    exhausted = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal false, exhausted[:valid]
    assert_equal "USAGE_EXCEEDED", exhausted[:error][:code]

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {lastRefillAt: Time.now - 3700})
    second_refill = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal true, second_refill[:valid]
    assert_equal 2, second_refill[:key][:remaining]
  end

  def test_default_permissions_callable_and_prefix_validation
    calls = []
    auth = build_auth(
      default_key_length: 12,
      permissions: {
        default_permissions: ->(reference_id, ctx) {
          calls << [reference_id, ctx.path]
          {repo: ["read"]}
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "permissions-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    invalid_prefix = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id, prefix: "bad prefix"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_PREFIX_LENGTH"], invalid_prefix.message

    created = auth.api.create_api_key(body: {userId: user_id})
    assert_equal({"repo" => ["read"]}, created[:permissions])
    assert_equal [[user_id, "/api-key/create"]], calls
    assert_equal true, auth.api.verify_api_key(body: {key: created[:key], permissions: {repo: ["read"]}})[:valid]
  end

  def test_organization_owned_api_keys_require_membership_permissions_and_filtering
    ac = BetterAuth::Plugins.create_access_control(
      organization: ["update", "delete"],
      member: ["create", "update", "delete"],
      invitation: ["create", "cancel"],
      team: ["create", "update", "delete"],
      ac: ["create", "read", "update", "delete"],
      apiKey: ["create", "read", "update", "delete"]
    )
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization(
          ac: ac,
          roles: {
            owner: ac.new_role(member: ["create", "update", "delete"], apiKey: ["create", "read", "update", "delete"]),
            member: ac.new_role(apiKey: ["read"])
          }
        ),
        BetterAuth::Plugins.api_key([
          {config_id: "user-keys", default_prefix: "usr_", references: "user", default_key_length: 12},
          {config_id: "org-keys", default_prefix: "org_", references: "organization", default_key_length: 12}
        ])
      ]
    )
    owner_cookie = sign_up_cookie(auth, email: "org-owner-key@example.com")
    member_cookie = sign_up_cookie(auth, email: "org-member-key@example.com")
    member_id = auth.api.get_session(headers: {"cookie" => member_cookie})[:user]["id"]
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "API Org", slug: "api-org"})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), userId: member_id, role: "member"})

    org_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})

    assert_equal "org-keys", org_key[:configId]
    assert_equal organization.fetch("id"), org_key[:referenceId]
    assert_equal "org_", org_key[:prefix]

    listed = auth.api.list_api_keys(headers: {"cookie" => member_cookie}, query: {organizationId: organization.fetch("id")})
    assert_equal [org_key[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] }

    insufficient = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => member_cookie}, body: {configId: "org-keys", keyId: org_key[:id], name: "blocked"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INSUFFICIENT_API_KEY_PERMISSIONS"], insufficient.message
  end

  def test_organization_owner_has_implicit_api_key_permissions
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.api_key([
          {config_id: "user-keys", references: "user", default_key_length: 12},
          {config_id: "org-keys", references: "organization", default_key_length: 12}
        ])
      ]
    )
    owner_cookie = sign_up_cookie(auth, email: "implicit-owner-key@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Implicit API Org", slug: "implicit-api-org"})

    org_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})
    updated = auth.api.update_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", keyId: org_key[:id], name: "owner-updated"})
    deleted = auth.api.delete_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", keyId: org_key[:id]})

    assert_equal organization.fetch("id"), org_key[:referenceId]
    assert_equal "owner-updated", updated[:name]
    assert_equal({success: true}, deleted)
  end

  def test_organization_api_key_denials_and_wrong_config_match_upstream
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.api_key([
          {config_id: "user-keys", references: "user", default_key_length: 12},
          {config_id: "org-keys", references: "organization", default_key_length: 12}
        ])
      ]
    )
    owner_cookie = sign_up_cookie(auth, email: "org-denial-owner-key@example.com")
    non_member_cookie = sign_up_cookie(auth, email: "org-denial-non-member-key@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Denied API Org", slug: "denied-api-org"})
    org_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})

    non_member = assert_raises(BetterAuth::APIError) do
      auth.api.list_api_keys(headers: {"cookie" => non_member_cookie}, query: {organizationId: organization.fetch("id")})
    end
    assert_equal "FORBIDDEN", non_member.status
    assert_equal "USER_NOT_MEMBER_OF_ORGANIZATION", non_member.code
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["USER_NOT_MEMBER_OF_ORGANIZATION"], non_member.message

    wrong_config = assert_raises(BetterAuth::APIError) do
      auth.api.get_api_key(headers: {"cookie" => owner_cookie}, query: {id: org_key[:id], configId: "user-keys"})
    end
    assert_equal "NOT_FOUND", wrong_config.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], wrong_config.message

    no_org_plugin = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.api_key([{config_id: "org-keys", references: "organization", default_key_length: 12}])]
    )
    cookie = sign_up_cookie(no_org_plugin, email: "missing-org-plugin-key@example.com")
    missing_plugin = assert_raises(BetterAuth::APIError) do
      no_org_plugin.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-keys", organizationId: "fake-org-id"})
    end
    assert_equal "INTERNAL_SERVER_ERROR", missing_plugin.status
    assert_equal "ORGANIZATION_PLUGIN_REQUIRED", missing_plugin.code
  end

  def test_organization_api_key_custom_roles_match_upstream
    ac = BetterAuth::Plugins.create_access_control(
      organization: ["update", "delete"],
      member: ["create", "update", "delete"],
      invitation: ["create", "cancel"],
      team: ["create", "update", "delete"],
      ac: ["create", "read", "update", "delete"],
      apiKey: ["create", "read", "update", "delete"]
    )
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization(
          ac: ac,
          roles: {
            owner: ac.new_role(member: ["create", "update", "delete"], apiKey: ["create", "read", "update", "delete"]),
            admin: ac.new_role(apiKey: ["create", "read", "update", "delete"]),
            member: ac.new_role(apiKey: ["read"]),
            restricted: ac.new_role({})
          }
        ),
        BetterAuth::Plugins.api_key([{config_id: "org-keys", references: "organization", default_key_length: 12}])
      ]
    )
    owner_cookie = sign_up_cookie(auth, email: "custom-role-owner-key@example.com")
    admin_cookie = sign_up_cookie(auth, email: "custom-role-admin-key@example.com")
    member_cookie = sign_up_cookie(auth, email: "custom-role-member-key@example.com")
    restricted_cookie = sign_up_cookie(auth, email: "custom-role-restricted-key@example.com")
    admin_id = auth.api.get_session(headers: {"cookie" => admin_cookie})[:user]["id"]
    member_id = auth.api.get_session(headers: {"cookie" => member_cookie})[:user]["id"]
    restricted_id = auth.api.get_session(headers: {"cookie" => restricted_cookie})[:user]["id"]
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Custom Role API Org", slug: "custom-role-api-org"})
    org_id = organization.fetch("id")
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org_id, userId: admin_id, role: "admin"})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org_id, userId: member_id, role: "member"})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org_id, userId: restricted_id, role: "restricted"})

    admin_key = auth.api.create_api_key(headers: {"cookie" => admin_cookie}, body: {configId: "org-keys", organizationId: org_id})
    assert_equal org_id, admin_key[:referenceId]
    assert_equal "admin-updated", auth.api.update_api_key(headers: {"cookie" => admin_cookie}, body: {configId: "org-keys", keyId: admin_key[:id], name: "admin-updated"})[:name]
    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => admin_cookie}, body: {configId: "org-keys", keyId: admin_key[:id]}))

    owner_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: org_id})
    assert_includes auth.api.list_api_keys(headers: {"cookie" => member_cookie}, query: {organizationId: org_id})[:apiKeys].map { |entry| entry[:id] }, owner_key[:id]
    member_create = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => member_cookie}, body: {configId: "org-keys", organizationId: org_id})
    end
    assert_equal "INSUFFICIENT_API_KEY_PERMISSIONS", member_create.code

    restricted_list = assert_raises(BetterAuth::APIError) do
      auth.api.list_api_keys(headers: {"cookie" => restricted_cookie}, query: {organizationId: org_id})
    end
    assert_equal "INSUFFICIENT_API_KEY_PERMISSIONS", restricted_list.code
  end

  def test_update_auth_boundaries_match_upstream
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "owner-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, permissions: {repo: ["read"]}})

    unauthorized = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {keyId: created[:id], name: "stolen"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"], unauthorized.message

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {keyId: created[:id], userId: "different-user", name: "stolen"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], missing.message

    server_update = auth.api.update_api_key(body: {keyId: created[:id], userId: user_id, permissions: {repo: ["read", "write"]}})
    assert_equal({"repo" => ["read", "write"]}, server_update[:permissions])

    client_server_only = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], permissions: {repo: ["admin"]}})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"], client_server_only.message
  end

  def test_update_rejects_server_only_properties_from_authenticated_client
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "update-server-only@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, name: "client-only"})

    %i[refillAmount refillInterval rateLimitMax rateLimitTimeWindow rateLimitEnabled remaining permissions].each do |field|
      payload = {keyId: created[:id]}
      payload[field] = (field == :rateLimitEnabled) ? true : 1
      error = assert_raises(BetterAuth::APIError) do
        auth.api.update_api_key(headers: {"cookie" => cookie}, body: payload)
      end
      assert_equal "BAD_REQUEST", error.status, "expected BAD_REQUEST for #{field}"
      assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"], error.message,
        "expected SERVER_ONLY_PROPERTY message for #{field}"
    end
  end

  def test_update_treats_refill_undefined_vs_zero_correctly
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "refill-undef@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    updated = auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], refillAmount: 5, refillInterval: 10})
    assert_equal 5, updated[:refillAmount]
    assert_equal 10, updated[:refillInterval]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], refillAmount: 5})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["REFILL_AMOUNT_AND_INTERVAL_REQUIRED"], error.message
  end

  def test_update_expires_in_nil_clears_existing_expiration
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "clear-expiration-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, expiresIn: 60 * 60 * 24 * 7})

    assert created[:expiresAt]

    updated = auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], expiresIn: nil})

    assert_nil updated[:expiresAt]
  end

  def test_update_validates_fields_and_supports_upstream_mutations
    auth = build_auth(default_key_length: 12, enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "update-validation-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    no_values = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id]})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["NO_VALUES_TO_UPDATE"], no_values.message

    name_too_short = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], name: ""})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_NAME_LENGTH"], name_too_short.message

    invalid_metadata = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], metadata: "invalid"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_METADATA_TYPE"], invalid_metadata.message

    missing_interval = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], refillAmount: 10})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["REFILL_AMOUNT_AND_INTERVAL_REQUIRED"], missing_interval.message

    updated = auth.api.update_api_key(
      body: {
        userId: user_id,
        keyId: created[:id],
        expiresIn: 60 * 60 * 24 * 7,
        remaining: 50,
        refillAmount: 10,
        refillInterval: 1000,
        rateLimitEnabled: false,
        rateLimitTimeWindow: 2000,
        rateLimitMax: 20,
        metadata: {test: "test-123"},
        permissions: {files: ["read", "write"]}
      }
    )

    assert updated[:expiresAt]
    assert_equal 50, updated[:remaining]
    assert_equal 10, updated[:refillAmount]
    assert_equal 1000, updated[:refillInterval]
    assert_equal false, updated[:rateLimitEnabled]
    assert_equal 2000, updated[:rateLimitTimeWindow]
    assert_equal 20, updated[:rateLimitMax]
    assert_equal({"test" => "test-123"}, updated[:metadata])
    assert_equal({"files" => ["read", "write"]}, updated[:permissions])
  end

  def test_update_does_not_touch_usage_fields_unless_explicitly_requested
    auth = build_auth(default_key_length: 12, enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "update-side-effects-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 100})

    renamed = auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], name: "updated-name"})
    assert_nil renamed[:lastRequest]
    assert_equal 100, renamed[:remaining]

    explicit_remaining = auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], remaining: 50})
    assert_nil explicit_remaining[:lastRequest]
    assert_equal 50, explicit_remaining[:remaining]

    verified = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal true, verified[:valid]
    stored = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    assert stored[:lastRequest]
    assert_equal 49, stored[:remaining]
  end

  def test_get_list_and_delete_edge_cases_match_upstream
    auth = build_auth(default_key_length: 12, enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "route-edge-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    first = auth.api.create_api_key(body: {userId: user_id, name: "aaa-sort-test", metadata: {tier: "pro"}, permissions: {files: ["read"]}})
    second = auth.api.create_api_key(body: {userId: user_id, name: "zzz-sort-test"})

    get_missing = assert_raises(BetterAuth::APIError) do
      auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: "invalid"})
    end
    assert_equal "NOT_FOUND", get_missing.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], get_missing.message

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: first[:id]})
    assert_equal({"tier" => "pro"}, fetched[:metadata])
    assert_equal({"files" => ["read"]}, fetched[:permissions])

    list_without_session = assert_raises(BetterAuth::APIError) { auth.api.list_api_keys }
    assert_equal "UNAUTHORIZED", list_without_session.status

    asc = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {sortBy: "name", sortDirection: "asc", limit: "2", offset: "0"})
    desc = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {sortBy: "name", sortDirection: "desc"})
    overflow = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {offset: asc[:total] + 100})

    assert_equal 2, asc[:limit]
    assert_equal 0, asc[:offset]
    assert_equal %w[aaa-sort-test zzz-sort-test], asc[:apiKeys].map { |entry| entry[:name] }
    assert_equal "zzz-sort-test", desc[:apiKeys].first[:name]
    assert_empty overflow[:apiKeys]
    assert_equal asc[:total], overflow[:total]

    delete_missing = assert_raises(BetterAuth::APIError) do
      auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: "invalid"})
    end
    assert_equal "NOT_FOUND", delete_missing.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], delete_missing.message

    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: second[:id]}))
  end

  def test_update_ignores_metadata_when_metadata_is_disabled
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "metadata-disabled-update-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    updated = auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], name: "renamed", metadata: {tier: "pro"}})

    assert_equal "renamed", updated[:name]
    assert_nil updated[:metadata]
  end

  def test_delete_all_expired_api_keys_returns_upstream_payload_shape
    auth = build_auth(default_key_length: 12)

    result = auth.api.delete_all_expired_api_keys

    assert_equal({success: true, error: nil}, result)
  end

  def test_delete_rejects_banned_users
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.admin,
        BetterAuth::Plugins.api_key(default_key_length: 12)
      ]
    )
    cookie = sign_up_cookie(auth, email: "banned-delete-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})
    auth.context.internal_adapter.update_user(user_id, banned: true)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_api_key(headers: {"cookie" => cookie}, query: {disableCookieCache: true}, body: {keyId: created[:id]})
    end

    assert_equal "UNAUTHORIZED", error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["USER_BANNED"], error.message
  end

  def test_secondary_storage_requires_configured_storage_backend
    auth = build_auth(default_key_length: 12, storage: "secondary-storage")
    cookie = sign_up_cookie(auth, email: "missing-storage-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id})
    end

    assert_equal "INTERNAL_SERVER_ERROR", error.status
    assert_equal "Secondary storage is required when storage mode is 'secondary-storage'", error.message
  end

  def test_legacy_double_stringified_metadata_is_returned_as_object_and_migrated
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "metadata-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {metadata: {tier: "free"}})
    legacy = JSON.generate(JSON.generate({tier: "legacy"}))

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {metadata: legacy})

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    assert_equal({"tier" => "legacy"}, fetched[:metadata])

    migrated = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert_equal({"tier" => "legacy"}, JSON.parse(migrated["metadata"]))

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {metadata: legacy})
    verified = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal({"tier" => "legacy"}, verified[:key][:metadata])
  end

  def test_verify_runs_expired_cleanup_synchronously_unless_deferred
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "verify-cleanup@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    expired = auth.api.create_api_key(body: {userId: user_id})
    auth.context.adapter.update(
      model: "apikey",
      where: [{field: "id", value: expired[:id]}],
      update: {expiresAt: Time.now - 60}
    )

    result = auth.api.verify_api_key(body: {key: expired[:key]})

    assert_equal false, result[:valid]
    refute auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: expired[:id]}])
  end

  def test_verify_schedules_expired_cleanup_in_background_when_deferred
    background = []
    auth = build_auth(
      default_key_length: 12,
      defer_updates: true,
      advanced: {background_tasks: {handler: ->(task) { background << task }}}
    )
    cookie = sign_up_cookie(auth, email: "verify-cleanup-deferred@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    expired = auth.api.create_api_key(body: {userId: user_id})
    auth.context.adapter.update(
      model: "apikey",
      where: [{field: "id", value: expired[:id]}],
      update: {expiresAt: Time.now - 60}
    )

    auth.api.verify_api_key(body: {key: expired[:key]})

    assert_equal 1, background.length
    background.each(&:call)
    refute auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: expired[:id]}]),
      "expected the deferred per-key cleanup to delete the expired record once the handler runs the task"
  end

  def test_defer_updates_uses_configured_background_task_handler
    deferred = []
    auth = build_auth(
      defer_updates: true,
      advanced: {
        background_tasks: {
          handler: ->(task) { deferred << task }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "defer-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 2})

    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal true, result[:valid]
    assert_equal 1, result[:key][:remaining]
    assert_equal 1, deferred.length, "expected only incidental cleanup to be scheduled; usage accounting must be immediate"
    stored_before_task = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert stored_before_task["lastRequest"]
    assert_equal 1, stored_before_task["remaining"]
    deferred.each(&:call)
    stored_after_task = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert stored_after_task["lastRequest"]
    assert_equal 1, stored_after_task["remaining"]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:90
  def test_create_without_session_or_user_id_returns_unauthorized
    auth = build_auth(default_key_length: 12)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {})
    end

    assert_equal "UNAUTHORIZED", error.status
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:171
  def test_create_defaults_rate_limit_enabled_true_when_omitted
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "rate-default-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    created = auth.api.create_api_key(body: {userId: user_id})

    assert_equal true, created[:rateLimitEnabled]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:370
  def test_create_sets_custom_expires_at_from_expires_in
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "custom-expiration-create-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    before = Time.now

    created = auth.api.create_api_key(body: {userId: user_id, expiresIn: 60 * 60 * 24 * 7})

    assert created[:expiresAt]
    assert_operator created[:expiresAt], :>=, before + (60 * 60 * 24 * 7) - 1
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:443
  def test_create_rejects_custom_expires_in_when_custom_expiration_is_disabled
    auth = build_auth(default_key_length: 12, key_expiration: {disable_custom_expires_time: true})
    cookie = sign_up_cookie(auth, email: "disabled-create-expiration-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id, expiresIn: 60 * 60 * 24 * 7})
    end

    assert_equal "BAD_REQUEST", error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_DISABLED_EXPIRATION"], error.message
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:921
  def test_create_accepts_server_side_custom_rate_limit_fields
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "server-rate-fields-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    created = auth.api.create_api_key(
      body: {userId: user_id, rateLimitMax: 15, rateLimitTimeWindow: 1000}
    )

    assert_equal 15, created[:rateLimitMax]
    assert_equal 1000, created[:rateLimitTimeWindow]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:985
  def test_verify_default_rate_limit_allows_first_ten_and_limits_afterward
    auth = build_auth(default_key_length: 12, rate_limit: {enabled: true, time_window: 60_000, max_requests: 10})
    cookie = sign_up_cookie(auth, email: "default-rate-limit-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    10.times do
      result = auth.api.verify_api_key(body: {key: created[:key]})
      assert_equal true, result[:valid]
      assert_nil result[:error]
    end
    limited = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal false, limited[:valid]
    assert_equal "RATE_LIMITED", limited[:error][:code]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:1007
  def test_verify_allows_requests_after_rate_limit_window_passes
    auth = build_auth(default_key_length: 12, rate_limit: {enabled: true, time_window: 1000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "rate-window-reset-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    assert_equal true, auth.api.verify_api_key(body: {key: created[:key]})[:valid]
    assert_equal false, auth.api.verify_api_key(body: {key: created[:key]})[:valid]
    auth.context.adapter.update(
      model: "apikey",
      where: [{field: "id", value: created[:id]}],
      update: {lastRequest: Time.now - 2, requestCount: 1}
    )
    reset = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal true, reset[:valid]
    assert_nil reset[:error]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:1020
  def test_verify_decrements_remaining_count_on_each_successful_use
    auth = build_auth(default_key_length: 12, rate_limit: {enabled: false})
    cookie = sign_up_cookie(auth, email: "remaining-decrement-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 10})

    first = auth.api.verify_api_key(body: {key: created[:key]})
    second = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal true, first[:valid]
    assert_equal 9, first[:key][:remaining]
    assert_equal true, second[:valid]
    assert_equal 8, second[:key][:remaining]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:1224
  def test_update_rejects_custom_expires_in_when_custom_expiration_is_disabled
    auth = build_auth(default_key_length: 12, key_expiration: {disable_custom_expires_time: true})
    cookie = sign_up_cookie(auth, email: "disabled-update-expiration-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], expiresIn: 60 * 60 * 24 * 7})
    end

    assert_equal "BAD_REQUEST", error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_DISABLED_EXPIRATION"], error.message
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:1271
  def test_update_rejects_expires_in_below_minimum
    auth = build_auth(default_key_length: 12, key_expiration: {min_expires_in: 1})
    cookie = sign_up_cookie(auth, email: "update-min-expiration-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], expiresIn: 1})
    end

    assert_equal "BAD_REQUEST", error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_SMALL"], error.message
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:1318
  def test_update_rejects_expires_in_above_maximum
    auth = build_auth(default_key_length: 12, key_expiration: {max_expires_in: 1})
    cookie = sign_up_cookie(auth, email: "update-max-expiration-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], expiresIn: 60 * 60 * 24 * 365 * 10})
    end

    assert_equal "BAD_REQUEST", error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_LARGE"], error.message
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:2007
  def test_delete_without_session_or_user_id_returns_unauthorized
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "delete-unauthorized-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_api_key(body: {keyId: created[:id]})
    end

    assert_equal "UNAUTHORIZED", error.status
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:1772
  def test_list_pagination_pages_do_not_overlap
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "pagination-overlap-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    5.times { |index| auth.api.create_api_key(body: {userId: user_id, name: "page-key-#{index}"}) }

    page_one = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {limit: 2, offset: 0, sortBy: "name", sortDirection: "asc"})
    page_two = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {limit: 2, offset: 2, sortBy: "name", sortDirection: "asc"})

    assert_operator page_one[:apiKeys].length, :<=, 2
    assert_operator page_two[:apiKeys].length, :<=, 2
    assert_empty page_one[:apiKeys].map { |key| key[:id] } & page_two[:apiKeys].map { |key| key[:id] }
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:1810
  def test_list_sorts_by_created_at_descending
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "created-desc-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.api.create_api_key(body: {userId: user_id, name: "oldest"})
    sleep 0.01
    auth.api.create_api_key(body: {userId: user_id, name: "newest"})

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {sortBy: "createdAt", sortDirection: "desc"})
    times = listed[:apiKeys].map { |key| key[:createdAt] }

    times.each_cons(2) do |previous, current|
      assert_operator previous, :>=, current
    end
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:1857
  def test_list_combines_created_at_sorting_with_pagination
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "created-pagination-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    5.times do |index|
      auth.api.create_api_key(body: {userId: user_id, name: "created-page-key-#{index}"})
      sleep 0.005
    end

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {limit: 3, offset: 0, sortBy: "createdAt", sortDirection: "desc"})

    assert_operator listed[:apiKeys].length, :<=, 3
    assert_equal 3, listed[:limit]
    listed[:apiKeys].map { |key| key[:createdAt] }.each_cons(2) do |previous, current|
      assert_operator previous, :>=, current
    end
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:2763
  def test_secondary_storage_expired_key_returns_key_expired
    storage = MemoryStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "secondary-expired-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, expiresIn: 60 * 60 * 24 + 1})
    record = JSON.parse(storage.get("api-key:by-id:#{created[:id]}"))
    record["expiresAt"] = (Time.now - 60).iso8601
    serialized = JSON.generate(record)
    storage.set("api-key:by-id:#{created[:id]}", serialized)
    storage.set("api-key:#{record["key"]}", serialized)

    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal false, result[:valid]
    assert_equal "KEY_EXPIRED", result[:error][:code]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:2792
  def test_secondary_storage_reference_list_removes_deleted_key
    storage = MemoryStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "secondary-ref-list-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    first = auth.api.create_api_key(body: {userId: user_id})
    second = auth.api.create_api_key(body: {userId: user_id})
    third = auth.api.create_api_key(body: {userId: user_id})

    before_delete = auth.api.list_api_keys(headers: {"cookie" => cookie})
    auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: second[:id]})
    after_delete = auth.api.list_api_keys(headers: {"cookie" => cookie})

    assert_equal [first[:id], second[:id], third[:id]].sort, before_delete[:apiKeys].map { |key| key[:id] }.sort
    assert_equal [first[:id], third[:id]].sort, after_delete[:apiKeys].map { |key| key[:id] }.sort
    ref_ids = JSON.parse(storage.get("api-key:by-ref:#{user_id}"))
    refute_includes ref_ids, second[:id]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:2879
  def test_secondary_storage_fallback_reads_cache_before_database
    storage = MemoryStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, fallback_to_database: true, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "fallback-cache-first-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "cache-name"})
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {name: "database-name"})

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})

    assert_equal "cache-name", fetched[:name]
    assert_includes storage.get_calls, "api-key:by-id:#{created[:id]}"
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:2898
  def test_secondary_storage_fallback_verify_persists_quota_updates_to_database
    storage = MemoryStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, fallback_to_database: true, default_key_length: 12, rate_limit: {enabled: false})
    cookie = sign_up_cookie(auth, email: "fallback-quota-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 1})

    first = auth.api.verify_api_key(body: {key: created[:key]})
    db_after_first = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    storage.clear
    second = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal true, first[:valid]
    assert_equal 0, first[:key][:remaining]
    assert_equal 0, db_after_first[:remaining]
    assert_equal false, second[:valid]
    assert_equal "USAGE_EXCEEDED", second[:error][:code]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:2990
  def test_secondary_storage_fallback_list_populates_all_cache_keys_from_database
    storage = MemoryStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, fallback_to_database: true, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "fallback-list-populate-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    first = create_raw_api_key_record(auth, reference_id: user_id, key: "hashed-db-key-1", name: "DB Key 1")
    second = create_raw_api_key_record(auth, reference_id: user_id, key: "hashed-db-key-2", name: "DB Key 2")

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})

    assert_includes listed[:apiKeys].map { |key| key[:id] }, first["id"]
    assert_includes listed[:apiKeys].map { |key| key[:id] }, second["id"]
    assert storage.get("api-key:by-id:#{first["id"]}")
    assert storage.get("api-key:by-id:#{second["id"]}")
    assert storage.get("api-key:hashed-db-key-1")
    assert storage.get("api-key:hashed-db-key-2")
    assert_equal [first["id"], second["id"]].sort, JSON.parse(storage.get("api-key:by-ref:#{user_id}")).sort
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3135
  def test_secondary_storage_fallback_population_touches_ref_list_once
    storage = MemoryStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, fallback_to_database: true, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "fallback-ref-touch-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    5.times { |index| create_raw_api_key_record(auth, reference_id: user_id, key: "hashed-ref-touch-#{index}", name: "Ref Touch #{index}") }
    ref_key = "api-key:by-ref:#{user_id}"

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})

    assert_operator listed[:apiKeys].length, :>=, 5
    assert_operator storage.get_calls.count { |key| key == ref_key }, :<=, 1
    assert_equal 1, storage.set_calls.count { |(key, _value, _ttl)| key == ref_key }
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3243
  def test_secondary_storage_pure_mode_does_not_write_database
    storage = MemoryStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "pure-only-key@example.com")

    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "pure-only"})

    assert storage.get("api-key:by-id:#{created[:id]}")
    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3254
  def test_secondary_storage_fallback_create_writes_database_and_cache
    storage = MemoryStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, fallback_to_database: true, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "fallback-create-cache-key@example.com")

    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "fallback-create"})
    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])

    assert storage.get("api-key:by-id:#{created[:id]}")
    assert stored
    assert_equal "fallback-create", stored["name"]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3276
  def test_secondary_storage_fallback_update_writes_database_and_cache
    storage = MemoryStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, fallback_to_database: true, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "fallback-update-cache-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "original"})

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], name: "updated"})
    cached = JSON.parse(storage.get("api-key:by-id:#{created[:id]}"))
    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])

    assert_equal "updated", updated[:name]
    assert_equal "updated", cached["name"]
    assert_equal "updated", stored["name"]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3311
  def test_secondary_storage_fallback_delete_removes_database_and_cache
    storage = MemoryStorage.new
    auth = build_auth(storage: "secondary-storage", secondary_storage: storage, fallback_to_database: true, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "fallback-delete-cache-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    result = auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id]})

    assert_equal({success: true}, result)
    assert_nil storage.get("api-key:by-id:#{created[:id]}")
    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3395
  def test_defer_updates_still_enforces_rate_limits
    deferred = []
    auth = build_auth(
      default_key_length: 12,
      defer_updates: true,
      rate_limit: {enabled: true, max_requests: 2, time_window: 60_000},
      advanced: {background_tasks: {handler: ->(task) { deferred << task }}}
    )
    cookie = sign_up_cookie(auth, email: "defer-rate-limit-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    first = auth.api.verify_api_key(body: {key: created[:key]})
    deferred.each(&:call)
    deferred.clear
    second = auth.api.verify_api_key(body: {key: created[:key]})
    deferred.each(&:call)
    deferred.clear
    third = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal true, first[:valid]
    assert_equal true, second[:valid]
    assert_equal false, third[:valid]
    assert_equal "RATE_LIMITED", third[:error][:code]
    assert third[:error][:details][:tryAgainIn]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3443
  def test_defer_updates_persists_remaining_count_after_background_task
    deferred = []
    auth = build_auth(
      default_key_length: 12,
      defer_updates: true,
      advanced: {background_tasks: {handler: ->(task) { deferred << task }}}
    )
    cookie = sign_up_cookie(auth, email: "defer-remaining-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 10})

    result = auth.api.verify_api_key(body: {key: created[:key]})
    deferred.each(&:call)
    updated = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})

    assert_equal true, result[:valid]
    assert_equal 9, result[:key][:remaining]
    assert_equal 9, updated[:remaining]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3483
  def test_defer_updates_without_background_handler_runs_synchronously
    auth = build_auth(default_key_length: 12, defer_updates: true)
    cookie = sign_up_cookie(auth, email: "defer-no-handler-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    result = auth.api.verify_api_key(body: {key: created[:key]})
    updated = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})

    assert_equal true, result[:valid]
    assert updated[:lastRequest]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3678
  def test_list_api_keys_migrates_double_stringified_metadata
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "metadata-list-migration-key@example.com")
    first = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "first", metadata: {plan: "pro"}})
    second = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "second", metadata: {plan: "enterprise"}})
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: first[:id]}], update: {metadata: JSON.generate(JSON.generate({plan: "legacy-1"}))})
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: second[:id]}], update: {metadata: JSON.generate(JSON.generate({plan: "legacy-2"}))})

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    first_result = listed[:apiKeys].find { |key| key[:id] == first[:id] }
    second_result = listed[:apiKeys].find { |key| key[:id] == second[:id] }
    migrated_first = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: first[:id]}])
    migrated_second = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: second[:id]}])

    assert_equal({"plan" => "legacy-1"}, first_result[:metadata])
    assert_equal({"plan" => "legacy-2"}, second_result[:metadata])
    assert_equal({"plan" => "legacy-1"}, JSON.parse(migrated_first["metadata"]))
    assert_equal({"plan" => "legacy-2"}, JSON.parse(migrated_second["metadata"]))
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3747
  def test_update_api_key_migrates_double_stringified_metadata
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "metadata-update-migration-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "legacy", metadata: {tier: "free"}})
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {metadata: JSON.generate(JSON.generate({tier: "legacy-tier"}))})

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], name: "updated-name"})
    migrated = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])

    assert_equal "updated-name", updated[:name]
    assert_equal({"tier" => "legacy-tier"}, updated[:metadata])
    assert_equal({"tier" => "legacy-tier"}, JSON.parse(migrated["metadata"]))
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3827
  def test_metadata_migration_leaves_properly_formatted_metadata_unchanged
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "metadata-unchanged-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {metadata: {alreadyCorrect: true, value: 123}})

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})

    assert_equal({"alreadyCorrect" => true, "value" => 123}, fetched[:metadata])
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:3848
  def test_metadata_migration_handles_null_metadata
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "metadata-null-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})

    assert_nil fetched[:metadata]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:4173
  def test_org_key_create_requires_organization_id
    auth = build_user_and_org_key_auth
    cookie = sign_up_cookie(auth, email: "org-id-required-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {configId: "org-keys", userId: user_id})
    end

    assert_equal "BAD_REQUEST", error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["ORGANIZATION_ID_REQUIRED"], error.message
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:4217
  def test_list_without_organization_id_returns_only_user_owned_keys
    auth = build_user_and_org_key_auth
    cookie = sign_up_cookie(auth, email: "list-user-owned-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "List User Owned Org", slug: unique_slug("list-user-owned")})
    user_key = auth.api.create_api_key(body: {configId: "user-keys", userId: user_id})
    org_key = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    ids = listed[:apiKeys].map { |key| key[:id] }

    assert_includes ids, user_key[:id]
    refute_includes ids, org_key[:id]
    assert listed[:apiKeys].all? { |key| key[:configId] == "user-keys" && key[:referenceId] == user_id }
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:4248
  def test_list_with_organization_id_returns_only_org_owned_keys
    auth = build_user_and_org_key_auth
    cookie = sign_up_cookie(auth, email: "list-org-owned-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "List Org Owned Org", slug: unique_slug("list-org-owned")})
    user_key = auth.api.create_api_key(body: {configId: "user-keys", userId: user_id})
    first_org_key = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id"), name: "org-key-1"})
    second_org_key = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id"), name: "org-key-2"})

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {organizationId: organization.fetch("id")})
    ids = listed[:apiKeys].map { |key| key[:id] }

    assert_equal [first_org_key[:id], second_org_key[:id]].sort, ids.sort
    refute_includes ids, user_key[:id]
    assert listed[:apiKeys].all? { |key| key[:configId] == "org-keys" && key[:referenceId] == organization.fetch("id") }
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:4300
  def test_list_org_keys_filters_by_config_id
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.api_key([
          {config_id: "org-public", default_prefix: "pub_", references: "organization", default_key_length: 12},
          {config_id: "org-internal", default_prefix: "int_", references: "organization", default_key_length: 12}
        ])
      ]
    )
    cookie = sign_up_cookie(auth, email: "org-config-filter-key@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Org Config Filter", slug: unique_slug("org-config-filter")})
    auth.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-public", organizationId: organization.fetch("id")})
    auth.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-internal", organizationId: organization.fetch("id")})

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {organizationId: organization.fetch("id"), configId: "org-public"})

    assert_equal 1, listed[:apiKeys].length
    assert_equal "org-public", listed[:apiKeys].first[:configId]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:4413
  def test_org_owned_key_cannot_create_api_key_session
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.api_key([{config_id: "org-keys", default_prefix: "org_", references: "organization", default_key_length: 12, enable_session_for_api_keys: true}])
      ]
    )
    cookie = sign_up_cookie(auth, email: "org-session-denied-key@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Org Session Denied", slug: unique_slug("org-session-denied")})
    org_key = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.get_session(headers: {"x-api-key" => org_key[:key]})
    end

    assert_equal "INVALID_REFERENCE_ID_FROM_API_KEY", error.code
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:4469
  def test_user_owned_key_can_create_api_key_session_with_org_plugin_installed
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.api_key([{config_id: "user-keys", default_prefix: "usr_", references: "user", default_key_length: 12, enable_session_for_api_keys: true}])
      ]
    )
    cookie = sign_up_cookie(auth, email: "user-session-with-org-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    user_key = auth.api.create_api_key(body: {configId: "user-keys", userId: user_id})

    session = auth.api.get_session(headers: {"x-api-key" => user_key[:key]})

    assert session
    assert_equal user_id, session[:user]["id"]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:4514
  def test_mixed_user_and_org_keys_verify_in_same_instance
    auth = build_user_and_org_key_auth
    cookie = sign_up_cookie(auth, email: "mixed-user-org-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Mixed User Org", slug: unique_slug("mixed-user-org")})
    user_key = auth.api.create_api_key(body: {configId: "user-keys", userId: user_id})
    org_key = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})

    user_result = auth.api.verify_api_key(body: {key: user_key[:key], configId: "user-keys"})
    org_result = auth.api.verify_api_key(body: {key: org_key[:key], configId: "org-keys"})

    assert_equal true, user_result[:valid]
    assert_equal user_id, user_result[:key][:referenceId]
    assert_equal true, org_result[:valid]
    assert_equal organization.fetch("id"), org_result[:key][:referenceId]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:4547
  def test_get_org_owned_key_by_id_from_server
    auth = build_user_and_org_key_auth
    cookie = sign_up_cookie(auth, email: "get-org-owned-key@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Get Org Owned", slug: unique_slug("get-org-owned")})
    org_key = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id"), name: "my-org-key"})

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: org_key[:id], configId: "org-keys"})

    assert_equal org_key[:id], fetched[:id]
    assert_equal "org-keys", fetched[:configId]
    assert_equal organization.fetch("id"), fetched[:referenceId]
    assert_equal "my-org-key", fetched[:name]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:4577
  def test_delete_org_owned_key_then_verify_fails
    auth = build_user_and_org_key_auth
    cookie = sign_up_cookie(auth, email: "delete-org-owned-key@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Delete Org Owned", slug: unique_slug("delete-org-owned")})
    org_key = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})

    deleted = auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: org_key[:id], configId: "org-keys"})
    verified = auth.api.verify_api_key(body: {key: org_key[:key], configId: "org-keys"})

    assert_equal({success: true}, deleted)
    assert_equal false, verified[:valid]
  end

  # Upstream: upstream/packages/api-key/src/api-key.test.ts:4609
  def test_update_org_owned_key_name_and_enabled_status
    auth = build_user_and_org_key_auth
    cookie = sign_up_cookie(auth, email: "update-org-owned-key@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Update Org Owned", slug: unique_slug("update-org-owned")})
    org_key = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id"), name: "original-name"})

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: org_key[:id], configId: "org-keys", name: "updated-name", enabled: false})

    assert_equal "updated-name", updated[:name]
    assert_equal false, updated[:enabled]
    assert_equal "org-keys", updated[:configId]
    assert_equal organization.fetch("id"), updated[:referenceId]
  end

  # Upstream: upstream/packages/api-key/src/org-api-key.test.ts:101
  def test_org_non_member_is_denied_full_api_key_crud
    auth = build_user_and_org_key_auth
    owner_cookie = sign_up_cookie(auth, email: "org-non-member-owner-key@example.com")
    non_member_cookie = sign_up_cookie(auth, email: "org-non-member-key@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Non Member CRUD Org", slug: unique_slug("non-member-crud")})
    org_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})

    assert_org_api_key_forbidden(auth, non_member_cookie, organization.fetch("id"), org_key[:id], "USER_NOT_MEMBER_OF_ORGANIZATION")
  end

  # Upstream: upstream/packages/api-key/src/org-api-key.test.ts:173
  def test_org_default_member_without_api_key_permissions_is_denied
    auth = build_user_and_org_key_auth
    owner_cookie = sign_up_cookie(auth, email: "org-default-owner-key@example.com")
    member_cookie = sign_up_cookie(auth, email: "org-default-member-key@example.com")
    member_id = auth.api.get_session(headers: {"cookie" => member_cookie})[:user]["id"]
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Default Member Org", slug: unique_slug("default-member")})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), userId: member_id, role: "member"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_api_keys(headers: {"cookie" => member_cookie}, query: {organizationId: organization.fetch("id")})
    end

    assert_equal "FORBIDDEN", error.status
    assert_equal "INSUFFICIENT_API_KEY_PERMISSIONS", error.code
  end

  # Upstream: upstream/packages/api-key/src/org-api-key.test.ts:416
  def test_org_read_only_member_can_read_but_cannot_create_update_or_delete
    auth = build_custom_org_api_key_auth
    owner_cookie = sign_up_cookie(auth, email: "org-read-owner-key@example.com")
    member_cookie = sign_up_cookie(auth, email: "org-read-member-key@example.com")
    member_id = auth.api.get_session(headers: {"cookie" => member_cookie})[:user]["id"]
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Read Member Org", slug: unique_slug("read-member")})
    org_id = organization.fetch("id")
    org_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: org_id})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org_id, userId: member_id, role: "member"})

    listed = auth.api.list_api_keys(headers: {"cookie" => member_cookie}, query: {organizationId: org_id})
    fetched = auth.api.get_api_key(headers: {"cookie" => member_cookie}, query: {id: org_key[:id], configId: "org-keys"})

    assert_includes listed[:apiKeys].map { |key| key[:id] }, org_key[:id]
    assert_equal org_key[:id], fetched[:id]
    create_error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => member_cookie}, body: {configId: "org-keys", organizationId: org_id})
    end
    update_error = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => member_cookie}, body: {keyId: org_key[:id], configId: "org-keys", name: "blocked"})
    end
    delete_error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_api_key(headers: {"cookie" => member_cookie}, body: {keyId: org_key[:id], configId: "org-keys"})
    end
    [create_error, update_error, delete_error].each do |error|
      assert_equal "FORBIDDEN", error.status
      assert_equal "INSUFFICIENT_API_KEY_PERMISSIONS", error.code
    end
  end

  # Upstream: upstream/packages/api-key/src/org-api-key.test.ts:478
  def test_org_restricted_member_is_denied_full_api_key_crud
    auth = build_custom_org_api_key_auth
    owner_cookie = sign_up_cookie(auth, email: "org-restricted-owner-key@example.com")
    restricted_cookie = sign_up_cookie(auth, email: "org-restricted-member-key@example.com")
    restricted_id = auth.api.get_session(headers: {"cookie" => restricted_cookie})[:user]["id"]
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Restricted Member Org", slug: unique_slug("restricted-member")})
    org_id = organization.fetch("id")
    org_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: org_id})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org_id, userId: restricted_id, role: "restricted"})

    assert_org_api_key_forbidden(auth, restricted_cookie, org_id, org_key[:id], "INSUFFICIENT_API_KEY_PERMISSIONS")
  end

  def build_auth(options = {})
    advanced = options.is_a?(Hash) ? options.delete(:advanced) : nil
    secondary_storage = options.is_a?(Hash) ? options.delete(:secondary_storage) : nil
    session = options.is_a?(Hash) ? options.delete(:session) : nil
    BetterAuth.auth({
      secret: SECRET,
      email_and_password: {enabled: true},
      advanced: advanced,
      secondary_storage: secondary_storage,
      session: session,
      plugins: [BetterAuth::Plugins.api_key(options)]
    }.compact)
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "API Key"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def create_raw_api_key_record(auth, reference_id:, key:, name:)
    now = Time.now
    auth.context.adapter.create(
      model: "apikey",
      data: {
        configId: "default",
        createdAt: now,
        updatedAt: now,
        name: name,
        prefix: "test",
        start: "test_",
        key: key,
        enabled: true,
        expiresAt: nil,
        referenceId: reference_id,
        lastRefillAt: nil,
        lastRequest: nil,
        metadata: nil,
        rateLimitMax: nil,
        rateLimitTimeWindow: nil,
        remaining: nil,
        refillAmount: nil,
        refillInterval: nil,
        rateLimitEnabled: false,
        requestCount: 0,
        permissions: nil
      }
    )
  end

  def build_user_and_org_key_auth
    BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.api_key([
          {config_id: "user-keys", default_prefix: "usr_", references: "user", default_key_length: 12},
          {config_id: "org-keys", default_prefix: "org_", references: "organization", default_key_length: 12}
        ])
      ]
    )
  end

  def build_custom_org_api_key_auth
    ac = BetterAuth::Plugins.create_access_control(
      organization: ["update", "delete"],
      member: ["create", "update", "delete"],
      invitation: ["create", "cancel"],
      team: ["create", "update", "delete"],
      ac: ["create", "read", "update", "delete"],
      apiKey: ["create", "read", "update", "delete"]
    )
    BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization(
          ac: ac,
          roles: {
            owner: ac.new_role(member: ["create", "update", "delete"], apiKey: ["create", "read", "update", "delete"]),
            admin: ac.new_role(apiKey: ["create", "read", "update", "delete"]),
            member: ac.new_role(apiKey: ["read"]),
            restricted: ac.new_role({})
          }
        ),
        BetterAuth::Plugins.api_key([{config_id: "org-keys", references: "organization", default_key_length: 12}])
      ]
    )
  end

  def assert_org_api_key_forbidden(auth, cookie, organization_id, key_id, code)
    list_error = assert_raises(BetterAuth::APIError) do
      auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {organizationId: organization_id})
    end
    create_error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-keys", organizationId: organization_id})
    end
    get_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: key_id, configId: "org-keys"})
    end
    update_error = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: key_id, configId: "org-keys", name: "blocked"})
    end
    delete_error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: key_id, configId: "org-keys"})
    end
    [list_error, create_error, get_error, update_error, delete_error].each do |error|
      assert_equal "FORBIDDEN", error.status
      assert_equal code, error.code
    end
  end

  def unique_slug(prefix)
    "#{prefix}-#{SecureRandom.hex(4)}"
  end

  class MemoryStorage
    attr_reader :values, :ttls, :get_calls, :set_calls, :delete_calls

    def initialize
      @values = {}
      @ttls = {}
      @get_calls = []
      @set_calls = []
      @delete_calls = []
    end

    def get(key)
      get_calls << key
      values[key]
    end

    def set(key, value, ttl = nil)
      set_calls << [key, value, ttl]
      values[key] = value
      ttls[key] = ttl if ttl
    end

    def delete(key)
      delete_calls << key
      values.delete(key)
      ttls.delete(key)
    end

    def keys
      values.keys
    end

    def clear
      values.clear
      ttls.clear
      get_calls.clear
      set_calls.clear
      delete_calls.clear
    end
  end

  class OrderTrackingStorage < MemoryStorage
    attr_reader :write_groups

    def initialize
      super
      @write_groups = []
      @current_group = nil
    end

    def set(key, value, ttl = nil)
      record_write(key)
      super
    end

    def delete(key)
      record_write(key)
      super
    end

    def batch
      @current_group = []
      yield
      @write_groups << @current_group unless @current_group.empty?
      @current_group = nil
    end

    private

    def record_write(key)
      if @current_group
        @current_group << key
      else
        @write_groups << [key]
      end
    end
  end
end

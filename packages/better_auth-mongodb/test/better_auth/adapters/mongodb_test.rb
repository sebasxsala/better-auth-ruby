# frozen_string_literal: true

require "json"
require_relative "../../test_helper"
require_relative "../../support/fake_mongo"

class BetterAuthMongoDBAdapterTest < Minitest::Test
  include BetterAuthMongoAdapterTestSupport

  SECRET = "test-secret-that-is-long-enough-for-validation"

  def setup
    @config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    @database = FakeMongoDatabase.new
    @adapter = BetterAuth::Adapters::MongoDB.new(@config, database: @database)
  end

  def test_mongodb_adapter_can_be_constructed_with_minimal_database
    assert_instance_of BetterAuth::Adapters::MongoDB, BetterAuth::Adapters::MongoDB.new(@config, database: @database)
  end

  def test_mongodb_adapter_ensures_schema_indexes_explicitly
    plugin = {
      id: "profile-indexes",
      schema: {
        profile: {
          modelName: "profiles",
          fields: {
            ownerId: {type: "string", required: true, fieldName: "owner_ref", references: {model: "user", field: "id"}, index: true},
            handle: {type: "string", required: true, fieldName: "profile_handle", unique: true}
          }
        }
      }
    }
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [plugin],
      user: {
        model_name: "people",
        fields: {email: "email_address"}
      },
      rate_limit: {storage: "database"}
    )
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)

    summary = adapter.ensure_indexes!

    assert_includes summary, {collection: "people", field: "email", keys: {"email_address" => 1}, unique: true}
    assert_includes summary, {collection: "session", field: "token", keys: {"token" => 1}, unique: true}
    assert_includes summary, {collection: "session", field: "userId", keys: {"user_id" => 1}, unique: false}
    assert_includes summary, {collection: "account", field: "userId", keys: {"user_id" => 1}, unique: false}
    assert_includes summary, {collection: "verification", field: "identifier", keys: {"identifier" => 1}, unique: false}
    assert_includes summary, {collection: "rateLimit", field: "key", keys: {"key" => 1}, unique: true}
    assert_includes summary, {collection: "profiles", field: "ownerId", keys: {"owner_ref" => 1}, unique: false}
    assert_includes summary, {collection: "profiles", field: "handle", keys: {"profile_handle" => 1}, unique: true}
    refute summary.any? { |entry| entry.fetch(:keys).key?("_id") }
    assert_equal [[{"email_address" => 1}, {unique: true}]], @database.collection("people").indexes.create_one_calls
    assert_includes @database.collection("profiles").indexes.create_one_calls, [{"owner_ref" => 1}, {}]
    assert_includes @database.collection("profiles").indexes.create_one_calls, [{"profile_handle" => 1}, {unique: true}]
  end

  def test_mongodb_adapter_maps_id_to_bson_id_and_returns_logical_fields
    user = @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    stored = @database.collection("user").documents.first

    assert_equal "user-1", user["id"]
    assert_equal "user-1", stored.fetch("_id")
    refute stored.key?("id")
    assert_equal false, user["emailVerified"]
    assert_equal "ada@example.com", @adapter.find_one(model: "user", where: [{field: "id", value: "user-1"}])["email"]
  end

  def test_mongodb_adapter_generates_object_id_documents_by_default
    user = @adapter.create(model: "user", data: {name: "Ada", email: "ada@example.com"})
    stored = @database.collection("user").documents.first

    assert_instance_of BSON::ObjectId, stored.fetch("_id")
    assert_equal stored.fetch("_id").to_s, user.fetch("id")
  end

  def test_mongodb_adapter_stores_uuid_generated_ids_as_bson_binary_uuid
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, advanced: {database: {generate_id: "uuid"}})
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)

    user = adapter.create(model: "user", data: {name: "Ada", email: "ada@example.com"})
    stored = @database.collection("user").documents.first

    assert_instance_of BSON::Binary, stored.fetch("_id")
    assert_equal :uuid, stored.fetch("_id").type
    assert_match(/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i, user.fetch("id"))
    assert_equal stored.fetch("_id").to_uuid, user.fetch("id")
  end

  def test_mongodb_adapter_stores_uuid_foreign_keys_as_bson_binary_uuid
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, advanced: {database: {generate_id: "uuid"}})
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)
    user_id = "550e8400-e29b-41d4-a716-446655440000"

    session = adapter.create(model: "session", data: {token: "token-1", userId: user_id, expiresAt: Time.now + 60})
    stored = @database.collection("session").documents.first

    assert_instance_of BSON::Binary, stored.fetch("_id")
    assert_instance_of BSON::Binary, stored.fetch("user_id")
    assert_equal :uuid, stored.fetch("user_id").type
    assert_equal user_id, stored.fetch("user_id").to_uuid
    assert_equal user_id, session.fetch("userId")
  end

  def test_mongodb_adapter_converts_bson_uuid_values_to_logical_strings
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, advanced: {database: {generate_id: "uuid"}})
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)
    user_id = "550e8400-e29b-41d4-a716-446655440000"
    session_id = "660e8400-e29b-41d4-a716-446655440001"
    @database.collection("session").insert_one(
      "_id" => BSON::Binary.from_uuid(session_id),
      "token" => "token-1",
      "user_id" => BSON::Binary.from_uuid(user_id),
      "expires_at" => Time.now + 60
    )

    session = adapter.find_one(model: "session", where: [{field: "id", value: session_id}])

    assert_equal session_id, session.fetch("id")
    assert_equal user_id, session.fetch("userId")
  end

  def test_mongodb_adapter_keeps_callable_custom_ids_as_plain_values
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, advanced: {database: {generate_id: -> { "custom-user-1" }}})
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)

    user = adapter.create(model: "user", data: {name: "Ada", email: "ada@example.com"})
    stored = @database.collection("user").documents.first

    assert_equal "custom-user-1", user.fetch("id")
    assert_equal "custom-user-1", stored.fetch("_id")
  end

  def test_mongodb_adapter_keeps_non_string_callable_custom_ids_as_plain_values
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, advanced: {database: {generate_id: -> { 42 }}})
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)

    user = adapter.create(model: "user", data: {name: "Ada", email: "ada@example.com"})
    stored = @database.collection("user").documents.first

    assert_equal 42, user.fetch("id")
    assert_equal 42, stored.fetch("_id")
  end

  def test_mongodb_adapter_supports_where_connectors_sort_limit_offset_and_count
    @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    @adapter.create(model: "user", data: {id: "user-2", name: "Grace", email: "grace@example.com"}, force_allow_id: true)
    @adapter.create(model: "user", data: {id: "user-3", name: "Linus", email: "linus@example.net"}, force_allow_id: true)

    matches = @adapter.find_many(
      model: "user",
      where: [
        {field: "email", operator: "ends_with", value: "example.net", connector: "OR"},
        {field: "name", connector: "OR", value: "Grace"}
      ],
      sort_by: {field: "email", direction: "desc"},
      limit: 2
    )

    assert_equal ["user-3", "user-2"], matches.map { |user| user["id"] }
    assert_equal 2, @adapter.count(model: "user", where: [{field: "email", operator: "ends_with", value: "example.com"}])
  end

  def test_mongodb_find_many_applies_default_limit_when_omitted
    5.times do |index|
      @adapter.create(model: "user", data: {id: "user-#{index}", name: "User #{index}", email: "user-#{index}@example.com"}, force_allow_id: true)
    end

    @adapter.find_many(model: "user", where: [])

    pipeline = @database.collection("user").aggregate_pipelines.last.first
    assert_equal({"$limit" => 100}, pipeline.last)

    database = FakeMongoDatabase.new
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, advanced: {database: {default_find_many_limit: 3}})
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: database)
    5.times do |index|
      adapter.create(model: "user", data: {id: "limited-user-#{index}", name: "User #{index}", email: "limited-#{index}@example.com"}, force_allow_id: true)
    end

    matches = adapter.find_many(model: "user", where: [])

    assert_equal 3, matches.length
    assert_equal({"$limit" => 3}, database.collection("user").aggregate_pipelines.last.first.last)
  end

  def test_mongodb_join_one_to_many_uses_default_find_many_limit
    database = FakeMongoDatabase.new
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, advanced: {database: {default_find_many_limit: 3}})
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: database)
    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    5.times do |index|
      adapter.create(model: "session", data: {id: "session-#{index}", token: "token-#{index}", userId: user.fetch("id"), expiresAt: Time.now + 60}, force_allow_id: true)
    end

    found = adapter.find_one(model: "user", where: [{field: "id", value: user.fetch("id")}], join: {session: true})

    assert_equal 3, found.fetch("session").length
    lookup = database.collection("user").aggregate_pipelines.last.first.find { |stage| stage.key?("$lookup") }.fetch("$lookup")
    assert_equal({"$limit" => 3}, lookup.fetch("pipeline").last)
  end

  def test_mongodb_joined_queries_limit_base_records_before_lookup
    3.times do |index|
      user = @adapter.create(model: "user", data: {id: "user-#{index}", name: "User #{index}", email: "user-#{index}@example.com"}, force_allow_id: true)
      @adapter.create(model: "session", data: {id: "session-#{index}", token: "token-#{index}", userId: user.fetch("id"), expiresAt: Time.now + 60}, force_allow_id: true)
    end

    @adapter.find_one(model: "user", join: {session: true})
    find_one_pipeline = @database.collection("user").aggregate_pipelines.last.first
    assert_operator find_one_pipeline.index { |stage| stage.key?("$limit") }, :<, find_one_pipeline.index { |stage| stage.key?("$lookup") }

    @adapter.find_many(model: "user", join: {session: true}, sort_by: {field: "email", direction: "asc"}, offset: 1, limit: 1)
    find_many_pipeline = @database.collection("user").aggregate_pipelines.last.first
    lookup_index = find_many_pipeline.index { |stage| stage.key?("$lookup") }
    assert_operator find_many_pipeline.index { |stage| stage.key?("$sort") }, :<, lookup_index
    assert_operator find_many_pipeline.index { |stage| stage.key?("$skip") }, :<, lookup_index
    assert_operator find_many_pipeline.index { |stage| stage.key?("$limit") }, :<, lookup_index
  end

  def test_mongodb_adapter_rejects_invalid_limits_and_offsets
    assert_bad_request { @adapter.find_many(model: "user", limit: 0) }
    assert_bad_request { @adapter.find_many(model: "user", limit: -1) }
    assert_bad_request { @adapter.find_many(model: "user", offset: -1) }
    assert_bad_request { @adapter.find_many(model: "user", join: {session: {limit: 0}}) }
    assert_bad_request { @adapter.find_many(model: "user", join: {session: {limit: -1}}) }

    database = FakeMongoDatabase.new
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, advanced: {database: {default_find_many_limit: 0}})
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: database)

    adapter.find_many(model: "user")

    assert_equal({"$limit" => 100}, database.collection("user").aggregate_pipelines.last.first.last)
  end

  def test_mongodb_where_connectors_use_upstream_and_or_buckets
    @adapter.find_many(
      model: "user",
      where: [
        {field: "email", operator: "ends_with", value: "example.com"},
        {field: "name", connector: "OR", value: "Grace"},
        {field: "emailVerified", value: false, connector: "AND"}
      ]
    )

    match = @database.collection("user").aggregate_pipelines.last.first.first.fetch("$match")
    assert_equal(
      {
        "$and" => [
          {"email" => Regexp.new("example\\.com\\z")},
          {"email_verified" => false}
        ],
        "$or" => [
          {"name" => "Grace"}
        ]
      },
      match
    )
  end

  def test_mongodb_adapter_supports_case_insensitive_where_modes_and_regex_escaping
    @adapter.create(model: "user", data: {id: "user-1", name: "A.da", email: "ADA+test@example.com"}, force_allow_id: true)
    @adapter.create(model: "user", data: {id: "user-2", name: "Grace", email: "grace@example.net"}, force_allow_id: true)

    eq_matches = @adapter.find_many(model: "user", where: [{field: "email", mode: "insensitive", value: "ada+TEST@example.com"}])
    contains_matches = @adapter.find_many(model: "user", where: [{field: "name", operator: "contains", mode: "insensitive", value: "."}])
    not_in_matches = @adapter.find_many(model: "user", where: [{field: "email", operator: "not_in", mode: "insensitive", value: ["ADA+TEST@example.com"]}])

    assert_equal ["user-1"], eq_matches.map { |user| user["id"] }
    assert_equal ["user-1"], contains_matches.map { |user| user["id"] }
    assert_equal ["user-2"], not_in_matches.map { |user| user["id"] }
  end

  def test_mongodb_adapter_preserves_false_where_values
    verified = @adapter.create(model: "user", data: {id: "user-true", name: "Verified", email: "verified@example.com"}, force_allow_id: true)
    unverified = @adapter.create(model: "user", data: {id: "user-false", name: "Unverified", email: "unverified@example.com"}, force_allow_id: true)
    @adapter.update(model: "user", where: [{field: "id", value: verified.fetch("id")}], update: {emailVerified: true})

    string_key_matches = @adapter.find_many(model: "user", where: [{"field" => "emailVerified", "value" => false}])
    symbol_key_matches = @adapter.find_many(model: "user", where: [{field: "emailVerified", value: false}])

    assert_equal [unverified.fetch("id")], string_key_matches.map { |user| user.fetch("id") }
    assert_equal [unverified.fetch("id")], symbol_key_matches.map { |user| user.fetch("id") }
  end

  def test_mongodb_adapter_rejects_unsupported_where_operators
    error = assert_raises(BetterAuth::Adapters::MongoDB::MongoAdapterError) do
      @adapter.find_many(model: "user", where: [{field: "email", operator: "matches", value: "ada"}])
    end

    assert_equal "UNSUPPORTED_OPERATOR", error.code
  end

  def test_mongodb_adapter_rejects_invalid_non_string_id_query_values
    error = assert_raises(BetterAuth::Adapters::MongoDB::MongoAdapterError) do
      @adapter.find_one(model: "user", where: [{field: "id", value: 123}])
    end

    assert_equal "INVALID_ID", error.code
  end

  def test_mongodb_adapter_rejects_malformed_where_and_join_inputs
    assert_bad_request { @adapter.find_many(model: "user", where: [nil]) }
    assert_bad_request { @adapter.find_many(model: "user", where: "bad") }
    assert_bad_request { @adapter.find_many(model: "user", join: true) }
    assert_bad_request { @adapter.find_many(model: "user", join: {session: {on: {from: "id"}}}) }
  end

  def test_mongodb_adapter_supports_select_update_update_many_delete_and_delete_many
    @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    @adapter.create(model: "user", data: {id: "user-2", name: "Grace", email: "grace@example.com"}, force_allow_id: true)
    @adapter.create(model: "user", data: {id: "user-3", name: "Linus", email: "linus@example.net"}, force_allow_id: true)

    selected = @adapter.find_one(model: "user", where: [{field: "id", value: "user-1"}], select: ["email"])
    updated = @adapter.update(model: "user", where: [{field: "id", value: "user-1"}], update: {name: "Augusta"})
    update_count = @adapter.update_many(model: "user", where: [{field: "email", operator: "ends_with", value: "example.com"}], update: {emailVerified: true})
    delete_result = @adapter.delete(model: "user", where: [{field: "id", value: "user-3"}])
    delete_count = @adapter.delete_many(model: "user", where: [{field: "emailVerified", value: true}])

    assert_equal({"email" => "ada@example.com"}, selected)
    assert_equal 0, @database.collection("user").aggregate_pipelines.last.first.find { |stage| stage.key?("$project") }.fetch("$project").fetch("_id")
    assert_equal "Augusta", updated.fetch("name")
    assert_equal 2, update_count
    assert_nil delete_result
    assert_equal 2, delete_count
    assert_equal 0, @adapter.count(model: "user")
  end

  def test_mongodb_adapter_updates_models_with_value_fields
    @adapter.create(model: "verification", data: {id: "verification-1", identifier: "email", value: "old", expiresAt: Time.now + 60}, force_allow_id: true)

    updated = @adapter.update(model: "verification", where: [{field: "id", value: "verification-1"}], update: {value: "new"})

    assert_equal "verification-1", updated.fetch("id")
    assert_equal "new", updated.fetch("value")
  end

  def test_mongodb_adapter_rejects_empty_update_payloads_before_calling_mongo
    @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    collection = @database.collection("user")

    assert_bad_request { @adapter.update(model: "user", where: [{field: "id", value: "user-1"}], update: {id: "ignored"}) }
    assert_bad_request { @adapter.update(model: "user", where: [{field: "id", value: "user-1"}], update: {id: nil}) }
    assert_bad_request { @adapter.update_many(model: "user", where: [], update: {unknownField: "ignored"}) }

    assert_empty collection.find_one_and_update_calls
    assert_empty collection.update_many_calls
  end

  def test_mongodb_adapter_strips_id_from_valid_update_payloads
    @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)

    @adapter.update(model: "user", where: [{field: "id", value: "user-1"}], update: {id: "attempted-change", name: "Augusta"})

    update_doc = @database.collection("user").find_one_and_update_calls.last[1].fetch("$set")
    refute update_doc.key?("_id")
    assert_equal "Augusta", update_doc.fetch("name")
  end

  def test_mongodb_adapter_rejects_invalid_date_strings
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      user: {
        additional_fields: {
          dateField: {type: "date", required: false}
        }
      }
    )
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)

    assert_bad_request do
      adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com", dateField: "not-a-date"}, force_allow_id: true)
    end
  end

  def test_mongodb_adapter_supports_core_joins
    user = @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    session = @adapter.create(model: "session", data: {id: "session-1", token: "token-1", userId: user["id"], expiresAt: Time.now + 60}, force_allow_id: true)
    @adapter.create(model: "account", data: {id: "account-1", userId: user["id"], providerId: "github", accountId: "gh-1"}, force_allow_id: true)

    found_session = @adapter.find_one(model: "session", where: [{field: "token", value: session["token"]}], join: {user: true})
    found_user = @adapter.find_one(model: "user", where: [{field: "id", value: user["id"]}], join: {account: true})

    assert_equal "Ada", found_session["user"]["name"]
    assert_equal ["github"], found_user["account"].map { |account| account["providerId"] }
  end

  def test_mongodb_adapter_supports_upstream_style_join_config
    user = @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    @adapter.create(model: "session", data: {id: "session-1", token: "token-1", userId: user["id"], expiresAt: Time.now + 60}, force_allow_id: true)
    @adapter.create(model: "session", data: {id: "session-2", token: "token-2", userId: user["id"], expiresAt: Time.now + 60}, force_allow_id: true)

    found = @adapter.find_one(
      model: "user",
      where: [{field: "id", value: user["id"]}],
      join: {
        session: {
          on: {from: "id", to: "userId"},
          relation: "one-to-many",
          limit: 1
        }
      }
    )

    assert_equal ["token-1"], found["session"].map { |session| session["token"] }
  end

  def test_mongodb_adapter_persists_auth_routes_and_get_session_reads_database_rows
    require "mongo"

    client = real_mongo_client("better-auth-ruby-test")
    drop_real_database(client)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: ->(options) { BetterAuth::Adapters::MongoDB.new(options, database: client.database, client: client, transaction: false) },
      email_and_password: {enabled: true},
      session: {cookie_cache: {enabled: false}}
    )

    status, headers, body = auth.api.sign_up_email(
      body: {email: "mongodb-route@example.com", password: "password123", name: "MongoDB Route"},
      as_response: true
    )
    payload = JSON.parse(body.join)
    token = payload.fetch("token")
    user_id = payload.fetch("user").fetch("id")

    assert_equal 200, status
    assert_equal "mongodb-route@example.com", client.database.collection("user").find(_id: mongo_object_id(user_id)).first.fetch("email")
    assert_equal "credential", client.database.collection("account").find(user_id: mongo_object_id(user_id)).first.fetch("provider_id")
    assert_equal mongo_object_id(user_id), client.database.collection("session").find(token: token).first.fetch("user_id")

    client.database.collection("user").find(_id: mongo_object_id(user_id)).update_one("$set" => {name: "MongoDB Direct Update"})
    session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})

    assert_equal token, session[:session]["token"]
    assert_equal user_id, session[:session]["userId"]
    assert_equal "MongoDB Direct Update", session[:user]["name"]
  rescue LoadError
    skip "mongo gem is not installed"
  rescue Mongo::Error::NoServerAvailable, Mongo::Error::SocketError
    skip "MongoDB test service is not available"
  ensure
    client&.close
  end

  def test_mongodb_adapter_real_mongo_native_update_delete_count_and_object_id_update
    require "mongo"

    client = real_mongo_client("better-auth-ruby-native-test")
    drop_real_database(client)
    adapter = BetterAuth::Adapters::MongoDB.new(@config, database: client.database, client: client, transaction: false)

    user = adapter.create(model: "user", data: {name: "Ada", email: "ada-native@example.com"})
    session = adapter.create(model: "session", data: {token: "native-token", userId: user.fetch("id"), expiresAt: Time.now + 60})
    stored_session = client.database.collection("session").find(_id: mongo_object_id(session.fetch("id"))).first
    assert_instance_of BSON::ObjectId, stored_session.fetch("user_id")

    updated = adapter.update(model: "session", where: [{field: "id", value: session.fetch("id")}], update: session.merge("expiresAt" => Time.now + 120, "id" => nil))
    stored_after_update = client.database.collection("session").find(_id: mongo_object_id(session.fetch("id"))).first

    assert_equal session.fetch("id"), updated.fetch("id")
    assert_instance_of BSON::ObjectId, stored_after_update.fetch("user_id")

    adapter.create(model: "user", data: {name: "Grace", email: "grace-native@example.com"})
    assert_equal 2, adapter.count(model: "user", where: [{field: "email", operator: "ends_with", value: "native@example.com"}])
    assert_equal 2, adapter.update_many(model: "user", where: [{field: "email", operator: "ends_with", value: "native@example.com"}], update: {emailVerified: true})
    assert_equal 2, adapter.delete_many(model: "user", where: [{field: "emailVerified", value: true}])
    assert_equal 0, adapter.count(model: "user")
  rescue LoadError
    skip "mongo gem is not installed"
  rescue Mongo::Error::NoServerAvailable, Mongo::Error::SocketError
    skip "MongoDB test service is not available"
  ensure
    client&.close
  end

  def test_mongodb_adapter_real_mongo_auth_flow_parity
    require "mongo"

    client = real_mongo_client("better-auth-ruby-auth-flow-test")
    drop_real_database(client)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: ->(options) { BetterAuth::Adapters::MongoDB.new(options, database: client.database, client: client, transaction: false) },
      email_and_password: {
        enabled: true,
        password: {
          hash: ->(password) { password },
          verify: ->(data) { data[:hash] == data[:password] || data["hash"] == data["password"] }
        }
      },
      user: {
        additional_fields: {
          dateField: {type: "date", required: false}
        }
      },
      session: {cookie_cache: {enabled: false}}
    )

    date_field = Time.now
    status, headers, body = auth.api.sign_up_email(
      body: {email: "auth-flow@example.com", password: "password123", name: "Auth Flow", dateField: date_field.iso8601},
      as_response: true
    )
    payload = JSON.parse(body.join)

    assert_equal 200, status
    assert_equal "auth-flow@example.com", payload.fetch("user").fetch("email")

    sign_in = auth.api.sign_in_email(body: {email: "auth-flow@example.com", password: "password123"})
    assert_equal payload.fetch("user").fetch("id"), sign_in.fetch(:user).fetch("id")

    assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_email(body: {email: "missing-auth-flow@example.com", password: "password123"})
    end

    original_tz = ENV["TZ"]
    ENV["TZ"] = "Europe/London"
    london_session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})
    ENV["TZ"] = "America/Los_Angeles"
    pacific_session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})

    assert_equal london_session[:user]["createdAt"].iso8601, pacific_session[:user]["createdAt"].iso8601
    assert_equal date_field.to_i, london_session[:user]["dateField"].to_i
  rescue LoadError
    skip "mongo gem is not installed"
  rescue Mongo::Error::NoServerAvailable, Mongo::Error::SocketError
    skip "MongoDB test service is not available"
  ensure
    ENV["TZ"] = original_tz
    client&.close
  end

  def test_mongodb_adapter_real_mongo_transaction_rollback_when_replica_set_url_is_configured
    require "mongo"

    url = ENV["BETTER_AUTH_MONGODB_REPLICA_SET_URL"]
    skip "BETTER_AUTH_MONGODB_REPLICA_SET_URL is not configured" unless url && !url.empty?

    client = Mongo::Client.new(url, database: "better-auth-ruby-transaction-test", server_selection_timeout: 1)
    drop_real_database(client)
    adapter = BetterAuth::Adapters::MongoDB.new(@config, database: client.database, client: client, transaction: true)

    assert_raises(RuntimeError) do
      adapter.transaction do |transaction_adapter|
        transaction_adapter.create(model: "user", data: {id: "rolled-back-user", name: "Rollback", email: "rollback@example.com"}, force_allow_id: true)
        raise "rollback"
      end
    end

    assert_equal 0, adapter.count(model: "user")
  rescue LoadError
    skip "mongo gem is not installed"
  rescue Mongo::Error::NoServerAvailable, Mongo::Error::SocketError
    skip "MongoDB replica set test service is not available"
  ensure
    client&.close
  end

  def test_mongodb_adapter_wraps_operations_in_client_transaction_when_enabled
    database = FakeMongoDatabase.new
    client = FakeMongoClient.new
    adapter = BetterAuth::Adapters::MongoDB.new(@config, database: database, client: client)

    adapter.transaction do |transaction_adapter|
      transaction_adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    end

    assert_equal 1, client.sessions.length
    session = client.sessions.first
    assert_equal false, session.started
    assert_equal true, session.committed
    assert_equal false, session.aborted
    assert_equal true, session.ended
    assert_equal session, database.collection("user").insert_options.first.fetch(:session)
  end

  def test_mongodb_adapter_fake_transaction_rolls_back_staged_mutations_and_records_session_options
    database = FakeMongoDatabase.new
    client = FakeMongoClient.new
    adapter = BetterAuth::Adapters::MongoDB.new(@config, database: database, client: client)
    adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    adapter.create(model: "user", data: {id: "user-2", name: "Grace", email: "grace@example.com"}, force_allow_id: true)

    assert_raises(RuntimeError) do
      adapter.transaction do |transaction_adapter|
        transaction_adapter.create(model: "user", data: {id: "user-3", name: "Linus", email: "linus@example.com"}, force_allow_id: true)
        transaction_adapter.update(model: "user", where: [{field: "id", value: "user-1"}], update: {name: "Changed"})
        transaction_adapter.update_many(model: "user", where: [{field: "email", operator: "ends_with", value: "example.com"}], update: {emailVerified: true})
        assert_equal 3, transaction_adapter.count(model: "user")
        transaction_adapter.delete(model: "user", where: [{field: "id", value: "user-2"}])
        assert_equal 2, transaction_adapter.count(model: "user")
        raise "rollback"
      end
    end

    collection = database.collection("user")
    session = client.sessions.first
    assert_equal true, session.aborted
    assert_equal true, session.ended
    assert_equal session, collection.insert_options.last.fetch(:session)
    assert_equal session, collection.find_one_and_update_calls.first[2].fetch(:session)
    assert_equal session, collection.update_many_calls.first[2].fetch(:session)
    assert_equal session, collection.delete_one_calls.first[1].fetch(:session)
    assert collection.aggregate_pipelines.any? { |_pipeline, options| options[:session] == session }
    assert_equal ["user-1", "user-2"], collection.documents.map { |document| document.fetch("_id") }
    assert_equal "Ada", adapter.find_one(model: "user", where: [{field: "id", value: "user-1"}]).fetch("name")
    assert_equal false, adapter.find_one(model: "user", where: [{field: "id", value: "user-1"}]).fetch("emailVerified")
    assert_equal "Grace", adapter.find_one(model: "user", where: [{field: "id", value: "user-2"}]).fetch("name")
    assert_nil adapter.find_one(model: "user", where: [{field: "id", value: "user-3"}])
  end

  def test_mongodb_adapter_uses_schema_model_and_field_names
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      user: {
        model_name: "people",
        fields: {
          email: "email_address"
        }
      }
    )
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)

    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    stored = @database.collection("people").documents.first

    assert_equal "ada@example.com", user.fetch("email")
    assert_equal "ada@example.com", stored.fetch("email_address")
    assert_nil @database.collection("user").documents.first
    assert_equal "Ada", adapter.find_one(model: "user", where: [{field: "email", value: "ada@example.com"}]).fetch("name")
  end

  def test_mongodb_adapter_matches_upstream_where_coercions_and_json_storage
    plugin = {
      id: "parity-fields",
      schema: {
        typedModel: {
          fields: {
            jsonData: {type: "json", required: false},
            score: {type: "number", required: false, defaultValue: 7},
            enabled: {type: "boolean", required: false, defaultValue: false},
            nullableReference: {type: "string", required: false, references: {model: "user", field: "id"}}
          }
        }
      }
    }
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: [plugin])
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)

    record = adapter.create(
      model: "typedModel",
      data: {
        jsonData: {"theme" => "dark"},
        nullableReference: nil
      }
    )
    stored = @database.collection("typedModel").documents.first

    assert_equal({"theme" => "dark"}, record.fetch("jsonData"))
    assert_equal JSON.generate("theme" => "dark"), stored.fetch("json_data")
    assert_nil stored.fetch("nullable_reference")

    adapter.find_many(model: "typedModel", where: [{field: "score", value: "7"}])
    assert_equal({"score" => 7}, @database.collection("typedModel").aggregate_pipelines.last.first.first.fetch("$match"))

    adapter.find_many(model: "typedModel", where: [{field: "enabled", value: "false"}])
    assert_equal({"enabled" => false}, @database.collection("typedModel").aggregate_pipelines.last.first.first.fetch("$match"))

    adapter.find_many(model: "typedModel", where: [{field: "score", operator: "in", value: ["7", "8"]}])
    assert_equal({"score" => {"$in" => [7, 8]}}, @database.collection("typedModel").aggregate_pipelines.last.first.first.fetch("$match"))

    assert_bad_request do
      adapter.find_many(model: "typedModel", where: [{field: "score", operator: "in", value: "7"}])
    end

    adapter.find_many(model: "typedModel", where: [{field: "score", operator: "not_in", value: "8"}])
    assert_equal({"score" => {"$nin" => [8]}}, @database.collection("typedModel").aggregate_pipelines.last.first.first.fetch("$match"))
  end

  def test_mongodb_adapter_stores_default_plugin_fields_as_snake_case
    plugin = {
      id: "storage-name-parity",
      schema: {
        storageModel: {
          fields: {
            camelCaseField: {type: "string", required: false}
          }
        }
      }
    }
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: [plugin])
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)

    adapter.create(model: "storageModel", data: {camelCaseField: "value"})
    stored = @database.collection("storageModel").documents.first

    assert_equal "value", stored.fetch("camel_case_field")
    refute stored.key?("camelCaseField")
  end

  def test_mongodb_adapter_infers_schema_driven_one_to_one_joins_and_empty_join_values
    plugin = {
      id: "join-parity",
      schema: {
        oneToOneTable: {
          fields: {
            oneToOne: {type: "string", required: true, references: {model: "user", field: "id"}, unique: true}
          }
        }
      }
    }
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: [plugin])
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)
    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    joined = adapter.create(model: "oneToOneTable", data: {oneToOne: user.fetch("id")})

    found = adapter.find_one(model: "user", where: [{field: "id", value: user.fetch("id")}], join: {oneToOneTable: true, session: true})

    assert_equal joined.fetch("id"), found.fetch("oneToOneTable").fetch("id")
    assert_equal [], found.fetch("session")

    missing_user = adapter.create(model: "user", data: {id: "user-2", name: "Grace", email: "grace@example.com"}, force_allow_id: true)
    missing = adapter.find_one(model: "user", where: [{field: "id", value: missing_user.fetch("id")}], join: {oneToOneTable: true})

    assert_nil missing.fetch("oneToOneTable")
  end

  def test_mongodb_adapter_infers_schema_driven_custom_field_joins
    plugin = {
      id: "custom-join-parity",
      schema: {
        profile: {
          modelName: "user_profile",
          fields: {
            ownerEmail: {type: "string", required: true, fieldName: "owner_email", references: {model: "user", field: "email"}, unique: true}
          }
        }
      }
    }
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [plugin],
      user: {
        fields: {
          email: "email_address"
        }
      }
    )
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)
    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    profile = adapter.create(model: "profile", data: {ownerEmail: user.fetch("email")})

    found = adapter.find_one(model: "user", where: [{field: "id", value: user.fetch("id")}], join: {profile: true})

    assert_equal profile.fetch("id"), found.fetch("profile").fetch("id")
    assert_equal "ada@example.com", @database.collection("user_profile").documents.first.fetch("owner_email")
  end

  def test_mongodb_adapter_rejects_missing_and_ambiguous_schema_joins
    ambiguous_plugin = {
      id: "ambiguous-join-parity",
      schema: {
        ambiguousProfile: {
          fields: {
            primaryUserId: {type: "string", required: true, references: {model: "user", field: "id"}},
            secondaryUserId: {type: "string", required: true, references: {model: "user", field: "id"}}
          }
        },
        unrelatedProfile: {
          fields: {
            label: {type: "string", required: false}
          }
        }
      }
    }
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: [ambiguous_plugin])
    adapter = BetterAuth::Adapters::MongoDB.new(config, database: @database)

    assert_raises(BetterAuth::Error) do
      adapter.find_one(model: "user", where: [{field: "id", value: "missing"}], join: {unrelatedProfile: true})
    end

    assert_raises(BetterAuth::Error) do
      adapter.find_one(model: "user", where: [{field: "id", value: "missing"}], join: {ambiguousProfile: true})
    end
  end

  def test_mongodb_adapter_escapes_regex_literals_for_each_string_operator
    starts = @adapter.create(model: "user", data: {id: "user-1", name: ".*danger", email: "start@example.com"}, force_allow_id: true)
    ends = @adapter.create(model: "user", data: {id: "user-2", name: "danger.*", email: "end@example.com"}, force_allow_id: true)
    contains = @adapter.create(model: "user", data: {id: "user-3", name: "prefix-.*-suffix", email: "contains@example.com"}, force_allow_id: true)
    @adapter.create(model: "user", data: {id: "user-4", name: "ordinary", email: "ordinary@example.com"}, force_allow_id: true)

    assert_equal [starts.fetch("id")], @adapter.find_many(model: "user", where: [{field: "name", operator: "starts_with", value: ".*"}]).map { |user| user.fetch("id") }
    assert_equal [ends.fetch("id")], @adapter.find_many(model: "user", where: [{field: "name", operator: "ends_with", value: ".*"}]).map { |user| user.fetch("id") }
    assert_equal [contains.fetch("id")], @adapter.find_many(model: "user", where: [{field: "name", operator: "contains", value: "-.*-"}]).map { |user| user.fetch("id") }
  end

  private

  def mongo_object_id(value)
    BSON::ObjectId.from_string(value)
  rescue BSON::Error::InvalidObjectId
    value
  end

  def real_mongo_client(database_name)
    Mongo::Client.new(ENV.fetch("BETTER_AUTH_MONGODB_URL", "mongodb://127.0.0.1:27017/#{database_name}"), server_selection_timeout: 1)
  end

  def drop_real_database(client)
    client.database.collections.each(&:drop)
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end

  def assert_bad_request(&block)
    error = assert_raises(BetterAuth::APIError, &block)
    assert_equal "BAD_REQUEST", error.status
    error
  end
end

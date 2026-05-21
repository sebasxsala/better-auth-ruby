# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthMemoryAdapterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def setup
    @config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    @adapter = BetterAuth::Adapters::Memory.new(@config)
  end

  def test_create_applies_defaults_generates_ids_and_preserves_camel_case_fields
    user = @adapter.create(model: "user", data: {name: "Ada", email: "ADA@example.com"})

    assert_kind_of String, user["id"]
    assert_equal "Ada", user["name"]
    assert_equal "ADA@example.com", user["email"]
    assert_equal false, user["emailVerified"]
    assert_nil user["image"]
    assert_kind_of Time, user["createdAt"]
    assert_kind_of Time, user["updatedAt"]
  end

  def test_find_many_supports_where_operators_sort_limit_offset_and_count
    3.times do |index|
      @adapter.create(model: "user", data: {
        id: "user-#{index}",
        name: "User #{index}",
        email: "user#{index}@example.com"
      }, force_allow_id: true)
    end

    matches = @adapter.find_many(
      model: "user",
      where: [{field: "id", operator: "in", value: ["user-0", "user-2"]}],
      sort_by: {field: "email", direction: "desc"},
      limit: 1,
      offset: 0
    )

    assert_equal ["user-2"], matches.map { |user| user["id"] }
    assert_equal 3, @adapter.count(model: "user", where: [{field: "email", operator: "contains", value: "@example.com"}])
  end

  def test_serial_ids_are_generated_as_numbers_and_coerced_in_where_values
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, advanced: {database: {generate_id: "serial"}})
    adapter = BetterAuth::Adapters::Memory.new(config)

    first = adapter.create(model: "user", data: {name: "Ada", email: "ada@example.com"})
    second = adapter.create(model: "user", data: {name: "Grace", email: "grace@example.com"})
    session = adapter.create(model: "session", data: {userId: "1", token: "token-1", expiresAt: Time.now + 60})

    assert_equal 1, first["id"]
    assert_equal 2, second["id"]
    assert_equal first, adapter.find_one(model: "user", where: [{field: "id", value: "1"}])
    assert_equal session, adapter.find_one(model: "session", where: [{field: "userId", value: 1}])
  end

  def test_find_many_supports_case_insensitive_string_where_modes
    @adapter.create(model: "user", data: {id: "user-1", name: "Ada Lovelace", email: "Ada@Example.com"}, force_allow_id: true)
    @adapter.create(model: "user", data: {id: "user-2", name: "Grace Hopper", email: "grace@example.com"}, force_allow_id: true)

    eq = @adapter.find_many(model: "user", where: [{field: "email", value: "ada@example.com", mode: "insensitive"}])
    in_values = @adapter.find_many(model: "user", where: [{field: "email", operator: "in", value: ["ADA@EXAMPLE.COM"], mode: "insensitive"}])
    contains = @adapter.find_many(model: "user", where: [{field: "name", operator: "contains", value: "love", mode: "insensitive"}])
    starts_with = @adapter.find_many(model: "user", where: [{field: "name", operator: "starts_with", value: "ada", mode: "insensitive"}])
    not_in = @adapter.find_many(model: "user", where: [{field: "email", operator: "not_in", value: ["GRACE@EXAMPLE.COM"], mode: "insensitive"}])

    assert_equal ["user-1"], eq.map { |user| user["id"] }
    assert_equal ["user-1"], in_values.map { |user| user["id"] }
    assert_equal ["user-1"], contains.map { |user| user["id"] }
    assert_equal ["user-1"], starts_with.map { |user| user["id"] }
    assert_equal ["user-1"], not_in.map { |user| user["id"] }
  end

  def test_find_many_preserves_false_where_values
    verified = @adapter.create(model: "user", data: {id: "user-true", name: "Verified", email: "verified@example.com"}, force_allow_id: true)
    unverified = @adapter.create(model: "user", data: {id: "user-false", name: "Unverified", email: "unverified@example.com"}, force_allow_id: true)
    @adapter.update(model: "user", where: [{field: "id", value: verified.fetch("id")}], update: {emailVerified: true})

    matches = @adapter.find_many(model: "user", where: [{"field" => "emailVerified", "value" => false}])

    assert_equal [unverified.fetch("id")], matches.map { |user| user.fetch("id") }
  end

  def test_comparison_operators_do_not_match_nil_record_values
    expired = @adapter.create(model: "verification", data: {identifier: "expired", value: "value", expiresAt: Time.now - 60})
    future = @adapter.create(model: "verification", data: {identifier: "future", value: "value", expiresAt: Time.now + 60})
    no_expiry = @adapter.create(model: "verification", data: {identifier: "no-expiry", value: "value", expiresAt: nil})

    deleted = @adapter.delete_many(
      model: "verification",
      where: [
        {field: "expiresAt", value: Time.now, operator: "lt"},
        {field: "expiresAt", value: nil, operator: "ne"}
      ]
    )

    assert_equal 1, deleted
    assert_nil @adapter.find_one(model: "verification", where: [{field: "id", value: expired.fetch("id")}])
    refute_nil @adapter.find_one(model: "verification", where: [{field: "id", value: future.fetch("id")}])
    refute_nil @adapter.find_one(model: "verification", where: [{field: "id", value: no_expiry.fetch("id")}])
  end

  def test_update_delete_many_and_transaction_rollback
    user = @adapter.create(model: "user", data: {name: "Ada", email: "ada@example.com"})

    updated = @adapter.update(model: "user", where: [{field: "id", value: user["id"]}], update: {name: "Grace"})

    assert_equal "Grace", updated["name"]

    assert_raises(RuntimeError) do
      @adapter.transaction do |trx|
        trx.update_many(model: "user", where: [], update: {name: "Rolled Back"})
        raise "boom"
      end
    end

    assert_equal "Grace", @adapter.find_one(model: "user", where: [{field: "id", value: user["id"]}])["name"]
    assert_equal 1, @adapter.delete_many(model: "user", where: [{field: "id", value: user["id"]}])
    assert_nil @adapter.find_one(model: "user", where: [{field: "id", value: user["id"]}])
  end

  def test_update_many_returns_count_and_rejects_empty_updates
    @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    @adapter.create(model: "user", data: {id: "user-2", name: "Alan", email: "alan@example.com"}, force_allow_id: true)

    count = @adapter.update_many(model: "user", where: [], update: {image: "avatar.png"})

    assert_equal 2, count
    error = assert_raises(BetterAuth::APIError) do
      @adapter.update_many(model: "user", where: [], update: {unknown: "field"})
    end
    assert_equal "No fields to update", error.message
  end

  def test_find_one_with_join_returns_related_user
    user = @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    session = @adapter.create(
      model: "session",
      data: {userId: user["id"], token: "token-1", expiresAt: Time.now + 60},
      force_allow_id: true
    )

    found = @adapter.find_one(model: "session", where: [{field: "token", value: session["token"]}], join: {user: true})

    assert_equal session["token"], found["token"]
    assert_equal user, found["user"]
  end

  def test_find_one_with_join_infers_plugin_one_to_one_reference
    plugin = BetterAuth::Plugin.new(
      id: "profile",
      schema: {
        profile: {
          model_name: "profiles",
          fields: {
            userId: {type: "string", required: true, unique: true, references: {model: "user", field: "id"}},
            bio: {type: "string", required: false}
          }
        }
      }
    )
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: [plugin])
    adapter = BetterAuth::Adapters::Memory.new(config)
    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    profile = adapter.create(model: "profile", data: {userId: user["id"], bio: "hello"})

    found = adapter.find_one(model: "user", where: [{field: "id", value: user["id"]}], join: {profile: true})

    assert_equal profile, found["profile"]
  end

  def test_find_many_with_join_infers_plugin_collection_reference_and_honors_limit
    plugin = BetterAuth::Plugin.new(
      id: "audit",
      schema: {
        auditLog: {
          model_name: "audit_logs",
          fields: {
            userId: {type: "string", required: true, references: {model: "user", field: "id"}},
            action: {type: "string", required: true}
          }
        }
      }
    )
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: [plugin])
    adapter = BetterAuth::Adapters::Memory.new(config)
    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    first = adapter.create(model: "auditLog", data: {userId: user["id"], action: "first"})
    adapter.create(model: "auditLog", data: {userId: user["id"], action: "second"})

    found = adapter.find_one(model: "user", where: [{field: "id", value: user["id"]}], join: {auditLog: {limit: 1}})

    assert_equal [first], found["auditLog"]
  end

  def test_find_one_with_join_supports_explicit_join_configuration
    plugin = BetterAuth::Plugin.new(
      id: "profile",
      schema: {
        profile: {
          model_name: "profiles",
          fields: {
            ownerEmail: {type: "string", required: true, unique: true},
            bio: {type: "string", required: false}
          }
        }
      }
    )
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: [plugin])
    adapter = BetterAuth::Adapters::Memory.new(config)
    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    profile = adapter.create(model: "profile", data: {ownerEmail: user["email"], bio: "hello"})

    found = adapter.find_one(
      model: "user",
      where: [{field: "id", value: user["id"]}],
      join: {profile: {on: {from: "email", to: "ownerEmail"}, relation: "one-to-one"}}
    )

    assert_equal profile, found["profile"]
  end
end

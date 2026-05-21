# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe BetterAuth::Hanami::SequelAdapter do
  let(:secret) { "test-secret-that-is-long-enough-for-validation" }
  let(:config) { BetterAuth::Configuration.new(secret: secret, database: :memory, plugins: [plugin], experimental: {joins: true}) }
  let(:plugin) do
    BetterAuth::Plugin.new(
      id: "audit",
      schema: {
        auditLog: {
          model_name: "audit_logs",
          fields: {
            id: {type: "string", required: true},
            userId: {type: "string", references: {model: "user", field: "id", on_delete: "cascade"}, index: true},
            action: {type: "string", required: true, unique: true},
            attempts: {type: "number", required: true, default_value: 0},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }}
          }
        }
      }
    )
  end

  it "creates, queries, updates, joins, and deletes records using logical Better Auth fields" do
    db = Sequel.sqlite
    apply_migration(db, config)
    adapter = described_class.new(config, connection: db)

    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    session = adapter.create(model: "session", data: {id: "session-1", userId: "user-1", token: "token-1", expiresAt: Time.now + 3600}, force_allow_id: true)
    adapter.create(model: "auditLog", data: {id: "audit-1", userId: "user-1", action: "login"}, force_allow_id: true)
    adapter.create(model: "auditLog", data: {id: "audit-2", userId: "user-1", action: "logout", attempts: 2}, force_allow_id: true)

    selected = adapter.find_many(model: "auditLog", where: [{field: "action", operator: "contains", value: "log"}], select: ["id", "action"], sort_by: {field: "action", direction: "desc"}, limit: 1)
    joined = adapter.find_one(model: "session", where: [{field: "id", value: session.fetch("id")}], join: {user: true})
    updated = adapter.update_many(model: "auditLog", where: [{field: "userId", value: "user-1"}], update: {attempts: 3}, returning: true)
    count = adapter.count(model: "auditLog", where: [{field: "attempts", operator: "gte", value: 3}])
    adapter.delete(model: "auditLog", where: [{field: "id", value: "audit-1"}])

    expect(user).to include("id" => "user-1", "emailVerified" => false)
    expect(selected).to eq([{"id" => "audit-2", "action" => "logout"}])
    expect(joined.fetch("user")).to include("id" => "user-1", "email" => "ada@example.com")
    expect(updated.map { |row| row.fetch("attempts") }).to eq([3, 3])
    expect(count).to eq(2)
    expect(adapter.find_one(model: "auditLog", where: [{field: "id", value: "audit-1"}])).to be_nil
  end

  it "preserves false where values for boolean predicates" do
    db = Sequel.sqlite
    apply_migration(db, config)
    adapter = described_class.new(config, connection: db)
    verified = adapter.create(model: "user", data: {id: "user-true", name: "Verified", email: "verified@example.com"}, force_allow_id: true)
    unverified = adapter.create(model: "user", data: {id: "user-false", name: "Unverified", email: "unverified@example.com"}, force_allow_id: true)
    adapter.update(model: "user", where: [{field: "id", value: verified.fetch("id")}], update: {emailVerified: true})

    matches = adapter.find_many(model: "user", where: [{"field" => "emailVerified", "value" => false}])

    expect(matches.map { |user| user.fetch("id") }).to eq([unverified.fetch("id")])
  end

  it "persists and reads plugin json and array fields" do
    typed_plugin = BetterAuth::Plugin.new(
      id: "typed",
      schema: {
        testModel: {
          model_name: "test_models",
          fields: {
            id: {type: "string", required: true},
            metadata: {type: "json", required: true},
            tags: {type: "string[]", required: true},
            scores: {type: "number[]", required: true}
          }
        }
      }
    )
    typed_config = BetterAuth::Configuration.new(secret: secret, database: :memory, plugins: [typed_plugin])
    db = Sequel.sqlite
    apply_migration(db, typed_config)
    adapter = described_class.new(typed_config, connection: db)

    created = adapter.create(
      model: "testModel",
      data: {
        metadata: {"foo" => "bar"},
        tags: ["a", "b"],
        scores: [1, 2]
      }
    )
    reloaded = adapter.find_one(model: "testModel", where: [{field: "id", value: created.fetch("id")}])

    expect(created).to include(
      "metadata" => {"foo" => "bar"},
      "tags" => ["a", "b"],
      "scores" => [1, 2]
    )
    expect(reloaded).to eq(created)
  end

  it "joins plugin one-to-one models inferred from schema references" do
    one_to_one_plugin = BetterAuth::Plugin.new(
      id: "one-to-one",
      schema: {
        oneToOneTable: {
          model_name: "one_to_one_tables",
          fields: {
            id: {type: "string", required: true},
            oneToOne: {type: "string", required: true, references: {model: "user", field: "id"}, unique: true}
          }
        }
      }
    )
    join_config = BetterAuth::Configuration.new(secret: secret, database: :memory, plugins: [one_to_one_plugin], experimental: {joins: true})
    db = Sequel.sqlite
    apply_migration(db, join_config)
    adapter = described_class.new(join_config, connection: db)

    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    one_to_one = adapter.create(model: "oneToOneTable", data: {id: "one-1", oneToOne: user.fetch("id")}, force_allow_id: true)
    session = adapter.create(model: "session", data: {id: "session-1", userId: user.fetch("id"), token: "token-1", expiresAt: Time.now + 3600}, force_allow_id: true)

    joined = adapter.find_one(model: "user", where: [{field: "id", value: user.fetch("id")}], join: {oneToOneTable: true})
    joined_many = adapter.find_many(model: "user", where: [{field: "id", value: user.fetch("id")}], join: {oneToOneTable: true, session: true})

    expect(joined.fetch("oneToOneTable")).to eq(one_to_one)
    expect(joined_many).to eq([user.merge("oneToOneTable" => one_to_one, "session" => [session])])
  end

  it "preserves selected join keys while returning only requested base fields" do
    db = Sequel.sqlite
    apply_migration(db, config)
    adapter = described_class.new(config, connection: db)
    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    adapter.create(model: "session", data: {id: "session-1", userId: user.fetch("id"), token: "token-1", expiresAt: Time.now + 3600}, force_allow_id: true)

    joined = adapter.find_one(model: "user", where: [{field: "id", value: user.fetch("id")}], select: ["email"], join: {session: true})

    expect(joined.keys).to contain_exactly("email", "session")
    expect(joined.fetch("session").map { |session| session.fetch("token") }).to eq(["token-1"])
  end

  it "supports case-insensitive string predicates across find count update and delete operations" do
    db = Sequel.sqlite
    apply_migration(db, config)
    adapter = described_class.new(config, connection: db)
    adapter.create(model: "user", data: {id: "user-1", name: "Ada Lovelace", email: "Ada@Example.com"}, force_allow_id: true)

    where = [{field: "email", operator: "eq", value: "ada@example.com", mode: "insensitive"}]
    contains = [{field: "name", operator: "contains", value: "lovelace", mode: "insensitive"}]

    expect(adapter.find_one(model: "user", where: where).fetch("id")).to eq("user-1")
    expect(adapter.count(model: "user", where: contains)).to eq(1)
    expect(adapter.update(model: "user", where: where, update: {name: "Updated"}).fetch("name")).to eq("Updated")
    expect(adapter.delete_many(model: "user", where: [{field: "name", operator: "in", value: ["updated"], mode: "insensitive"}])).to eq(1)
  end

  it "applies defaults when required fields are explicitly nil on create" do
    db = Sequel.sqlite
    apply_migration(db, config)
    adapter = described_class.new(config, connection: db)

    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com", emailVerified: nil}, force_allow_id: true)

    expect(user.fetch("emailVerified")).to be(false)
  end

  it "creates and updates database rate limit rows with generated id fields" do
    rate_limit_config = BetterAuth::Configuration.new(
      secret: secret,
      database: :memory,
      rate_limit: {storage: "database"}
    )
    db = Sequel.sqlite
    apply_migration(db, rate_limit_config)
    adapter = described_class.new(rate_limit_config, connection: db)

    record = adapter.create(model: "rateLimit", data: {key: "ip:127.0.0.1", count: 1, lastRequest: 123})
    updated = adapter.update(model: "rateLimit", where: [{field: "key", value: "ip:127.0.0.1"}], update: {count: 2})

    expect(record).to include("key" => "ip:127.0.0.1", "count" => 1)
    expect(record.fetch("id")).to be_a(String)
    expect(updated).to include("key" => "ip:127.0.0.1", "count" => 2)
  end

  it "raises controlled API errors for invalid query fields and pagination" do
    db = Sequel.sqlite
    apply_migration(db, config)
    adapter = described_class.new(config, connection: db)

    expect {
      adapter.find_many(model: "user", where: [{field: "doesNotExist", value: "x"}])
    }.to raise_error(BetterAuth::APIError, /Invalid field/)
    expect {
      adapter.find_many(model: "user", sort_by: {field: "doesNotExist"})
    }.to raise_error(BetterAuth::APIError, /Invalid field/)
    expect {
      adapter.find_many(model: "user", limit: "nope")
    }.to raise_error(BetterAuth::APIError, /Invalid limit/)
    expect {
      adapter.find_many(model: "user", where: [{field: "createdAt", value: "not-a-date"}])
    }.to raise_error(BetterAuth::APIError, /Invalid date/)
  end

  it "uses configured default limits for inferred one-to-many joins" do
    limited_config = BetterAuth::Configuration.new(secret: secret, database: :memory, experimental: {joins: true}, advanced: {database: {default_find_many_limit: 2}})
    db = Sequel.sqlite
    apply_migration(db, limited_config)
    adapter = described_class.new(limited_config, connection: db)
    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    3.times do |index|
      adapter.create(model: "session", data: {id: "session-#{index}", userId: user.fetch("id"), token: "token-#{index}", expiresAt: Time.now + 3600}, force_allow_id: true)
    end

    joined = adapter.find_one(model: "user", where: [{field: "id", value: user.fetch("id")}], join: {session: true})

    expect(joined.fetch("session").length).to eq(2)
  end

  it "applies configured join limits per parent for multi-parent collection joins" do
    limited_config = BetterAuth::Configuration.new(secret: secret, database: :memory, experimental: {joins: true}, advanced: {database: {default_find_many_limit: 2}})
    db = Sequel.sqlite
    apply_migration(db, limited_config)
    adapter = described_class.new(limited_config, connection: db)
    users = 2.times.map do |user_index|
      user = adapter.create(model: "user", data: {id: "user-#{user_index}", name: "User #{user_index}", email: "user-#{user_index}@example.com"}, force_allow_id: true)
      3.times do |session_index|
        adapter.create(model: "session", data: {id: "session-#{user_index}-#{session_index}", userId: user.fetch("id"), token: "token-#{user_index}-#{session_index}", expiresAt: Time.now + 3600}, force_allow_id: true)
      end
      user
    end

    joined = adapter.find_many(model: "user", where: [{field: "id", operator: "in", value: users.map { |user| user.fetch("id") }}], sort_by: {field: "email"}, join: {session: true})

    expect(joined.map { |user| user.fetch("session").length }).to eq([2, 2])
  end

  it "treats LIKE wildcard characters literally in string predicates" do
    db = Sequel.sqlite
    apply_migration(db, config)
    adapter = described_class.new(config, connection: db)
    literal_percent = adapter.create(model: "user", data: {id: "user-percent", name: "100% Ada", email: "percent@example.com"}, force_allow_id: true)
    adapter.create(model: "user", data: {id: "user-normal", name: "100x Ada", email: "normal@example.com"}, force_allow_id: true)
    literal_underscore = adapter.create(model: "user", data: {id: "user-underscore", name: "Ada_1", email: "underscore@example.com"}, force_allow_id: true)

    percent_matches = adapter.find_many(model: "user", where: [{field: "name", value: "100%", operator: "starts_with"}])
    underscore_matches = adapter.find_many(model: "user", where: [{field: "name", value: "_", operator: "contains"}])

    expect(percent_matches.map { |user| user.fetch("id") }).to eq([literal_percent.fetch("id")])
    expect(underscore_matches.map { |user| user.fetch("id") }).to eq([literal_underscore.fetch("id")])
  end

  describe ".from_hanami" do
    it "warns when no Hanami container is available and memory storage is used" do
      expect(Kernel).to receive(:warn).with(/in-memory|Memory/i)

      adapter = described_class.from_hanami(config, container: false)

      expect(adapter).to be_a(BetterAuth::Adapters::Memory)
    end

    it "raises in production when memory fallback is not explicitly allowed" do
      previous = ENV["APP_ENV"]
      ENV["APP_ENV"] = "production"

      expect {
        described_class.from_hanami(config, container: false)
      }.to raise_error(BetterAuth::Error, /db.gateway/)
    ensure
      ENV["APP_ENV"] = previous
    end
  end

  describe ".from_container" do
    it "uses the Hanami db.gateway connection when present" do
      db = Sequel.sqlite
      gateway = Struct.new(:connection).new(db)
      container = Class.new do
        def initialize(gateway)
          @gateway = gateway
        end

        def key?(key)
          key == "db.gateway"
        end

        def [](key)
          raise KeyError unless key == "db.gateway"

          @gateway
        end
      end.new(gateway)

      adapter = described_class.from_container(container, config)

      expect(adapter).to be_a(described_class)
      expect(adapter.connection).to equal(db)
    end

    it "warns when db.gateway is missing and memory storage is used" do
      container = Class.new do
        def key?(_key) = false

        def [](_key)
          raise KeyError
        end
      end.new

      expect(Kernel).to receive(:warn).with(/in-memory|Memory/i)

      adapter = described_class.from_container(container, config)

      expect(adapter).to be_a(BetterAuth::Adapters::Memory)
    end
  end

  # rubocop:disable Security/Eval
  def apply_migration(db, config)
    require "rom-sql"
    gateway = ROM::SQL::Gateway.new(db)
    migration = ROM::SQL.with_gateway(gateway) do
      eval(BetterAuth::Hanami::Migration.render(config), binding, __FILE__, __LINE__)
    end
    migration.apply(db, :up)
  end
  # rubocop:enable Security/Eval
end

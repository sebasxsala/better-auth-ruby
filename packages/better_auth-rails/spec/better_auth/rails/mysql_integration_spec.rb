# frozen_string_literal: true

require "tmpdir"
require_relative "../../spec_helper"

RSpec.describe "BetterAuth::Rails MySQL integration" do
  let(:url) { ENV.fetch("BETTER_AUTH_MYSQL_URL", "mysql2://user:password@127.0.0.1:3306/better_auth") }
  let(:secret) { "test-secret-that-is-long-enough-for-validation" }
  let(:config) { BetterAuth::Configuration.new(secret: secret, database: :memory) }
  let(:plugin) do
    BetterAuth::Plugin.new(
      id: "audit",
      schema: {
        auditLog: {
          model_name: "audit_logs",
          fields: {
            id: {type: "string", required: true},
            userId: {type: "string", required: false, references: {model: "user", field: "id", on_delete: "cascade"}, index: true},
            action: {type: "string", required: true, unique: true},
            attempts: {type: "number", required: true, default_value: 0},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }}
          }
        }
      }
    )
  end
  let(:plugin_config) { BetterAuth::Configuration.new(secret: secret, database: :memory, plugins: [plugin]) }

  before do
    require "mysql2"
    require "active_record"
    ActiveRecord::Base.establish_connection(url)
    reset_schema
  end

  after do
    reset_schema if ActiveRecord::Base.connected?
    ActiveRecord::Base.connection_pool.disconnect! if ActiveRecord::Base.connected?
  end

  it "creates MySQL tables from the generated Rails migration and reads users through ActiveRecord and SQL adapters" do
    run_generated_migration
    active_record_adapter = BetterAuth::Rails::ActiveRecordAdapter.new(config, connection: ActiveRecord::Base)

    created = active_record_adapter.create(
      model: "user",
      data: {id: "user-1", name: "Ada", email: "ada@example.com"},
      force_allow_id: true
    )
    found_with_active_record = active_record_adapter.find_one(model: "user", where: [{field: "email", value: "ada@example.com"}])
    found_with_sql = with_mysql_connection do |connection|
      BetterAuth::Adapters::MySQL.new(config, connection: connection)
        .find_one(model: "user", where: [{field: "id", value: "user-1"}])
    end

    expect(created).to include("id" => "user-1", "emailVerified" => false)
    expect(found_with_active_record).to include("name" => "Ada", "email" => "ada@example.com")
    expect(found_with_sql).to include("id" => "user-1", "email" => "ada@example.com", "emailVerified" => false)
    expect(ActiveRecord::Base.connection.table_exists?("users")).to be(true)
    expect(ActiveRecord::Base.connection.indexes("users").any? { |index| index.columns == ["email"] && index.unique }).to be(true)
  end

  it "creates plugin tables and supports ActiveRecord adapter queries for plugin models" do
    run_generated_migration(plugin_config)
    active_record_adapter = BetterAuth::Rails::ActiveRecordAdapter.new(plugin_config, connection: ActiveRecord::Base)

    active_record_adapter.create(
      model: "user",
      data: {id: "user-1", name: "Ada", email: "ada@example.com"},
      force_allow_id: true
    )
    active_record_adapter.create(model: "auditLog", data: {id: "audit-1", userId: "user-1", action: "login"}, force_allow_id: true)
    active_record_adapter.create(model: "auditLog", data: {id: "audit-2", userId: "user-1", action: "logout", attempts: 2}, force_allow_id: true)

    selected = active_record_adapter.find_many(
      model: "auditLog",
      where: [{field: "action", operator: "contains", value: "log"}],
      select: ["id", "action"],
      sort_by: {field: "action", direction: "desc"},
      limit: 1
    )
    by_prefix = active_record_adapter.find_many(model: "auditLog", where: [{field: "action", operator: "starts_with", value: "log"}], sort_by: {field: "action", direction: "asc"})
    by_suffix = active_record_adapter.find_many(model: "auditLog", where: [{field: "action", operator: "ends_with", value: "out"}])
    by_in = active_record_adapter.find_many(model: "auditLog", where: [{field: "action", operator: "in", value: ["login", "logout"]}])
    by_not_in = active_record_adapter.find_many(model: "auditLog", where: [{field: "action", operator: "not_in", value: ["login"]}])
    by_ne = active_record_adapter.find_many(model: "auditLog", where: [{field: "action", operator: "ne", value: "login"}])
    by_gt = active_record_adapter.find_many(model: "auditLog", where: [{field: "attempts", operator: "gt", value: 1}])
    by_gte = active_record_adapter.find_many(model: "auditLog", where: [{field: "attempts", operator: "gte", value: 2}])
    by_lt = active_record_adapter.find_many(model: "auditLog", where: [{field: "attempts", operator: "lt", value: 1}])
    by_lte = active_record_adapter.find_many(model: "auditLog", where: [{field: "attempts", operator: "lte", value: 0}])
    with_offset = active_record_adapter.find_many(model: "auditLog", sort_by: {field: "action", direction: "asc"}, limit: 1, offset: 1)
    updated = active_record_adapter.update_many(
      model: "auditLog",
      where: [{field: "userId", value: "user-1"}],
      update: {attempts: 3},
      returning: true
    )
    session = active_record_adapter.create(
      model: "session",
      data: {id: "session-1", userId: "user-1", token: "token-1", expiresAt: Time.now + 3600},
      force_allow_id: true
    )
    joined = active_record_adapter.find_one(model: "session", where: [{field: "id", value: session["id"]}], join: {user: true})
    user_with_audit_logs = active_record_adapter.find_one(model: "user", where: [{field: "id", value: "user-1"}], join: {auditLog: true})

    expect(selected).to eq([{"id" => "audit-2", "action" => "logout"}])
    expect(by_prefix.map { |row| row["action"] }).to eq(["login", "logout"])
    expect(by_suffix.map { |row| row["action"] }).to eq(["logout"])
    expect(by_in.map { |row| row["action"] }).to contain_exactly("login", "logout")
    expect(by_not_in.map { |row| row["action"] }).to eq(["logout"])
    expect(by_ne.map { |row| row["action"] }).to eq(["logout"])
    expect(by_gt.map { |row| row["action"] }).to eq(["logout"])
    expect(by_gte.map { |row| row["action"] }).to eq(["logout"])
    expect(by_lt.map { |row| row["action"] }).to eq(["login"])
    expect(by_lte.map { |row| row["action"] }).to eq(["login"])
    expect(with_offset.map { |row| row["action"] }).to eq(["logout"])
    expect(updated.map { |row| row["attempts"] }).to eq([3, 3])
    expect(joined.fetch("user")).to include("id" => "user-1", "email" => "ada@example.com")
    expect(user_with_audit_logs.fetch("auditLog").map { |audit_log| audit_log.fetch("action") }).to contain_exactly("login", "logout")
    expect(ActiveRecord::Base.connection.table_exists?("audit_logs")).to be(true)
  end

  it "supports OR connectors and case-insensitive string predicates" do
    run_generated_migration(plugin_config)
    active_record_adapter = BetterAuth::Rails::ActiveRecordAdapter.new(plugin_config, connection: ActiveRecord::Base)

    active_record_adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    active_record_adapter.create(model: "user", data: {id: "user-2", name: "Grace", email: "grace@example.com"}, force_allow_id: true)
    active_record_adapter.create(model: "user", data: {id: "user-3", name: "Linus", email: "linus@example.com"}, force_allow_id: true)
    active_record_adapter.create(model: "auditLog", data: {id: "audit-1", userId: "user-1", action: "PrefixContainsSuffix"}, force_allow_id: true)
    active_record_adapter.create(model: "auditLog", data: {id: "audit-2", userId: "user-2", action: "OtherAction"}, force_allow_id: true)

    or_users = active_record_adapter.find_many(
      model: "user",
      where: [
        {field: "email", value: "ada@example.com"},
        {field: "email", value: "grace@example.com", connector: "OR"}
      ],
      sort_by: {field: "email", direction: "asc"}
    )
    eq_user = active_record_adapter.find_one(model: "user", where: [{field: "email", value: "ADA@EXAMPLE.COM", mode: "insensitive"}])
    in_users = active_record_adapter.find_many(model: "user", where: [{field: "email", operator: "in", value: ["ADA@EXAMPLE.COM", "GRACE@EXAMPLE.COM"], mode: "insensitive"}])
    not_in_users = active_record_adapter.find_many(model: "user", where: [{field: "email", operator: "not_in", value: ["ADA@EXAMPLE.COM", "GRACE@EXAMPLE.COM"], mode: "insensitive"}])
    contains = active_record_adapter.find_many(model: "auditLog", where: [{field: "action", operator: "contains", value: "contains", mode: "insensitive"}])
    starts_with = active_record_adapter.find_many(model: "auditLog", where: [{field: "action", operator: "starts_with", value: "prefix", mode: "insensitive"}])
    ends_with = active_record_adapter.find_many(model: "auditLog", where: [{field: "action", operator: "ends_with", value: "suffix", mode: "insensitive"}])
    ne_users = active_record_adapter.find_many(model: "user", where: [{field: "email", operator: "ne", value: "ADA@EXAMPLE.COM", mode: "insensitive"}])

    expect(or_users.map { |user| user.fetch("email") }).to eq(["ada@example.com", "grace@example.com"])
    expect(eq_user.fetch("id")).to eq("user-1")
    expect(in_users.map { |user| user.fetch("id") }).to contain_exactly("user-1", "user-2")
    expect(not_in_users.map { |user| user.fetch("id") }).to eq(["user-3"])
    expect(contains.map { |row| row.fetch("id") }).to eq(["audit-1"])
    expect(starts_with.map { |row| row.fetch("id") }).to eq(["audit-1"])
    expect(ends_with.map { |row| row.fetch("id") }).to eq(["audit-1"])
    expect(ne_users.map { |user| user.fetch("id") }).to contain_exactly("user-2", "user-3")
  end

  it "uses native ActiveRecord eager loading for supported joins" do
    run_generated_migration
    active_record_adapter = BetterAuth::Rails::ActiveRecordAdapter.new(config, connection: ActiveRecord::Base)

    active_record_adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    active_record_adapter.create(model: "user", data: {id: "user-2", name: "Grace", email: "grace@example.com"}, force_allow_id: true)
    active_record_adapter.create(model: "session", data: {id: "session-1", userId: "user-1", token: "token-1", expiresAt: Time.now + 3600}, force_allow_id: true)
    active_record_adapter.create(model: "session", data: {id: "session-2", userId: "user-2", token: "token-2", expiresAt: Time.now + 3600}, force_allow_id: true)
    active_record_adapter.create(model: "account", data: {id: "account-1", userId: "user-1", accountId: "github-1", providerId: "github"}, force_allow_id: true)
    active_record_adapter.create(model: "account", data: {id: "account-2", userId: "user-2", accountId: "github-2", providerId: "github"}, force_allow_id: true)

    session_query_count = count_selects do
      joined_sessions = active_record_adapter.find_many(model: "session", sort_by: {field: "id", direction: "asc"}, join: {user: true})
      expect(joined_sessions.map { |session| session.fetch("user").fetch("email") }).to eq(["ada@example.com", "grace@example.com"])
    end
    account_query_count = count_selects do
      joined_accounts = active_record_adapter.find_many(model: "account", sort_by: {field: "id", direction: "asc"}, join: {user: true})
      expect(joined_accounts.map { |account| account.fetch("user").fetch("email") }).to eq(["ada@example.com", "grace@example.com"])
    end
    user_query_count = count_selects do
      joined_users = active_record_adapter.find_many(model: "user", sort_by: {field: "id", direction: "asc"}, join: {account: true})
      expect(joined_users.map { |user| user.fetch("account").map { |account| account.fetch("accountId") } }).to eq([["github-1"], ["github-2"]])
    end

    expect(session_query_count).to be <= 2
    expect(account_query_count).to be <= 2
    expect(user_query_count).to be <= 2
  end

  def run_generated_migration(render_config = config)
    Object.send(:remove_const, :CreateBetterAuthTables) if Object.const_defined?(:CreateBetterAuthTables)
    Dir.mktmpdir("better-auth-migration") do |dir|
      path = File.join(dir, "create_better_auth_tables.rb")
      File.write(path, BetterAuth::Rails::Migration.render(render_config))
      load path
    end
    CreateBetterAuthTables.migrate(:up)
  end

  def reset_schema
    reset_mysql_schema
  end

  def with_mysql_connection
    connection = Mysql2::Client.new(
      host: ENV.fetch("BETTER_AUTH_MYSQL_HOST", "127.0.0.1"),
      port: ENV.fetch("BETTER_AUTH_MYSQL_PORT", "3306").to_i,
      username: ENV.fetch("BETTER_AUTH_MYSQL_USER", "user"),
      password: ENV.fetch("BETTER_AUTH_MYSQL_PASSWORD", "password"),
      database: ENV.fetch("BETTER_AUTH_MYSQL_DATABASE", "better_auth"),
      symbolize_keys: false
    )
    yield connection
  ensure
    connection&.close
  end

  def count_selects
    count = 0
    callback = lambda do |_name, _start, _finish, _id, payload|
      sql = payload[:sql].to_s
      count += 1 if sql.start_with?("SELECT") && payload[:name] != "SCHEMA"
    end

    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { yield }
    count
  end
end

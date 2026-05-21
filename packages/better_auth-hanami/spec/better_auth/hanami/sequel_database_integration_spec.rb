# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe "BetterAuth::Hanami::SequelAdapter database integrations" do
  let(:secret) { "test-secret-that-is-long-enough-for-validation" }
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
  let(:config) { BetterAuth::Configuration.new(secret: secret, database: :memory, plugins: [plugin], rate_limit: {storage: "database"}, experimental: {joins: true}) }

  {
    "PostgreSQL" => :postgres,
    "MySQL" => :mysql,
    "MSSQL" => :mssql
  }.each do |label, database|
    it "round-trips core, plugin, join, and rate-limit records on #{label} when available" do
      db = connect_database(database)
      reset_database(db, database)
      apply_migration(db, config)
      exercise_adapter(db)
    ensure
      reset_database(db, database) if db
      db&.disconnect
    end
  end

  def exercise_adapter(db)
    adapter = BetterAuth::Hanami::SequelAdapter.new(config, connection: db)
    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    session = adapter.create(model: "session", data: {id: "session-1", userId: user.fetch("id"), token: "token-1", expiresAt: Time.now + 3600}, force_allow_id: true)
    adapter.create(model: "auditLog", data: {id: "audit-1", userId: user.fetch("id"), action: "login"}, force_allow_id: true)
    adapter.create(model: "auditLog", data: {id: "audit-2", userId: user.fetch("id"), action: "logout", attempts: 2}, force_allow_id: true)
    rate_limit = adapter.create(model: "rateLimit", data: {key: "ip:127.0.0.1", count: 1, lastRequest: 123})

    selected = adapter.find_many(model: "auditLog", where: [{field: "action", operator: "contains", value: "log"}], sort_by: {field: "action", direction: "asc"})
    joined = adapter.find_one(model: "session", where: [{field: "id", value: session.fetch("id")}], join: {user: true})
    updated_rate_limit = adapter.update(model: "rateLimit", where: [{field: "key", value: "ip:127.0.0.1"}], update: {count: 2})

    expect(selected.map { |row| row.fetch("action") }).to eq(%w[login logout])
    expect(joined.fetch("user")).to include("id" => user.fetch("id"), "email" => "ada@example.com")
    expect(rate_limit.fetch("id")).to be_a(String)
    expect(updated_rate_limit).to include("key" => "ip:127.0.0.1", "count" => 2)
  end

  # rubocop:disable Security/Eval
  def apply_migration(db, render_config)
    require "rom-sql"
    gateway = ROM::SQL::Gateway.new(db)
    migration = ROM::SQL.with_gateway(gateway) do
      eval(BetterAuth::Hanami::Migration.render(render_config), binding, __FILE__, __LINE__)
    end
    migration.apply(db, :up)
  end
  # rubocop:enable Security/Eval

  def connect_database(database)
    case database
    when :postgres
      require "pg"
      Sequel.connect(ENV.fetch("BETTER_AUTH_POSTGRES_URL", "postgres://user:password@localhost:5432/better_auth"))
    when :mysql
      require "mysql2"
      Sequel.connect(ENV.fetch("BETTER_AUTH_MYSQL_URL", "mysql2://user:password@127.0.0.1:3306/better_auth"))
    when :mssql
      require "tiny_tds"
      Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_URL", "tinytds://sa:Password123!@127.0.0.1:1433/better_auth?timeout=30"))
    end
  rescue LoadError
    skip "#{database} driver gem is not installed"
  rescue Sequel::DatabaseConnectionError
    skip "#{database} test service is not available"
  end

  def reset_database(db, database)
    case database
    when :postgres
      db.run("DROP SCHEMA IF EXISTS public CASCADE")
      db.run("CREATE SCHEMA public")
    when :mysql
      db.run("SET FOREIGN_KEY_CHECKS = 0")
      db.tables.each { |table| db.drop_table?(table) }
      db.run("SET FOREIGN_KEY_CHECKS = 1")
    when :mssql
      drop_mssql_foreign_keys(db)
      db.tables.each { |table| db.drop_table?(table) }
    end
  end

  def drop_mssql_foreign_keys(db)
    db.run(<<~SQL)
      DECLARE @sql NVARCHAR(MAX) = N''
      SELECT @sql = @sql + N'ALTER TABLE ' + QUOTENAME(SCHEMA_NAME(parent_table.schema_id)) + N'.' + QUOTENAME(parent_table.name) + N' DROP CONSTRAINT ' + QUOTENAME(foreign_key.name) + CHAR(10)
      FROM sys.foreign_keys AS foreign_key
      INNER JOIN sys.tables AS parent_table ON foreign_key.parent_object_id = parent_table.object_id
      EXEC sp_executesql @sql
    SQL
  end
end

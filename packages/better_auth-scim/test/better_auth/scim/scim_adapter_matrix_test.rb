# frozen_string_literal: true

require_relative "../scim_test_helper"

class BetterAuthPluginsScimAdapterMatrixTest < Minitest::Test
  include SCIMTestHelper

  def test_scim_flow_persists_with_sqlite_adapter
    require "sqlite3"

    Tempfile.create(["better-auth-scim", ".sqlite3"]) do |file|
      config = scim_schema_config
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      connection.execute("PRAGMA foreign_keys = ON")
      create_sql_schema(connection, config, :sqlite)

      auth = build_scim_auth_with_database(
        ->(options) { BetterAuth::Adapters::SQLite.new(options, connection: connection) }
      )

      run_scim_adapter_smoke(auth, provider_id: "sqlite-provider")
      assert_nil direct_sqlite_value(connection, %(SELECT account_id FROM "accounts" WHERE provider_id = ?), "sqlite-provider")
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_scim_flow_persists_with_postgres_adapter_when_available
    require "pg"

    config = scim_schema_config
    connection = PG.connect(ENV.fetch("BETTER_AUTH_POSTGRES_URL", "postgres://user:password@localhost:5432/better_auth"))
    reset_postgres_schema(connection, config)
    create_sql_schema(connection, config, :postgres)
    auth = build_scim_auth_with_database(
      ->(options) { BetterAuth::Adapters::Postgres.new(options, connection: connection) }
    )

    run_scim_adapter_smoke(auth, provider_id: "postgres-provider")
  rescue LoadError
    skip "pg gem is not installed"
  rescue PG::ConnectionBad
    skip "PostgreSQL test service is not available"
  ensure
    connection&.close
  end

  def test_scim_flow_persists_with_mysql_adapter_when_available
    require "mysql2"

    config = scim_schema_config
    connection = Mysql2::Client.new(
      host: ENV.fetch("BETTER_AUTH_MYSQL_HOST", "127.0.0.1"),
      port: ENV.fetch("BETTER_AUTH_MYSQL_PORT", "3306").to_i,
      username: ENV.fetch("BETTER_AUTH_MYSQL_USER", "user"),
      password: ENV.fetch("BETTER_AUTH_MYSQL_PASSWORD", "password"),
      database: ENV.fetch("BETTER_AUTH_MYSQL_DATABASE", "better_auth"),
      symbolize_keys: false
    )
    reset_mysql_schema(connection, config)
    create_sql_schema(connection, config, :mysql)
    auth = build_scim_auth_with_database(
      ->(options) { BetterAuth::Adapters::MySQL.new(options, connection: connection) }
    )

    run_scim_adapter_smoke(auth, provider_id: "mysql-provider")
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  ensure
    connection&.close
  end

  def test_scim_flow_persists_with_mssql_adapter_when_available
    require "sequel"
    require "tiny_tds"

    ensure_mssql_database
    config = scim_schema_config
    connection = Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_URL", "tinytds://sa:Password123!@127.0.0.1:1433/better_auth?timeout=30"))
    reset_mssql_schema(connection)
    create_sql_schema(connection, config, :mssql)
    auth = build_scim_auth_with_database(
      ->(options) { BetterAuth::Adapters::MSSQL.new(options, connection: connection) }
    )

    run_scim_adapter_smoke(auth, provider_id: "mssql-provider")
  rescue LoadError
    skip "sequel or tiny_tds gem is not installed"
  rescue Sequel::DatabaseConnectionError
    skip "MSSQL test service is not available"
  ensure
    connection&.disconnect
  end

  def test_scim_flow_persists_with_mongodb_adapter_when_available
    require "better_auth/mongodb"
    require "mongo"

    database_name = "better-auth-scim-ruby-test"
    client = Mongo::Client.new(ENV.fetch("BETTER_AUTH_MONGODB_URL", "mongodb://127.0.0.1:27017/#{database_name}"), server_selection_timeout: 1)
    client.database.collections.each { |collection| collection.drop unless collection.name.start_with?("system.") }
    auth = build_scim_auth_with_database(
      ->(options) { BetterAuth::Adapters::MongoDB.new(options, database: client.database, client: client, transaction: false) }
    )

    auth.context.adapter.ensure_indexes! if auth.context.adapter.respond_to?(:ensure_indexes!)
    run_scim_adapter_smoke(auth, provider_id: "mongodb-provider")
  rescue LoadError
    skip "better_auth-mongodb or mongo gem is not installed"
  rescue Mongo::Error::NoServerAvailable, Mongo::Error::SocketError
    skip "MongoDB test service is not available"
  ensure
    client&.close
  end

  private

  def create_sql_schema(connection, config, dialect)
    BetterAuth::Schema::SQL.create_statements(config, dialect: dialect).each do |statement|
      case dialect
      when :postgres
        connection.exec(statement)
      when :mysql
        connection.query(statement)
      when :mssql
        connection.run(statement)
      else
        connection.execute(statement)
      end
    end
  end

  def schema_table_names(config)
    BetterAuth::Schema.auth_tables(config).values.map { |table| table.fetch(:model_name) }
  end

  def reset_postgres_schema(connection, config)
    schema_table_names(config).each do |table|
      connection.exec(%(DROP TABLE IF EXISTS "#{table}" CASCADE))
    end
  end

  def reset_mysql_schema(connection, config)
    connection.query("SET FOREIGN_KEY_CHECKS = 0")
    schema_table_names(config).each do |table|
      connection.query("DROP TABLE IF EXISTS #{quote_mysql_identifier(table)}")
    end
    connection.query("SET FOREIGN_KEY_CHECKS = 1")
  end

  def quote_mysql_identifier(identifier)
    "`#{identifier.to_s.gsub("`", "``")}`"
  end

  def ensure_mssql_database
    master = Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_MASTER_URL", "tinytds://sa:Password123!@127.0.0.1:1433/master?timeout=30"))
    master.run("IF DB_ID(N'better_auth') IS NULL CREATE DATABASE [better_auth]")
  rescue Sequel::DatabaseConnectionError
    skip "MSSQL test service is not available"
  ensure
    master&.disconnect
  end

  def reset_mssql_schema(connection)
    connection.run(<<~SQL)
      DECLARE @sql NVARCHAR(MAX) = N''
      SELECT @sql = @sql + N'ALTER TABLE ' + QUOTENAME(SCHEMA_NAME(parent_table.schema_id)) + N'.' + QUOTENAME(parent_table.name) + N' DROP CONSTRAINT ' + QUOTENAME(foreign_key.name) + CHAR(10)
      FROM sys.foreign_keys AS foreign_key
      INNER JOIN sys.tables AS parent_table ON foreign_key.parent_object_id = parent_table.object_id
      EXEC sp_executesql @sql
    SQL
    connection.fetch("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'").all.each do |row|
      table = row[:TABLE_NAME] || row[:table_name] || row["TABLE_NAME"] || row["table_name"]
      connection.run("DROP TABLE [#{table.to_s.gsub("]", "]]")}]") if table
    end
  end

  def direct_sqlite_value(connection, sql, *params)
    connection.execute(sql, params).first&.values&.first
  end
end

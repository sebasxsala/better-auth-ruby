# frozen_string_literal: true

require "json"
require "tempfile"
require_relative "../../test_helper"

class OAuthProviderAdapterSmokeTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_memory_adapter_oauth_provider_smoke_flow
    run_oauth_provider_smoke(database: :memory)
  end

  def test_sqlite_adapter_oauth_provider_smoke_flow
    require "sqlite3"

    Tempfile.create(["better-auth-oauth-provider", ".sqlite3"]) do |file|
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      connection.execute("PRAGMA foreign_keys = ON")
      create_sql_schema(connection, :sqlite)

      run_oauth_provider_smoke(
        database: ->(options) { BetterAuth::Adapters::SQLite.new(options, connection: connection) }
      )
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_postgres_adapter_oauth_provider_smoke_flow
    require "pg"

    connection = PG.connect(ENV.fetch("BETTER_AUTH_POSTGRES_URL", "postgres://user:password@localhost:5432/better_auth"))
    reset_postgres_schema(connection)
    create_sql_schema(connection, :postgres)

    run_oauth_provider_smoke(
      database: ->(options) { BetterAuth::Adapters::Postgres.new(options, connection: connection) }
    )
  rescue LoadError
    skip "pg gem is not installed"
  rescue PG::ConnectionBad
    skip "PostgreSQL test service is not available"
  ensure
    connection&.close
  end

  def test_mysql_adapter_oauth_provider_smoke_flow
    require "mysql2"

    connection = Mysql2::Client.new(
      host: ENV.fetch("BETTER_AUTH_MYSQL_HOST", "127.0.0.1"),
      port: ENV.fetch("BETTER_AUTH_MYSQL_PORT", "3306").to_i,
      username: ENV.fetch("BETTER_AUTH_MYSQL_USER", "user"),
      password: ENV.fetch("BETTER_AUTH_MYSQL_PASSWORD", "password"),
      database: ENV.fetch("BETTER_AUTH_MYSQL_DATABASE", "better_auth"),
      symbolize_keys: false
    )
    reset_mysql_schema(connection)
    create_sql_schema(connection, :mysql)

    run_oauth_provider_smoke(
      database: ->(options) { BetterAuth::Adapters::MySQL.new(options, connection: connection) }
    )
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  ensure
    connection&.close
  end

  def test_mssql_adapter_oauth_provider_smoke_flow
    require "sequel"
    require "tiny_tds"

    ensure_mssql_database
    connection = Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_URL", "tinytds://sa:Password123!@127.0.0.1:1433/better_auth?timeout=30"))
    reset_mssql_schema(connection)
    create_sql_schema(connection, :mssql)

    run_oauth_provider_smoke(
      database: ->(options) { BetterAuth::Adapters::MSSQL.new(options, connection: connection) }
    )
  rescue LoadError
    skip "sequel or tiny_tds gem is not installed"
  rescue Sequel::DatabaseConnectionError
    skip "MSSQL test service is not available"
  ensure
    connection&.disconnect
  end

  def test_mongodb_adapter_oauth_provider_smoke_flow
    require_relative "../../../../better_auth-mongodb/lib/better_auth/mongodb"
    require_relative "../../../../better_auth-mongodb/test/support/fake_mongo"

    database = FakeMongoDatabase.new
    run_oauth_provider_smoke(
      database: ->(options) { BetterAuth::Adapters::MongoDB.new(options, database: database) }
    )
  rescue LoadError
    skip "better_auth-mongodb or mongo gem is not available"
  end

  def test_oauth_provider_sql_schema_contains_tables_indexes_and_foreign_keys_for_all_dialects
    %i[sqlite postgres mysql mssql].each do |dialect|
      sql = oauth_provider_sql(dialect)

      assert_includes sql, "oauth_clients", "expected oauth_clients table for #{dialect}"
      assert_includes sql, "oauth_refresh_tokens", "expected oauth_refresh_tokens table for #{dialect}"
      assert_includes sql, "oauth_access_tokens", "expected oauth_access_tokens table for #{dialect}"
      assert_includes sql, "oauth_consents", "expected oauth_consents table for #{dialect}"
      assert_includes sql, "index_oauth_access_tokens_on_refresh_id", "expected access-token refresh index for #{dialect}"
      assert_includes sql, "index_oauth_consents_on_reference_id", "expected consent reference index for #{dialect}"
      assert_match(/FOREIGN KEY .*oauth_clients.*client_id/im, sql, "expected client foreign key for #{dialect}")
      assert_match(/FOREIGN KEY .*sessions.*id/im, sql, "expected session foreign key for #{dialect}")
    end
  end

  private

  def run_oauth_provider_smoke(database:)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: OAuthProviderFlowHelpers::SECRET,
      database: database,
      email_and_password: {enabled: true},
      session: {cookie_cache: {enabled: false}},
      plugins: [oauth_provider_smoke_plugin]
    )
    cookie = sign_up_cookie(auth, email: "adapter-smoke@example.com")
    client = create_client(
      auth,
      cookie,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: "openid offline_access read"
    )

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access read")
    assert_equal "Bearer", tokens[:token_type]
    assert tokens[:access_token]
    assert tokens[:refresh_token]

    active = auth.api.o_auth2_introspect(body: introspect_body(client, tokens[:access_token]))
    assert_equal true, active[:active]
    assert_equal client[:client_id], active[:client_id]

    refreshed = auth.api.o_auth2_token(body: refresh_grant_body(client, tokens[:refresh_token], scope: "openid read"))
    assert refreshed[:access_token]
    assert_equal "openid read", refreshed[:scope]

    revoked = auth.api.o_auth2_revoke(body: revoke_body(client, refreshed[:access_token], hint: "access_token"))
    assert_equal({revoked: true}, revoked)
  end

  def oauth_provider_smoke_plugin
    BetterAuth::Plugins.oauth_provider(
      scopes: ["openid", "offline_access", "read"],
      allow_dynamic_client_registration: true
    )
  end

  def oauth_provider_sql(dialect)
    config = BetterAuth::Configuration.new(
      secret: OAuthProviderFlowHelpers::SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      session: {cookie_cache: {enabled: false}},
      plugins: [oauth_provider_smoke_plugin]
    )
    BetterAuth::Schema::SQL.create_statements(config, dialect: dialect).join("\n")
  end

  def create_sql_schema(connection, dialect)
    sql_config = BetterAuth::Configuration.new(
      secret: OAuthProviderFlowHelpers::SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      session: {cookie_cache: {enabled: false}},
      plugins: [oauth_provider_smoke_plugin]
    )
    BetterAuth::Schema::SQL.create_statements(sql_config, dialect: dialect).each do |statement|
      case dialect
      when :sqlite
        connection.execute(statement)
      when :postgres
        connection.exec(statement)
      when :mysql
        connection.query(statement)
      when :mssql
        connection.run(statement)
      end
    end
  end

  def reset_postgres_schema(connection)
    connection.exec("DROP SCHEMA public CASCADE")
    connection.exec("CREATE SCHEMA public")
  end

  def reset_mysql_schema(connection)
    connection.query("SET FOREIGN_KEY_CHECKS = 0")
    connection.query("SHOW TABLES").each do |row|
      table = row.values.first
      connection.query("DROP TABLE IF EXISTS `#{table.to_s.gsub("`", "``")}`")
    end
    connection.query("SET FOREIGN_KEY_CHECKS = 1")
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
end

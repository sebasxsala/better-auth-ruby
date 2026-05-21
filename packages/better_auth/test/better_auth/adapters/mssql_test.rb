# frozen_string_literal: true

require "json"
require_relative "../../test_helper"
require_relative "adapter_contract"

class BetterAuthMSSQLAdapterTest < Minitest::Test
  include BetterAuthAdapterContract

  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_mssql_adapter_can_be_instantiated_with_injected_connection
    connection = FakeSequelDatabase.new
    adapter = BetterAuth::Adapters::MSSQL.new(connection: connection)

    assert_equal :mssql, adapter.dialect
    assert_same connection, adapter.connection
  end

  def test_mssql_adapter_persists_auth_routes_and_get_session_reads_database_rows
    require "sequel"
    require "tiny_tds"

    ensure_database
    connection = Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_URL", "tinytds://sa:Password123!@127.0.0.1:1433/better_auth?timeout=30"))
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    reset_schema(connection)
    create_schema(connection, config)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: ->(options) { BetterAuth::Adapters::MSSQL.new(options, connection: connection) },
      email_and_password: {enabled: true},
      session: {cookie_cache: {enabled: false}}
    )

    status, headers, body = auth.api.sign_up_email(
      body: {email: "mssql-route@example.com", password: "password123", name: "MSSQL Route"},
      as_response: true
    )
    payload = JSON.parse(body.join)
    token = payload.fetch("token")
    user_id = payload.fetch("user").fetch("id")

    assert_equal 200, status
    assert_equal "mssql-route@example.com", direct_mssql_value(connection, "SELECT email FROM [users] WHERE id = ?", user_id)
    assert_equal "credential", direct_mssql_value(connection, "SELECT provider_id FROM [accounts] WHERE user_id = ?", user_id)
    assert_equal user_id, direct_mssql_value(connection, "SELECT user_id FROM [sessions] WHERE token = ?", token)

    connection.run("UPDATE [users] SET [name] = 'MSSQL Direct Update' WHERE id = '#{user_id.gsub("'", "''")}'")
    session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})

    assert_equal token, session[:session]["token"]
    assert_equal user_id, session[:session]["userId"]
    assert_equal "MSSQL Direct Update", session[:user]["name"]
  rescue LoadError
    skip "sequel or tiny_tds gem is not installed"
  rescue Sequel::DatabaseConnectionError
    skip "MSSQL test service is not available"
  ensure
    connection&.disconnect
  end

  def test_mssql_adapter_allows_multiple_null_values_for_nullable_unique_plugin_fields
    require "sequel"
    require "tiny_tds"

    ensure_database
    connection = Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_URL", "tinytds://sa:Password123!@127.0.0.1:1433/better_auth?timeout=30"))
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: ->(options) { BetterAuth::Adapters::MSSQL.new(options, connection: connection) },
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.phone_number]
    )
    reset_schema(connection)
    create_schema(connection, auth.options)

    first_status, = auth.api.sign_up_email(body: {email: "mssql-null-one@example.com", password: "password123", name: "Null One"}, as_response: true)
    second_status, = auth.api.sign_up_email(body: {email: "mssql-null-two@example.com", password: "password123", name: "Null Two"}, as_response: true)

    assert_equal 200, first_status
    assert_equal 200, second_status
  rescue LoadError
    skip "sequel or tiny_tds gem is not installed"
  rescue Sequel::DatabaseConnectionError
    skip "MSSQL test service is not available"
  ensure
    connection&.disconnect
  end

  private

  def with_contract_adapter(config)
    require "sequel"
    require "tiny_tds"

    ensure_database
    connection = Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_URL", "tinytds://sa:Password123!@127.0.0.1:1433/better_auth?timeout=30"))
    reset_schema(connection)
    create_schema(connection, config)
    yield BetterAuth::Adapters::MSSQL.new(config, connection: connection)
  rescue LoadError
    skip "sequel or tiny_tds gem is not installed"
  rescue Sequel::DatabaseConnectionError
    skip "MSSQL test service is not available"
  ensure
    connection&.disconnect
  end

  def ensure_database
    master = Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_MASTER_URL", "tinytds://sa:Password123!@127.0.0.1:1433/master?timeout=30"))
    master.run("IF DB_ID(N'better_auth') IS NULL CREATE DATABASE [better_auth]")
  rescue Sequel::DatabaseConnectionError
    skip "MSSQL test service is not available"
  ensure
    master&.disconnect
  end

  def reset_schema(connection)
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

  def create_schema(connection, config)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :mssql).each { |statement| connection.run(statement) }
  end

  def direct_mssql_value(connection, sql, *params)
    connection.fetch(sql, *params).first&.values&.first
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end

  class FakeSequelDatabase
    def fetch(_sql, *_params)
      []
    end
  end
end

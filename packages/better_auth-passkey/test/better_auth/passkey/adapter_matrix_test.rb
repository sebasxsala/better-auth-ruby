# frozen_string_literal: true

require "tempfile"
require_relative "support"

class BetterAuthPasskeyAdapterMatrixTest < Minitest::Test
  include BetterAuthPasskeyTestSupport

  def test_sqlite_adapter_persists_complete_passkey_flow
    require "sqlite3"

    Tempfile.create(["better-auth-passkey", ".sqlite3"]) do |file|
      config = passkey_config
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      connection.execute("PRAGMA foreign_keys = ON")
      create_sql_schema(connection, config, dialect: :sqlite)
      auth = adapter_auth do |options|
        BetterAuth::Adapters::SQLite.new(options, connection: connection)
      end

      assert_passkey_round_trip(passkey_round_trip(auth, email: "sqlite-passkey@example.com"), email: "sqlite-passkey@example.com")
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_postgres_adapter_persists_complete_passkey_flow
    require "pg"

    connection = PG.connect(ENV.fetch("BETTER_AUTH_POSTGRES_URL", "postgres://user:password@localhost:5432/better_auth"))
    config = passkey_config
    reset_postgres_schema(connection)
    create_sql_schema(connection, config, dialect: :postgres)
    auth = adapter_auth do |options|
      BetterAuth::Adapters::Postgres.new(options, connection: connection)
    end

    assert_passkey_round_trip(passkey_round_trip(auth, email: "postgres-passkey@example.com"), email: "postgres-passkey@example.com")
  rescue LoadError
    skip "pg gem is not installed"
  rescue PG::ConnectionBad
    skip "PostgreSQL test service is not available"
  ensure
    connection&.close
  end

  def test_mysql_adapter_persists_complete_passkey_flow
    require "mysql2"

    connection = mysql_connection
    config = passkey_config
    reset_mysql_schema(connection)
    create_sql_schema(connection, config, dialect: :mysql)
    auth = adapter_auth do |options|
      BetterAuth::Adapters::MySQL.new(options, connection: connection)
    end

    assert_passkey_round_trip(passkey_round_trip(auth, email: "mysql-passkey@example.com"), email: "mysql-passkey@example.com")
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  ensure
    connection&.close
  end

  def test_mssql_adapter_persists_complete_passkey_flow
    require "sequel"
    require "tiny_tds"

    ensure_mssql_database
    connection = Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_URL", "tinytds://sa:Password123!@127.0.0.1:1433/better_auth?timeout=30"))
    config = passkey_config
    reset_mssql_schema(connection)
    create_sql_schema(connection, config, dialect: :mssql)
    auth = adapter_auth do |options|
      BetterAuth::Adapters::MSSQL.new(options, connection: connection)
    end

    assert_passkey_round_trip(passkey_round_trip(auth, email: "mssql-passkey@example.com"), email: "mssql-passkey@example.com")
  rescue LoadError
    skip "sequel or tiny_tds gem is not installed"
  rescue Sequel::DatabaseConnectionError
    skip "MSSQL test service is not available"
  ensure
    connection&.disconnect
  end

  def test_mongodb_adapter_persists_complete_passkey_flow
    url = ENV.fetch("BETTER_AUTH_MONGODB_URL", "mongodb://127.0.0.1:27017/better_auth_passkey_test")
    skip "MongoDB test service is not available" unless tcp_reachable?(url, default_port: 27017)
    require "mongo"
    require "better_auth/mongodb"

    client = Mongo::Client.new(
      url,
      server_selection_timeout: 1,
      connect_timeout: 1,
      socket_timeout: 1
    )
    client.database.collections.each(&:drop)
    auth = adapter_auth do |options|
      BetterAuth::Adapters::MongoDB.new(options, database: client.database, client: client)
    end

    assert_passkey_round_trip(passkey_round_trip(auth, email: "mongodb-passkey@example.com"), email: "mongodb-passkey@example.com")
  rescue LoadError
    skip "mongo or better_auth-mongodb gem is not installed"
  rescue => error
    raise unless defined?(::Mongo::Error::NoServerAvailable) && error.instance_of?(::Mongo::Error::NoServerAvailable)

    skip "MongoDB test service is not available"
  ensure
    client&.close
  end

  private

  def passkey_config
    BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.passkey]
    )
  end

  def adapter_auth(&database)
    BetterAuth.auth(
      base_url: ORIGIN,
      secret: SECRET,
      database: database,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.passkey],
      session: {cookie_cache: {enabled: false}}
    )
  end

  def reset_postgres_schema(connection)
    %w[passkeys rate_limits verifications accounts sessions users].each do |table|
      connection.exec(%(DROP TABLE IF EXISTS "#{table}" CASCADE))
    end
  end

  def mysql_connection
    Mysql2::Client.new(
      host: ENV.fetch("BETTER_AUTH_MYSQL_HOST", "127.0.0.1"),
      port: ENV.fetch("BETTER_AUTH_MYSQL_PORT", "3306").to_i,
      username: ENV.fetch("BETTER_AUTH_MYSQL_USER", "user"),
      password: ENV.fetch("BETTER_AUTH_MYSQL_PASSWORD", "password"),
      database: ENV.fetch("BETTER_AUTH_MYSQL_DATABASE", "better_auth"),
      symbolize_keys: false
    )
  end

  def reset_mysql_schema(connection)
    connection.query("SET FOREIGN_KEY_CHECKS = 0")
    mysql_table_names(connection).each do |table|
      connection.query("DROP TABLE IF EXISTS #{quote_mysql_identifier(table)}")
    end
  ensure
    connection&.query("SET FOREIGN_KEY_CHECKS = 1")
  end

  def mysql_table_names(connection)
    connection.query(<<~SQL).map { |row| row["table_name"] || row.fetch("TABLE_NAME") }
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
    SQL
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

  def tcp_reachable?(url, default_port:)
    require "socket"
    require "timeout"
    require "uri"

    uri = URI.parse(url)
    Timeout.timeout(0.5) do
      socket = TCPSocket.new(uri.host, uri.port || default_port)
      socket.close
      true
    end
  rescue
    false
  end
end

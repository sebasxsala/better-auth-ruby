# frozen_string_literal: true

require "tempfile"
require "securerandom"
require_relative "test_support"

class BetterAuthAPIKeyAdapterMatrixTest < Minitest::Test
  include APIKeyTestSupport

  SECRET = APIKeyTestSupport::SECRET

  def test_memory_adapter_api_key_lifecycle
    with_memory_auth do |auth|
      assert_api_key_lifecycle(auth)
    end
  end

  def test_sqlite_adapter_api_key_lifecycle
    require "sqlite3"

    Tempfile.create(["better-auth-api-key-matrix", ".sqlite3"]) do |file|
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      connection.execute("PRAGMA foreign_keys = ON")
      with_sql_auth(:sqlite, connection) do |auth|
        assert_api_key_lifecycle(auth) do |created|
          row = connection.execute(%(SELECT reference_id, config_id FROM "api_keys" WHERE id = ?), [created.fetch(:id)]).first
          assert_equal created.fetch(:referenceId), row.fetch("reference_id")
          assert_equal created.fetch(:configId), row.fetch("config_id")
        end
      end
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_postgres_adapter_api_key_lifecycle
    require "pg"

    connection = PG.connect(ENV.fetch("BETTER_AUTH_POSTGRES_URL", "postgres://user:password@localhost:5432/better_auth"))
    reset_postgres_schema(connection)
    with_sql_auth(:postgres, connection) do |auth|
      assert_api_key_lifecycle(auth) do |created|
        row = connection.exec_params(%(SELECT reference_id, config_id FROM "api_keys" WHERE id = $1), [created.fetch(:id)]).first
        assert_equal created.fetch(:referenceId), row.fetch("reference_id")
        assert_equal created.fetch(:configId), row.fetch("config_id")
      end
    end
  rescue LoadError
    skip "pg gem is not installed"
  rescue PG::ConnectionBad
    skip "PostgreSQL test service is not available"
  ensure
    connection&.close
  end

  def test_mysql_adapter_api_key_lifecycle
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
    with_sql_auth(:mysql, connection) do |auth|
      assert_api_key_lifecycle(auth) do |created|
        statement = connection.prepare("SELECT reference_id, config_id FROM `api_keys` WHERE id = ?")
        row = statement.execute(created.fetch(:id)).first
        assert_equal created.fetch(:referenceId), row.fetch("reference_id")
        assert_equal created.fetch(:configId), row.fetch("config_id")
      end
    end
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  ensure
    connection&.close
  end

  def test_mssql_adapter_api_key_lifecycle
    require "sequel"
    require "tiny_tds"

    ensure_mssql_database
    connection = Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_URL", "tinytds://sa:Password123!@127.0.0.1:1433/better_auth?timeout=30"))
    reset_mssql_schema(connection)
    with_sql_auth(:mssql, connection) do |auth|
      assert_api_key_lifecycle(auth) do |created|
        row = connection.fetch("SELECT reference_id, config_id FROM [api_keys] WHERE id = ?", created.fetch(:id)).first
        assert_equal created.fetch(:referenceId), row.fetch(:reference_id)
        assert_equal created.fetch(:configId), row.fetch(:config_id)
      end
    end
  rescue LoadError
    skip "sequel or tiny_tds gem is not installed"
  rescue Sequel::DatabaseConnectionError
    skip "MSSQL test service is not available"
  ensure
    connection&.disconnect
  end

  def test_fake_mongodb_adapter_api_key_lifecycle_and_field_mapping
    require "better_auth/mongodb"
    require_relative "../../../../better_auth-mongodb/test/support/fake_mongo"

    database = BetterAuthMongoAdapterTestSupport::FakeMongoDatabase.new
    auth = build_matrix_auth(
      database: ->(options) { BetterAuth::Adapters::MongoDB.new(options, database: database) }
    )

    assert_api_key_lifecycle(auth) do |created|
      stored = database.collection("api_keys").documents.find { |document| document.fetch("_id").to_s == created.fetch(:id).to_s }
      assert stored, "expected api key document to be stored in api_keys"
      assert_equal created.fetch(:referenceId), stored.fetch("reference_id").to_s
      assert_equal created.fetch(:configId), stored.fetch("config_id")
      assert_instance_of Time, stored.fetch("created_at")
      assert_equal 0, stored.fetch("request_count")
    end
  rescue LoadError
    skip "better_auth-mongodb or mongo gem is not installed"
  end

  def test_rack_mounting_exposes_api_key_endpoints
    with_memory_auth do |auth|
      cookie = sign_up_cookie(auth, email: "rack-api-key-matrix@example.com")
      status, created = rack_json_response(auth, "POST", "/api-key/create", cookie: cookie, body: {name: "rack key"})

      assert_equal 200, status
      assert created.fetch("key")

      status, verified = rack_json_response(auth, "POST", "/api-key/verify", body: {key: created.fetch("key")})
      assert_equal 200, status
      assert_equal true, verified.fetch("valid")

      status, listed = rack_json_response(auth, "GET", "/api-key/list", cookie: cookie)
      assert_equal 200, status
      assert_includes listed.fetch("apiKeys").map { |entry| entry.fetch("id") }, created.fetch("id")
    end
  end

  private

  def with_memory_auth
    yield build_matrix_auth
  end

  def with_sql_auth(dialect, connection)
    auth = build_matrix_auth(
      database: ->(options) { sql_adapter_for(dialect, options, connection) }
    )
    create_sql_schema(dialect, connection, auth.options)
    yield auth
  end

  def build_matrix_auth(database: :memory)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: database,
      email_and_password: {enabled: true},
      session: {cookie_cache: {enabled: false}},
      plugins: [
        BetterAuth::Plugins.api_key([
          {config_id: "default", default_key_length: 12, default_prefix: "ba_"},
          {config_id: "service", default_key_length: 12, default_prefix: "svc_", rate_limit: {enabled: true, time_window: 60_000, max_requests: 2}}
        ])
      ]
    )
  end

  def assert_api_key_lifecycle(auth)
    cookie = sign_up_cookie(auth, email: "adapter-matrix-#{SecureRandom.hex(5)}@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie}).fetch(:user).fetch("id")

    expired = auth.api.create_api_key(body: {configId: "service", userId: user_id, name: "expired"})
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: expired.fetch(:id)}], update: {expiresAt: Time.now - 60})
    cleanup = auth.api.delete_all_expired_api_keys
    assert_equal true, cleanup.fetch(:success)
    assert_raises(BetterAuth::APIError) do
      auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: expired.fetch(:id), configId: "service"})
    end

    main = auth.api.create_api_key(
      body: {
        configId: "service",
        userId: user_id,
        name: "matrix-main",
        remaining: 2,
        rateLimitEnabled: false,
        permissions: {files: ["read"]}
      }
    )
    yield main if block_given?

    first_quota = auth.api.verify_api_key(body: {key: main.fetch(:key), permissions: {files: ["read"]}})
    assert_equal true, first_quota.fetch(:valid)
    assert_equal 1, first_quota.fetch(:key).fetch(:remaining)

    second_quota = auth.api.verify_api_key(body: {key: main.fetch(:key)})
    assert_equal true, second_quota.fetch(:valid)
    assert_equal 0, second_quota.fetch(:key).fetch(:remaining)

    exhausted = auth.api.verify_api_key(body: {key: main.fetch(:key)})
    assert_equal false, exhausted.fetch(:valid)
    assert_equal "USAGE_EXCEEDED", exhausted.fetch(:error).fetch(:code)

    alpha = auth.api.create_api_key(body: {configId: "service", userId: user_id, name: "alpha", rateLimitEnabled: false})
    beta = auth.api.create_api_key(body: {configId: "service", userId: user_id, name: "beta", rateLimitEnabled: false})
    rate_limited = auth.api.create_api_key(
      body: {configId: "service", userId: user_id, name: "rate", rateLimitEnabled: true, rateLimitMax: 1, rateLimitTimeWindow: 60_000}
    )

    rate_ok = auth.api.verify_api_key(body: {key: rate_limited.fetch(:key), configId: "service"})
    assert_equal true, rate_ok.fetch(:valid)
    assert_equal 1, rate_ok.fetch(:key).fetch(:requestCount)
    assert rate_ok.fetch(:key).fetch(:lastRequest)

    rate_error = auth.api.verify_api_key(body: {key: rate_limited.fetch(:key), configId: "service"})
    assert_equal false, rate_error.fetch(:valid)
    assert_equal "RATE_LIMITED", rate_error.fetch(:error).fetch(:code)
    assert_operator rate_error.fetch(:error).fetch(:details).fetch(:tryAgainIn), :>, 0

    first_page = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {configId: "service", limit: 1, offset: 0, sortBy: "name", sortDirection: "asc"})
    second_page = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {configId: "service", limit: 1, offset: 1, sortBy: "name", sortDirection: "asc"})
    assert_operator first_page.fetch(:total), :>=, 3
    refute_equal first_page.fetch(:apiKeys).first.fetch(:id), second_page.fetch(:apiKeys).first.fetch(:id)
    assert_equal alpha.fetch(:id), first_page.fetch(:apiKeys).first.fetch(:id)

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {configId: "service", keyId: beta.fetch(:id), name: "beta-disabled", enabled: false})
    assert_equal "beta-disabled", updated.fetch(:name)
    assert_equal false, updated.fetch(:enabled)
    disabled = auth.api.verify_api_key(body: {key: beta.fetch(:key), configId: "service"})
    assert_equal false, disabled.fetch(:valid)
    assert_equal "KEY_DISABLED", disabled.fetch(:error).fetch(:code)

    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {configId: "service", keyId: beta.fetch(:id)}))
    assert_raises(BetterAuth::APIError) do
      auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: beta.fetch(:id), configId: "service"})
    end
  end

  def sql_adapter_for(dialect, options, connection)
    case dialect
    when :sqlite
      BetterAuth::Adapters::SQLite.new(options, connection: connection)
    when :postgres
      BetterAuth::Adapters::Postgres.new(options, connection: connection)
    when :mysql
      BetterAuth::Adapters::MySQL.new(options, connection: connection)
    when :mssql
      BetterAuth::Adapters::MSSQL.new(options, connection: connection)
    else
      raise ArgumentError, "unsupported SQL dialect: #{dialect}"
    end
  end

  def create_sql_schema(dialect, connection, config)
    BetterAuth::Schema::SQL.create_statements(config, dialect: dialect).each do |statement|
      execute_sql(connection, statement)
    end
  end

  def execute_sql(connection, statement)
    if connection.respond_to?(:exec)
      connection.exec(statement)
    elsif connection.respond_to?(:query)
      connection.query(statement)
    elsif connection.respond_to?(:run)
      connection.run(statement)
    else
      connection.execute(statement)
    end
  end

  def reset_postgres_schema(connection)
    connection.exec("DROP SCHEMA IF EXISTS public CASCADE")
    connection.exec("CREATE SCHEMA public")
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
end

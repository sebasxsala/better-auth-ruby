# frozen_string_literal: true

require "json"
require_relative "../../test_helper"
require_relative "adapter_contract"

class BetterAuthMySQLAdapterTest < Minitest::Test
  include BetterAuthMySQLTestHelpers
  include BetterAuthAdapterContract

  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_mysql_adapter_can_be_instantiated_without_rails
    port = ENV.fetch("BETTER_AUTH_MYSQL_PORT", "3306")
    adapter = BetterAuth::Adapters::MySQL.new(url: "mysql2://user:password@127.0.0.1:#{port}/better_auth")

    assert_equal :mysql, adapter.dialect
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  end

  def test_mysql_adapter_runs_core_crud_against_docker_service
    require "mysql2"

    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = Mysql2::Client.new(
      host: ENV.fetch("BETTER_AUTH_MYSQL_HOST", "127.0.0.1"),
      port: ENV.fetch("BETTER_AUTH_MYSQL_PORT", "3306").to_i,
      username: ENV.fetch("BETTER_AUTH_MYSQL_USER", "user"),
      password: ENV.fetch("BETTER_AUTH_MYSQL_PASSWORD", "password"),
      database: ENV.fetch("BETTER_AUTH_MYSQL_DATABASE", "better_auth"),
      symbolize_keys: false
    )
    reset_mysql_schema(connection)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :mysql).each { |statement| connection.query(statement) }
    adapter = BetterAuth::Adapters::MySQL.new(config, connection: connection)

    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    found = adapter.find_one(model: "user", where: [{field: "email", value: "ada@example.com"}])

    assert_equal "user-1", user["id"]
    assert_equal false, user["emailVerified"]
    assert_equal "Ada", found["name"]
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  ensure
    connection&.close
  end

  def test_mysql_adapter_persists_auth_routes_and_get_session_reads_database_rows
    require "mysql2"

    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = mysql_connection
    reset_mysql_schema(connection)
    create_schema(connection, config)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: ->(options) { BetterAuth::Adapters::MySQL.new(options, connection: connection) },
      email_and_password: {enabled: true},
      session: {cookie_cache: {enabled: false}}
    )

    status, headers, body = auth.api.sign_up_email(
      body: {email: "mysql-route@example.com", password: "password123", name: "MySQL Route"},
      as_response: true
    )
    payload = JSON.parse(body.join)
    token = payload.fetch("token")
    user_id = payload.fetch("user").fetch("id")

    assert_equal 200, status
    assert_equal "mysql-route@example.com", direct_mysql_value(connection, "SELECT email FROM `users` WHERE id = ?", user_id)
    assert_equal "credential", direct_mysql_value(connection, "SELECT provider_id FROM `accounts` WHERE user_id = ?", user_id)
    assert_equal user_id, direct_mysql_value(connection, "SELECT user_id FROM `sessions` WHERE token = ?", token)

    statement = connection.prepare("UPDATE `users` SET `name` = ? WHERE id = ?")
    statement.execute("MySQL Direct Update", user_id)
    session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})

    assert_equal token, session[:session]["token"]
    assert_equal user_id, session[:session]["userId"]
    assert_equal "MySQL Direct Update", session[:user]["name"]
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  ensure
    connection&.close
  end

  def test_mysql_pending_migration_does_not_recreate_existing_indexes
    require "mysql2"

    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = mysql_connection
    reset_mysql_schema(connection)
    create_schema(connection, config)

    sql = BetterAuth::SQLMigration.render_pending(config, connection: connection, dialect: :mysql, generator: "better_auth-test")

    refute_includes sql, "index_sessions_on_user_id"
    refute_includes sql, "index_accounts_on_user_id"
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  ensure
    connection&.close
  end

  def test_mysql_pending_migration_adds_plugin_table_after_core_schema
    require "mysql2"

    plugin = BetterAuth::Plugin.new(
      id: "audit",
      schema: {
        auditLog: {
          model_name: "audit_logs",
          fields: {
            id: {type: "string", required: true},
            userId: {type: "string", required: true, references: {model: "user", field: "id"}, index: true},
            action: {type: "string", required: true, index: true}
          }
        }
      }
    )
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    plugin_config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: [plugin])
    connection = mysql_connection
    reset_mysql_schema(connection)
    create_schema(connection, config)

    sql = BetterAuth::SQLMigration.render_pending(plugin_config, connection: connection, dialect: :mysql, generator: "better_auth-test")

    assert_includes sql, "CREATE TABLE IF NOT EXISTS `audit_logs`"
    assert_includes sql, "CONSTRAINT `fk_audit_logs_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE"

    BetterAuth::SQLMigration.execute_sql(connection, sql)

    assert_includes mysql_table_names(connection), "audit_logs"
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  ensure
    connection&.close
  end

  private

  def with_contract_adapter(config)
    require "mysql2"

    connection = mysql_connection
    reset_mysql_schema(connection)
    create_schema(connection, config)
    yield BetterAuth::Adapters::MySQL.new(config, connection: connection)
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  ensure
    connection&.close
  end

  def create_schema(connection, config)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :mysql).each { |statement| connection.query(statement) }
  end

  def direct_mysql_value(connection, sql, *params)
    statement = connection.prepare(sql)
    statement.execute(*params).first&.values&.first
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end

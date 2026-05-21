# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPostgresAdapterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_postgres_adapter_can_be_instantiated_without_rails
    connection = Object.new
    adapter = BetterAuth::Adapters::Postgres.new(connection: connection)

    assert_equal :postgres, adapter.dialect
    assert_same connection, adapter.connection
  end

  def test_postgres_adapter_runs_core_crud_against_docker_service
    require "pg"

    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = PG.connect(ENV.fetch("BETTER_AUTH_POSTGRES_URL", "postgres://user:password@localhost:5432/better_auth"))
    reset_schema(connection)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :postgres).each { |statement| connection.exec(statement) }
    adapter = BetterAuth::Adapters::Postgres.new(config, connection: connection)

    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    found = adapter.find_one(model: "user", where: [{field: "email", value: "ada@example.com"}])

    assert_equal "user-1", user["id"]
    assert_equal false, user["emailVerified"]
    assert_equal "Ada", found["name"]
  rescue LoadError
    skip "pg gem is not installed"
  rescue PG::ConnectionBad
    skip "PostgreSQL test service is not available"
  ensure
    connection&.close
  end

  def test_postgres_adapter_persists_auth_routes_and_get_session_reads_database_rows
    require "pg"

    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = PG.connect(ENV.fetch("BETTER_AUTH_POSTGRES_URL", "postgres://user:password@localhost:5432/better_auth"))
    reset_schema(connection)
    create_schema(connection, config)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: ->(options) { BetterAuth::Adapters::Postgres.new(options, connection: connection) },
      email_and_password: {enabled: true},
      session: {cookie_cache: {enabled: false}}
    )

    status, headers, body = auth.api.sign_up_email(
      body: {email: "postgres-route@example.com", password: "password123", name: "Postgres Route"},
      as_response: true
    )
    payload = JSON.parse(body.join)
    token = payload.fetch("token")
    user_id = payload.fetch("user").fetch("id")

    assert_equal 200, status
    assert_equal "postgres-route@example.com", direct_postgres_value(connection, %(SELECT email FROM "users" WHERE id = $1), [user_id])
    assert_equal "credential", direct_postgres_value(connection, %(SELECT provider_id FROM "accounts" WHERE user_id = $1), [user_id])
    assert_equal user_id, direct_postgres_value(connection, %(SELECT user_id FROM "sessions" WHERE token = $1), [token])

    connection.exec_params(%(UPDATE "users" SET "name" = $1 WHERE id = $2), ["Postgres Direct Update", user_id])
    session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})

    assert_equal token, session[:session]["token"]
    assert_equal user_id, session[:session]["userId"]
    assert_equal "Postgres Direct Update", session[:user]["name"]
  rescue LoadError
    skip "pg gem is not installed"
  rescue PG::ConnectionBad
    skip "PostgreSQL test service is not available"
  ensure
    connection&.close
  end

  private

  def reset_schema(connection)
    %w[rate_limits verifications accounts sessions users].each do |table|
      connection.exec(%(DROP TABLE IF EXISTS "#{table}" CASCADE))
    end
  end

  def create_schema(connection, config)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :postgres).each { |statement| connection.exec(statement) }
  end

  def direct_postgres_value(connection, sql, params)
    connection.exec_params(sql, params).first&.values&.first
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end

# frozen_string_literal: true

require "json"
require "tempfile"
require_relative "../../test_helper"

class BetterAuthSQLiteAdapterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_sqlite_adapter_can_be_instantiated_with_injected_connection
    connection = Object.new
    adapter = BetterAuth::Adapters::SQLite.new(connection: connection)

    assert_equal :sqlite, adapter.dialect
    assert_same connection, adapter.connection
  end

  def test_sqlite_adapter_persists_auth_routes_and_get_session_reads_database_rows
    require "sqlite3"

    Tempfile.create(["better-auth", ".sqlite3"]) do |file|
      config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      connection.execute("PRAGMA foreign_keys = ON")
      create_schema(connection, config)

      auth = BetterAuth.auth(
        base_url: "http://localhost:3000",
        secret: SECRET,
        database: ->(options) { BetterAuth::Adapters::SQLite.new(options, connection: connection) },
        email_and_password: {enabled: true},
        session: {cookie_cache: {enabled: false}}
      )

      status, headers, body = auth.api.sign_up_email(
        body: {email: "sqlite-route@example.com", password: "password123", name: "SQLite Route"},
        as_response: true
      )
      payload = JSON.parse(body.join)
      token = payload.fetch("token")
      user_id = payload.fetch("user").fetch("id")

      assert_equal 200, status
      assert_equal "sqlite-route@example.com", direct_sqlite_value(connection, %(SELECT email FROM "users" WHERE id = ?), user_id)
      assert_equal "credential", direct_sqlite_value(connection, %(SELECT provider_id FROM "accounts" WHERE user_id = ?), user_id)
      assert_equal user_id, direct_sqlite_value(connection, %(SELECT user_id FROM "sessions" WHERE token = ?), token)

      connection.execute(%(UPDATE "users" SET "name" = ? WHERE id = ?), ["SQLite Direct Update", user_id])
      session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})

      assert_equal token, session[:session]["token"]
      assert_equal user_id, session[:session]["userId"]
      assert_equal "SQLite Direct Update", session[:user]["name"]
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_sqlite_adapter_persists_social_id_token_sign_in
    require "sqlite3"

    Tempfile.create(["better-auth-social", ".sqlite3"]) do |file|
      config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      connection.execute("PRAGMA foreign_keys = ON")
      create_schema(connection, config)

      auth = BetterAuth.auth(
        base_url: "http://localhost:3000",
        secret: SECRET,
        database: ->(options) { BetterAuth::Adapters::SQLite.new(options, connection: connection) },
        social_providers: {
          github: {
            id: "github",
            verify_id_token: ->(_token, _nonce = nil) { true },
            get_user_info: ->(_tokens) {
              {
                user: {
                  id: "sqlite-gh-1",
                  email: "sqlite-social@example.com",
                  name: "SQLite Social",
                  image: "https://example.com/sqlite.png",
                  emailVerified: true
                }
              }
            }
          }
        },
        session: {cookie_cache: {enabled: false}}
      )

      status, headers, body = auth.api.sign_in_social(
        body: {provider: "github", idToken: {token: "id-token", accessToken: "access-token"}},
        as_response: true
      )
      payload = JSON.parse(body.join)
      user_id = payload.fetch("user").fetch("id")
      token = payload.fetch("token")

      assert_equal 200, status
      assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
      assert_equal "sqlite-social@example.com", direct_sqlite_value(connection, %(SELECT email FROM "users" WHERE id = ?), user_id)
      assert_equal "sqlite-gh-1", direct_sqlite_value(connection, %(SELECT account_id FROM "accounts" WHERE user_id = ?), user_id)
      assert_equal "github", direct_sqlite_value(connection, %(SELECT provider_id FROM "accounts" WHERE user_id = ?), user_id)
      assert_equal user_id, direct_sqlite_value(connection, %(SELECT user_id FROM "sessions" WHERE token = ?), token)
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_sqlite_adapter_round_trips_json_and_array_fields
    require "sqlite3"

    Tempfile.create(["better-auth-typed", ".sqlite3"]) do |file|
      plugin = BetterAuth::Plugin.new(
        id: "typed",
        schema: {
          typedRecord: {
            model_name: "typed_records",
            fields: {
              id: {type: "string", required: true},
              metadata: {type: "json", required: false},
              tags: {type: "string[]", required: false},
              scores: {type: "number[]", required: false}
            }
          }
        }
      )
      config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: [plugin])
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      create_schema(connection, config)
      adapter = BetterAuth::Adapters::SQLite.new(config, connection: connection)

      adapter.create(
        model: "typedRecord",
        data: {
          id: "typed-1",
          metadata: {"nested" => {"enabled" => true}},
          tags: ["alpha", "beta"],
          scores: [1, 2, 3]
        },
        force_allow_id: true
      )
      record = adapter.find_one(model: "typedRecord", where: [{field: "id", value: "typed-1"}])

      assert_equal({"nested" => {"enabled" => true}}, record.fetch("metadata"))
      assert_equal ["alpha", "beta"], record.fetch("tags")
      assert_equal [1, 2, 3], record.fetch("scores")
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_sqlite_adapter_coerces_string_where_values_to_schema_types
    require "sqlite3"

    Tempfile.create(["better-auth-coerce", ".sqlite3"]) do |file|
      config = BetterAuth::Configuration.new(
        secret: SECRET,
        database: :memory,
        user: {
          additional_fields: {
            age: {type: "number", required: false}
          }
        }
      )
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      create_schema(connection, config)
      adapter = BetterAuth::Adapters::SQLite.new(config, connection: connection)

      adapter.create(model: "user", data: {name: "False", email: "false-sqlite@example.com", age: 25})
      true_user = adapter.create(model: "user", data: {name: "True", email: "true-sqlite@example.com", age: 30})
      adapter.update(model: "user", where: [{field: "id", value: true_user.fetch("id")}], update: {emailVerified: true})

      by_boolean = adapter.find_many(model: "user", where: [{field: "emailVerified", value: "false"}])
      by_number = adapter.find_many(model: "user", where: [{field: "age", value: "25"}])

      assert_equal ["false-sqlite@example.com"], by_boolean.map { |user| user["email"] }
      assert_equal ["false-sqlite@example.com"], by_number.map { |user| user["email"] }
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_sqlite_adapter_matches_binary_encoded_string_where_values
    require "sqlite3"

    Tempfile.create(["better-auth-binary-token", ".sqlite3"]) do |file|
      config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      create_schema(connection, config)
      adapter = BetterAuth::Adapters::SQLite.new(config, connection: connection)

      user = adapter.create(model: "user", data: {name: "Binary Token", email: "binary-token@example.com"})
      token = "binary-token-value"
      adapter.create(
        model: "session",
        data: {token: token, userId: user.fetch("id"), expiresAt: Time.now + 3600},
        force_allow_id: true
      )

      binary_token = token.b
      assert_equal Encoding::ASCII_8BIT, binary_token.encoding

      session = adapter.find_one(model: "session", where: [{field: "token", value: binary_token}])
      assert_equal token, session.fetch("token")
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_sqlite_adapter_creates_plugin_records_when_schema_does_not_declare_id
    require "sqlite3"

    Tempfile.create(["better-auth-plugin-id", ".sqlite3"]) do |file|
      plugin = BetterAuth::Plugin.new(
        id: "plugin-id",
        schema: {
          auditLog: {
            model_name: "audit_logs",
            fields: {
              action: {type: "string", required: true, unique: true},
              createdAt: {type: "date", required: true}
            }
          }
        }
      )
      config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: [plugin])
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      create_schema(connection, config)
      adapter = BetterAuth::Adapters::SQLite.new(config, connection: connection)

      record = adapter.create(model: "auditLog", data: {action: "created", createdAt: Time.now})

      assert record.fetch("id")
      assert_equal "created", record.fetch("action")
      assert_equal record.fetch("id"), direct_sqlite_value(connection, %(SELECT id FROM "audit_logs" WHERE action = ?), "created")
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_sqlite_adapter_persists_database_rate_limit_table_without_id_column
    require "sqlite3"

    Tempfile.create(["better-auth-rate-limit", ".sqlite3"]) do |file|
      config = BetterAuth::Configuration.new(
        secret: SECRET,
        database: :memory,
        rate_limit: {storage: "database"}
      )
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      create_schema(connection, config)
      adapter = BetterAuth::Adapters::SQLite.new(config, connection: connection)

      record = adapter.create(model: "rateLimit", data: {key: "ip:127.0.0.1", count: 1, lastRequest: 123})
      updated = adapter.update(model: "rateLimit", where: [{field: "key", value: "ip:127.0.0.1"}], update: {count: 2})

      assert_equal "ip:127.0.0.1", record.fetch("key")
      refute record.key?("id")
      assert_equal 2, updated.fetch("count")
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  private

  def create_schema(connection, config)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :sqlite).each { |statement| connection.execute(statement) }
  end

  def direct_sqlite_value(connection, sql, *params)
    connection.execute(sql, params).first&.values&.first
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end

# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../../better_auth/lib", __dir__)

require "better_auth/cli"
require "minitest/autorun"
require_relative "../support/cli_helpers"

class BetterAuthCLITest < Minitest::Test
  include BetterAuthCLITestHelpers

  SECRET = BetterAuthCLITestHelpers::SECRET
  HARDENED_SECRET = BetterAuthCLITestHelpers::HARDENED_SECRET

  def teardown
    BetterAuth::CLI.configure(nil)
  end

  def test_generate_accepts_hash_config_and_writes_full_sql_for_memory_adapter
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_hash_config(dir, secret: SECRET, database: :memory, email_and_password: {enabled: true})
      output = File.join(dir, "auth.sql")

      status, stdout, stderr = run_cli("generate", "--config", config_path, "--dialect", "sqlite", "--output", output)

      assert_equal 0, status, stderr
      assert_includes stdout, "generated #{output}"
      assert_includes File.read(output), 'CREATE TABLE IF NOT EXISTS "users"'
    end
  end

  def test_generate_accepts_configuration_return
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_config(
        dir,
        <<~RUBY
          BetterAuth::Configuration.new(
            secret: #{SECRET.inspect},
            database: :memory,
            email_and_password: {enabled: true}
          )
        RUBY
      )
      output = File.join(dir, "auth.sql")

      status, _stdout, stderr = run_cli("generate", "--config", config_path, "--dialect", "sqlite", "--output", output)

      assert_equal 0, status, stderr
      assert_includes File.read(output), 'CREATE TABLE IF NOT EXISTS "users"'
    end
  end

  def test_generate_accepts_auth_return
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_config(
        dir,
        <<~RUBY
          BetterAuth.auth(
            secret: #{SECRET.inspect},
            database: :memory,
            email_and_password: {enabled: true}
          )
        RUBY
      )
      output = File.join(dir, "auth.sql")

      status, _stdout, stderr = run_cli("generate", "--config", config_path, "--dialect", "sqlite", "--output", output)

      assert_equal 0, status, stderr
      assert_includes File.read(output), 'CREATE TABLE IF NOT EXISTS "users"'
    end
  end

  def test_generate_accepts_cli_configure_block
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_config(
        dir,
        <<~RUBY
          BetterAuth::CLI.configure do
            {
              secret: #{SECRET.inspect},
              database: :memory,
              email_and_password: {enabled: true}
            }
          end
          nil
        RUBY
      )
      output = File.join(dir, "auth.sql")

      status, _stdout, stderr = run_cli("generate", "--config", config_path, "--dialect", "sqlite", "--output", output)

      assert_equal 0, status, stderr
      assert_includes File.read(output), 'CREATE TABLE IF NOT EXISTS "users"'
    end
  end

  def test_missing_config_file_returns_error
    Dir.mktmpdir("better-auth-cli") do |dir|
      status, _stdout, stderr = run_cli("doctor", "--config", File.join(dir, "missing.rb"))

      assert_equal 1, status
      assert_includes stderr, "Config file not found"
    end
  end

  def test_invalid_config_return_reports_allowed_types
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_config(dir, "42")

      status, _stdout, stderr = run_cli("doctor", "--config", config_path)

      assert_equal 1, status
      assert_includes stderr, "Hash, BetterAuth::Configuration, or BetterAuth::Auth"
    end
  end

  def test_unknown_command_returns_error
    status, _stdout, stderr = run_cli("wat")

    assert_equal 1, status
    assert_includes stderr, "Unknown command: wat"
  end

  def test_unknown_mongo_subcommand_returns_error
    status, _stdout, stderr = run_cli("mongo", "wat")

    assert_equal 1, status
    assert_includes stderr, "Unknown mongo command: wat"
  end

  def test_missing_required_options_return_errors
    status, _stdout, stderr = run_cli("generate", "--config", "config.rb")
    assert_equal 1, status
    assert_includes stderr, "generate --output PATH is required"

    status, _stdout, stderr = run_cli("migrate")
    assert_equal 1, status
    assert_includes stderr, "migrate --config PATH is required"

    status, _stdout, stderr = run_cli("doctor")
    assert_equal 1, status
    assert_includes stderr, "doctor --config PATH is required"
  end

  def test_invalid_option_returns_error_status
    status, _stdout, stderr = run_cli("generate", "--bogus")

    assert_equal 1, status
    assert_includes stderr, "invalid option: --bogus"
  end

  def test_missing_option_argument_returns_error_status
    status, _stdout, stderr = run_cli("generate", "--config")

    assert_equal 1, status
    assert_includes stderr, "missing argument: --config"
  end

  def test_migrate_requires_yes
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_sqlite_config(dir)

      status, _stdout, stderr = run_cli("migrate", "--config", config_path)

      assert_equal 1, status
      assert_includes stderr, "Pass --yes to apply migrations."
    end
  end

  def test_generate_writes_incremental_sql
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_sqlite_config(dir)
      output = File.join(dir, "auth.sql")

      status, stdout, stderr = run_cli("generate", "--config", config_path, "--dialect", "sqlite", "--output", output)

      assert_equal 0, status, stderr
      assert_includes stdout, "generated #{output}"
      assert_includes File.read(output), 'CREATE TABLE IF NOT EXISTS "users"'
    end
  end

  def test_generate_reports_no_migrations_needed_without_writing_output
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_sqlite_config(dir)
      output = File.join(dir, "auth.sql")

      status, _stdout, stderr = run_cli("migrate", "--config", config_path, "--yes")
      assert_equal 0, status, stderr

      status, stdout, stderr = run_cli("generate", "--config", config_path, "--dialect", "sqlite", "--output", output)

      assert_equal 0, status, stderr
      assert_includes stdout, "No migrations needed."
      refute File.exist?(output)
    end
  end

  def test_generate_includes_plugin_schema
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_sqlite_config(
        dir,
        plugins_source: <<~RUBY.strip
          [
            BetterAuth::Plugin.new(
              id: "audit",
              schema: {
                auditLog: {
                  model_name: "audit_logs",
                  fields: {
                    id: {type: "string", required: true},
                    action: {type: "string", required: true, index: true}
                  }
                }
              }
            )
          ]
        RUBY
      )
      output = File.join(dir, "auth.sql")

      status, _stdout, stderr = run_cli("generate", "--config", config_path, "--dialect", "sqlite", "--output", output)

      assert_equal 0, status, stderr
      assert_includes File.read(output), 'CREATE TABLE IF NOT EXISTS "audit_logs"'
    end
  end

  def test_generate_includes_database_rate_limit_table
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_sqlite_config(dir, rate_limit: {enabled: true, storage: "database"})
      output = File.join(dir, "auth.sql")

      status, _stdout, stderr = run_cli("generate", "--config", config_path, "--dialect", "sqlite", "--output", output)

      assert_equal 0, status, stderr
      assert_includes File.read(output), 'CREATE TABLE IF NOT EXISTS "rate_limits"'
    end
  end

  def test_migrate_applies_pending_schema_and_repeated_migrate_reports_no_changes
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_sqlite_config(dir)

      status, stdout, stderr = run_cli("migrate", "--config", config_path, "--yes")
      assert_equal 0, status, stderr
      assert_includes stdout, "migration completed successfully."
      assert_includes sqlite_tables(dir), "users"

      status, stdout, stderr = run_cli("migrate", "--config", config_path, "--yes")
      assert_equal 0, status, stderr
      assert_includes stdout, "No migrations needed."
    end
  end

  def test_migrate_status_lists_pending_schema_before_migration_and_no_changes_after
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_sqlite_config(dir)

      status, stdout, stderr = run_cli("migrate", "status", "--config", config_path)
      assert_equal 0, status, stderr
      assert_includes stdout, "create table users"

      status, _stdout, stderr = run_cli("migrate", "--config", config_path, "--yes")
      assert_equal 0, status, stderr

      status, stdout, stderr = run_cli("migrate", "status", "--config", config_path)
      assert_equal 0, status, stderr
      assert_includes stdout, "No migrations needed."
    end
  end

  def test_migrate_reports_unsupported_adapter
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_hash_config(dir, secret: SECRET, database: :memory)

      status, _stdout, stderr = run_cli("migrate", "--config", config_path, "--yes")

      assert_equal 1, status
      assert_includes stderr, "SQL adapters"
    end
  end

  def test_doctor_reports_insecure_secret_and_pending_migrations
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_sqlite_config(
        dir,
        secret: BetterAuth::Configuration::DEFAULT_SECRET,
        base_url: "http://example.test"
      )

      status, stdout, stderr = run_cli("doctor", "--config", config_path)

      assert_equal 1, status
      assert_includes stderr, "ERROR secret uses the default development value"
      assert_includes stdout, "WARN base_url is not HTTPS"
      assert_includes stdout, "WARN rate_limit uses memory storage"
      assert_includes stdout, "WARN database has pending Better Auth migrations"
    end
  end

  def test_doctor_passes_for_hardened_config_after_migration
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_sqlite_config(
        dir,
        secret: HARDENED_SECRET,
        base_url: "https://example.test",
        rate_limit: {enabled: true, storage: "database"}
      )
      status, _stdout, stderr = run_cli("migrate", "--config", config_path, "--yes")
      assert_equal 0, status, stderr

      status, stdout, stderr = run_cli("doctor", "--config", config_path)

      assert_equal 0, status, stderr
      assert_includes stdout, "OK config loaded"
      assert_includes stdout, "OK secret length and entropy look acceptable"
      assert_includes stdout, "OK database schema is up to date"
      assert_includes stdout, "OK rate_limit storage is database"
    end
  end

  def test_doctor_warns_when_rate_limit_is_disabled
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_hash_config(
        dir,
        secret: HARDENED_SECRET,
        base_url: "https://example.test",
        database: :memory,
        rate_limit: {enabled: false, storage: "memory"}
      )

      status, stdout, stderr = run_cli("doctor", "--config", config_path)

      assert_equal 0, status, stderr
      assert_includes stdout, "WARN rate_limit is disabled"
      assert_includes stdout, "WARN rate_limit uses memory storage"
      assert_includes stdout, "WARN database adapter does not expose SQL migration introspection"
    end
  end

  def test_doctor_accepts_secondary_storage_rate_limit_without_memory_warning
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_hash_config(
        dir,
        secret: HARDENED_SECRET,
        base_url: "https://example.test",
        database: :memory,
        rate_limit: {enabled: true, storage: "secondary-storage"}
      )

      status, stdout, stderr = run_cli("doctor", "--config", config_path)

      assert_equal 0, status, stderr
      assert_includes stdout, "OK rate_limit storage is secondary-storage"
      refute_includes stdout, "rate_limit uses memory storage"
    end
  end

  def test_fake_sql_adapters_cover_generate_and_status_for_all_supported_dialects
    {
      sqlite: '"users"',
      postgres: '"users"',
      mysql: "`users`",
      mssql: "[users]"
    }.each do |dialect, quoted_users|
      Dir.mktmpdir("better-auth-cli") do |dir|
        config_path = write_fake_sql_config(dir, dialect: dialect)
        output = File.join(dir, "#{dialect}.sql")

        status, _stdout, stderr = run_cli("generate", "--config", config_path, "--output", output)
        assert_equal 0, status, "#{dialect}: #{stderr}"
        assert_includes File.read(output), "CREATE TABLE"
        assert_includes File.read(output), quoted_users

        status, stdout, stderr = run_cli("migrate", "status", "--config", config_path)
        assert_equal 0, status, "#{dialect}: #{stderr}"
        assert_includes stdout, "create table users"
      end
    end
  end

  def test_mongo_indexes_calls_adapter_index_setup
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_mongo_config(
        dir,
        indexes: [
          {collection: "users", field: "email", unique: true},
          {collection: "sessions", field: "token", unique: false}
        ]
      )

      status, stdout, stderr = run_cli("mongo", "indexes", "--config", config_path)

      assert_equal 0, status, stderr
      assert_includes stdout, "ensured unique index users.email"
      assert_includes stdout, "ensured index sessions.token"
    end
  end

  def test_mongo_indexes_reports_no_indexes_needed
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_mongo_config(dir, indexes: [])

      status, stdout, stderr = run_cli("mongo", "indexes", "--config", config_path)

      assert_equal 0, status, stderr
      assert_includes stdout, "No MongoDB indexes needed."
    end
  end

  def test_mongo_indexes_reports_malformed_index_metadata
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_mongo_config(dir, indexes: [{collection: "users", unique: true}])

      status, _stdout, stderr = run_cli("mongo", "indexes", "--config", config_path)

      assert_equal 1, status
      assert_includes stderr, "MongoDB index metadata must include collection and field"
    end
  end

  def test_mongo_indexes_reports_unsupported_adapter
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_hash_config(dir, secret: SECRET, database: :memory)

      status, _stdout, stderr = run_cli("mongo", "indexes", "--config", config_path)

      assert_equal 1, status
      assert_includes stderr, "ensure_indexes"
    end
  end

  def test_better_auth_executable_is_packaged
    spec = Gem::Specification.load(File.expand_path("../../better_auth-cli.gemspec", __dir__))

    assert_includes spec.executables, "better-auth"
    refute_includes spec.executables, "openauth"
  end
end

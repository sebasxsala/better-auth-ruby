# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../../better_auth/lib", __dir__)

require "better_auth/cli"
require "fileutils"
require "minitest/autorun"
require "sqlite3"
require "stringio"
require "tmpdir"

class BetterAuthCLITest < Minitest::Test
  SECRET = "cli-secret-that-is-long-enough-for-validation"

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

  def test_migrate_applies_pending_schema_and_status_reports_no_changes
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = write_sqlite_config(dir)

      status, _stdout, stderr = run_cli("migrate", "--config", config_path, "--yes")
      assert_equal 0, status, stderr

      db = SQLite3::Database.new(File.join(dir, "auth.sqlite3"))
      tables = db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").flatten
      assert_includes tables, "users"

      status, stdout, stderr = run_cli("migrate", "status", "--config", config_path)
      assert_equal 0, status, stderr
      assert_includes stdout, "No migrations needed."
    end
  end

  def test_migrate_reports_unsupported_adapter
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = File.join(dir, "better_auth.rb")
      File.write(config_path, "{secret: #{SECRET.inspect}, database: :memory}")

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
        secret: "doctor-secret-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
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
    end
  end

  def test_mongo_indexes_calls_adapter_index_setup
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = File.join(dir, "better_auth.rb")
      File.write(
        config_path,
        <<~RUBY
          {
            secret: #{SECRET.inspect},
            database: ->(options) do
              Class.new(BetterAuth::Adapters::Base) do
                def ensure_indexes!
                  [
                    {collection: "users", field: "email", unique: true},
                    {collection: "sessions", field: "token", unique: false}
                  ]
                end
              end.new(options)
            end
          }
        RUBY
      )

      status, stdout, stderr = run_cli("mongo", "indexes", "--config", config_path)

      assert_equal 0, status, stderr
      assert_includes stdout, "ensured unique index users.email"
      assert_includes stdout, "ensured index sessions.token"
    end
  end

  def test_mongo_indexes_reports_unsupported_adapter
    Dir.mktmpdir("better-auth-cli") do |dir|
      config_path = File.join(dir, "better_auth.rb")
      File.write(config_path, "{secret: #{SECRET.inspect}, database: :memory}")

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

  private

  def run_cli(*argv)
    stdout = StringIO.new
    stderr = StringIO.new
    status = BetterAuth::CLI.run(argv, stdout: stdout, stderr: stderr)
    [status, stdout.string, stderr.string]
  end

  def write_sqlite_config(dir, secret: SECRET, base_url: nil, rate_limit: nil)
    path = File.join(dir, "better_auth.rb")
    db_path = File.join(dir, "auth.sqlite3")
    rate_limit_line = rate_limit ? ",\n  rate_limit: #{rate_limit.inspect}" : ""
    base_url_line = base_url ? ",\n  base_url: #{base_url.inspect}" : ""
    File.write(
      path,
      <<~RUBY
        {
          secret: #{secret.inspect},
          database: ->(options) { BetterAuth::Adapters::SQLite.new(options, path: #{db_path.inspect}) },
          email_and_password: {enabled: true}#{base_url_line}#{rate_limit_line}
        }
      RUBY
    )
    path
  end
end

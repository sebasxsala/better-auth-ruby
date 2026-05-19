# frozen_string_literal: true

require_relative "../test_helper"
require "better_auth/doctor"
require "sqlite3"

class BetterAuthDoctorTest < Minitest::Test
  def test_reports_errors_warnings_and_ok_items
    config = BetterAuth::Configuration.new(
      secret: BetterAuth::Configuration::DEFAULT_SECRET,
      base_url: "http://example.test",
      database: ->(options) { BetterAuth::Adapters::SQLite.new(options, connection: sqlite_connection) }
    )

    result = BetterAuth::Doctor.check(config)

    assert result.errors.any? { |error| error.include?("secret uses the default") }
    assert result.warnings.any? { |warning| warning.include?("base_url is not HTTPS") }
    assert result.warnings.any? { |warning| warning.include?("rate_limit uses memory storage") }
    assert result.warnings.any? { |warning| warning.include?("pending Better Auth migrations") }
    assert_includes result.ok, "config loaded"
  end

  def test_passes_for_hardened_config_with_current_schema
    connection = sqlite_connection
    config = BetterAuth::Configuration.new(
      secret: "doctor-secret-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      base_url: "https://example.test",
      rate_limit: {enabled: true, storage: "database"},
      database: ->(options) { BetterAuth::Adapters::SQLite.new(options, connection: connection) }
    )
    BetterAuth::SQLMigration.migrate_pending(BetterAuth.auth(config.to_h))

    result = BetterAuth::Doctor.check(config)

    assert_empty result.errors
    assert_empty result.warnings
    assert_includes result.ok, "secret length and entropy look acceptable"
    assert_includes result.ok, "database schema is up to date"
  end

  private

  def sqlite_connection
    SQLite3::Database.new(":memory:").tap do |connection|
      connection.results_as_hash = true
      connection.execute("PRAGMA foreign_keys = ON")
    end
  end
end

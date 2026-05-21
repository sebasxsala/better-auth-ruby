# frozen_string_literal: true

require_relative "../../test_helper"
require "minitest/mock"
require "better_auth"
require "better_auth/telemetry/detectors/database"

class DatabaseDetectorTest < Minitest::Test
  Database = BetterAuth::Telemetry::Detectors::Database

  # ---------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------

  # Run the block with `Gem.loaded_specs` stubbed to `specs` (a
  # `Hash<String, Gem::Specification|FakeSpec>`). Restores the real
  # value on the way out.
  def with_loaded_specs(specs)
    ::Gem.stub(:loaded_specs, specs) do
      yield
    end
  end

  # Minimal stand-in for `Gem::Specification` that responds to
  # `#version` with a real `Gem::Version`. Used to drive the gem
  # fallback branch without depending on the live gem environment.
  FakeSpec = Struct.new(:version) do
    def self.with_version(string)
      new(::Gem::Version.new(string))
    end
  end

  # Minimal stand-in for {NormalizedContext}. The detector reads
  # `#database` first and, when it is the generic "adapter" marker,
  # may refine the signal from `#adapter`.
  StubContext = Struct.new(:database, :adapter, keyword_init: true)

  # Build a {BetterAuth::Configuration} with a specific `database`
  # value and the minimum other keys needed to instantiate it without
  # raising on missing-secret validation.
  def configuration_with_database(database)
    BetterAuth::Configuration.new(
      secret: "0" * 40,
      database: database
    )
  end

  # ---------------------------------------------------------------------
  # 1. Context override (Requirement 10.1)
  # ---------------------------------------------------------------------

  def test_context_database_override_short_circuits_with_nil_version
    context = StubContext.new(database: "postgresql")

    result = Database.call(nil, context)

    assert_equal({name: "postgresql", version: nil}, result)
  end

  def test_context_override_wins_over_configuration_database
    context = StubContext.new(database: "custom-db")
    config = configuration_with_database(:postgres)

    result = Database.call(config, context)

    assert_equal({name: "custom-db", version: nil}, result)
  end

  def test_context_override_wins_over_gem_fallback
    context = StubContext.new(database: "custom-db")

    with_loaded_specs("pg" => FakeSpec.with_version("1.5.6")) do
      assert_equal({name: "custom-db", version: nil}, Database.call(nil, context))
    end
  end

  def test_empty_context_database_is_ignored
    context = StubContext.new(database: "")

    with_loaded_specs({}) do
      assert_nil Database.call(nil, context)
    end
  end

  def test_non_string_context_database_is_ignored
    context = StubContext.new(database: :postgres)

    with_loaded_specs({}) do
      assert_nil Database.call(nil, context)
    end
  end

  def test_nil_context_falls_through
    with_loaded_specs({}) do
      assert_nil Database.call(nil, nil)
    end
  end

  def test_hash_context_with_symbol_key_is_honored
    with_loaded_specs({}) do
      assert_equal({name: "mongo", version: nil}, Database.call(nil, {database: "mongo"}))
    end
  end

  def test_hash_context_with_string_key_is_honored
    with_loaded_specs({}) do
      assert_equal({name: "mongo", version: nil}, Database.call(nil, {"database" => "mongo"}))
    end
  end

  def test_context_generic_adapter_marker_uses_known_adapter_class
    expected = {
      "BetterAuth::Adapters::Memory" => "memory",
      "BetterAuth::Adapters::Postgres" => "postgres",
      "BetterAuth::Adapters::MySQL" => "mysql",
      "BetterAuth::Adapters::SQLite" => "sqlite",
      "BetterAuth::Adapters::MSSQL" => "mssql",
      "BetterAuth::Adapters::MongoDB" => "mongodb"
    }

    expected.each do |adapter_class_name, database_name|
      context = StubContext.new(database: "adapter", adapter: adapter_class_name)

      with_loaded_specs({}) do
        assert_equal(
          {name: database_name, version: nil},
          Database.call(nil, context),
          "expected context adapter #{adapter_class_name.inspect} to resolve"
        )
      end
    end
  end

  def test_hash_context_generic_adapter_marker_uses_known_adapter_class
    context = {
      database: "adapter",
      adapter: "BetterAuth::Adapters::MongoDB"
    }

    with_loaded_specs({}) do
      assert_equal({name: "mongodb", version: nil}, Database.call(nil, context))
    end
  end

  def test_hash_context_string_keys_generic_adapter_marker_uses_known_adapter_class
    context = {
      "database" => "adapter",
      "adapter" => "BetterAuth::Adapters::MongoDB"
    }

    with_loaded_specs({}) do
      assert_equal({name: "mongodb", version: nil}, Database.call(nil, context))
    end
  end

  def test_custom_context_database_wins_over_known_adapter_class
    context = StubContext.new(database: "custom-db", adapter: "BetterAuth::Adapters::MongoDB")

    with_loaded_specs({}) do
      assert_equal({name: "custom-db", version: nil}, Database.call(nil, context))
    end
  end

  def test_unknown_context_adapter_class_remains_generic_adapter
    context = StubContext.new(database: "adapter", adapter: "Acme::Internal::ShardAdapter")

    with_loaded_specs({}) do
      assert_equal({name: "adapter", version: nil}, Database.call(nil, context))
    end
  end

  # ---------------------------------------------------------------------
  # 2. Configuration adapter (Requirement 10.2)
  # ---------------------------------------------------------------------

  def test_configuration_with_known_adapter_symbol_resolves
    {
      postgres: "postgres",
      mysql: "mysql",
      sqlite: "sqlite",
      mssql: "mssql",
      memory: "memory"
    }.each do |symbol, expected|
      config = configuration_with_database(symbol)

      with_loaded_specs({}) do
        assert_equal(
          {name: expected, version: nil},
          Database.call(config, nil),
          "expected database=#{symbol.inspect} to resolve to #{expected.inspect}"
        )
      end
    end
  end

  def test_configuration_with_known_adapter_instance_resolves_to_short_identifier
    instance = BetterAuth::Adapters::Memory.new(
      configuration_with_database(:memory)
    )
    config = configuration_with_database(instance)

    with_loaded_specs({}) do
      assert_equal({name: "memory", version: nil}, Database.call(config, nil))
    end
  end

  def test_identify_adapter_resolves_every_known_adapter_class_name
    expected = {
      "BetterAuth::Adapters::Memory" => "memory",
      "BetterAuth::Adapters::Postgres" => "postgres",
      "BetterAuth::Adapters::MySQL" => "mysql",
      "BetterAuth::Adapters::SQLite" => "sqlite",
      "BetterAuth::Adapters::MSSQL" => "mssql",
      "BetterAuth::Adapters::MongoDB" => "mongodb"
    }

    expected.each do |class_name, database_name|
      adapter_class = Class.new
      adapter_class.define_singleton_method(:name) { class_name }
      adapter = adapter_class.new

      assert_equal database_name, Database.identify_adapter(adapter)
    end
  end

  def test_configuration_with_unknown_database_symbol_falls_through
    config = configuration_with_database(:redis)

    with_loaded_specs({}) do
      assert_nil Database.call(config, nil)
    end
  end

  def test_configuration_with_nil_database_falls_through
    config = configuration_with_database(nil)

    with_loaded_specs({}) do
      assert_nil Database.call(config, nil)
    end
  end

  def test_hash_options_with_known_database_symbol_resolves
    with_loaded_specs({}) do
      assert_equal(
        {name: "postgres", version: nil},
        Database.call({database: :postgres}, nil)
      )
    end
  end

  def test_hash_options_with_string_key_database_symbol_resolves
    with_loaded_specs({}) do
      assert_equal(
        {name: "postgres", version: nil},
        Database.call({"database" => :postgres}, nil)
      )
    end
  end

  def test_configuration_database_takes_precedence_over_gem_fallback
    config = configuration_with_database(:sqlite)

    with_loaded_specs("pg" => FakeSpec.with_version("1.5.6")) do
      assert_equal({name: "sqlite", version: nil}, Database.call(config, nil))
    end
  end

  # ---------------------------------------------------------------------
  # 3. Gem fallback (Requirement 10.3)
  # ---------------------------------------------------------------------

  def test_first_gem_in_fallback_order_wins
    specs = {
      "sequel" => FakeSpec.with_version("5.78.0"),
      "pg" => FakeSpec.with_version("1.5.6"),
      "activerecord" => FakeSpec.with_version("7.1.3")
    }

    with_loaded_specs(specs) do
      assert_equal({name: "sequel", version: "5.78.0"}, Database.call(nil, nil))
    end
  end

  def test_gem_fallback_returns_each_listed_gem_when_singled_out
    Database::GEM_FALLBACKS.each do |gem_name|
      specs = {gem_name => FakeSpec.with_version("9.9.9")}

      with_loaded_specs(specs) do
        assert_equal(
          {name: gem_name, version: "9.9.9"},
          Database.call(nil, nil),
          "expected the lone presence of #{gem_name.inspect} to win the fallback"
        )
      end
    end
  end

  def test_gem_fallback_skips_unknown_gems
    specs = {"redis" => FakeSpec.with_version("5.0.0")}

    with_loaded_specs(specs) do
      assert_nil Database.call(nil, nil)
    end
  end

  def test_gem_fallback_only_runs_when_options_path_does_not_match
    # An unknown configuration symbol falls through to the gem fallback.
    config = configuration_with_database(:redis)
    specs = {"mysql2" => FakeSpec.with_version("0.5.6")}

    with_loaded_specs(specs) do
      assert_equal({name: "mysql2", version: "0.5.6"}, Database.call(config, nil))
    end
  end

  # ---------------------------------------------------------------------
  # 4. No match (Requirement 10.4)
  # ---------------------------------------------------------------------

  def test_returns_nil_when_no_signal_is_available
    with_loaded_specs({}) do
      assert_nil Database.call(nil, nil)
    end
  end

  # ---------------------------------------------------------------------
  # Failure handling: the whole call is wrapped in `rescue StandardError`.
  # ---------------------------------------------------------------------

  def test_returns_nil_when_gem_loaded_specs_raises
    raising = lambda { raise "boom" }

    ::Gem.stub(:loaded_specs, raising) do
      assert_nil Database.call(nil, nil)
    end
  end

  def test_returns_nil_when_context_database_reader_raises
    bad_context = Object.new
    def bad_context.database
      raise "boom"
    end

    with_loaded_specs({}) do
      assert_nil Database.call(nil, bad_context)
    end
  end
end

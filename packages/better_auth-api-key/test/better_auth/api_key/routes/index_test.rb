# frozen_string_literal: true

require_relative "../test_support"

class BetterAuthAPIKeyRoutesIndexTest < Minitest::Test
  include APIKeyTestSupport

  def setup
    BetterAuth::APIKey::Routes.instance_variable_set(:@last_expired_check, nil)
  end

  def test_config_id_matching_treats_nil_empty_and_default_as_default
    assert BetterAuth::APIKey::Routes.default_config_id?(nil)
    assert BetterAuth::APIKey::Routes.default_config_id?("")
    assert BetterAuth::APIKey::Routes.default_config_id?("default")
    assert BetterAuth::APIKey::Routes.config_id_matches?(nil, "default")
    assert BetterAuth::APIKey::Routes.config_id_matches?("", nil)
    refute BetterAuth::APIKey::Routes.config_id_matches?("service", "default")
  end

  def test_resolve_config_falls_back_to_default_when_requested_id_is_unknown
    logger = Struct.new(:messages) do
      def error(message)
        messages << message
      end
    end.new([])
    context = Struct.new(:logger).new(logger)
    config = BetterAuth::APIKey::Configuration.normalize([
      {config_id: "default", default_prefix: "def_", default_key_length: 12},
      {config_id: "service", default_prefix: "svc_", default_key_length: 12}
    ])

    selected = BetterAuth::APIKey::Routes.resolve_config(context, config, "missing")

    assert_equal "default", selected.fetch(:config_id)
    assert_equal "def_", selected.fetch(:default_prefix)
    assert_empty logger.messages
  end

  def test_delete_expired_throttles_regular_cleanup_and_bypass_deletes_immediately
    auth = build_api_key_auth(default_key_length: 12)
    config = BetterAuth::APIKey::Configuration.normalize({})
    first = create_expired_record(auth, "first-expired-key")

    BetterAuth::APIKey::Routes.delete_expired(auth.context, config)
    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: first.fetch("id")}])

    second = create_expired_record(auth, "second-expired-key")
    BetterAuth::APIKey::Routes.delete_expired(auth.context, config)
    assert auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: second.fetch("id")}])

    BetterAuth::APIKey::Routes.delete_expired(auth.context, config, bypass_last_check: true)
    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: second.fetch("id")}])
  end

  def test_delete_expired_uses_adapter_delete_many_semantics
    auth = build_api_key_auth(default_key_length: 12)
    config = BetterAuth::APIKey::Configuration.normalize({})
    now = Time.now

    expired = auth.context.adapter.create(
      model: "apikey",
      data: base_api_key_row("expired", now - 120, reference_id: "r1")
    )
    future = auth.context.adapter.create(
      model: "apikey",
      data: base_api_key_row("future", now + 3600, reference_id: "r2")
    )
    no_expiry = auth.context.adapter.create(
      model: "apikey",
      data: base_api_key_row("no-expiry", nil, reference_id: "r3")
    )

    BetterAuth::APIKey::Routes.delete_expired(auth.context, config, bypass_last_check: true)

    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: expired.fetch("id")}])
    refute_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: future.fetch("id")}])
    refute_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: no_expiry.fetch("id")}])
  end

  def test_delete_expired_uses_sql_null_predicates_for_database_adapters
    options = BetterAuth::Configuration.new(
      secret: "api-key-sql-null-predicate-secret",
      database: :memory,
      plugins: [BetterAuth::Plugins.api_key]
    )
    connection = RecordingSQLConnection.new
    adapter = BetterAuth::Adapters::SQL.new(options, connection: connection, dialect: :mssql)
    context = Struct.new(:adapter, :logger).new(adapter, nil)
    config = BetterAuth::APIKey::Configuration.normalize({})

    BetterAuth::APIKey::Routes.delete_expired(context, config, bypass_last_check: true)

    assert_includes connection.sql.first, "[api_keys].[expires_at] < ?"
    assert_includes connection.sql.first, "[api_keys].[expires_at] IS NOT NULL"
    assert_equal 1, connection.params.first.length
  end

  def test_deferred_schedule_cleanup_logs_failures
    deferred = []
    errors = []
    auth = build_api_key_auth(
      defer_updates: true,
      advanced: {background_tasks: {handler: ->(task) { deferred << task }}}
    )
    logger = Object.new
    logger.define_singleton_method(:error) { |message, *| errors << message }
    auth.context.define_singleton_method(:logger) { logger }
    auth.context.adapter.define_singleton_method(:delete_many) do |**|
      raise StandardError, "simulated cleanup failure"
    end
    ctx = Struct.new(:context).new(auth.context)
    config = BetterAuth::APIKey::Configuration.normalize(defer_updates: true)

    BetterAuth::APIKey::Routes.schedule_cleanup(ctx, config)
    deferred.each(&:call)

    assert_equal 1, errors.length
    assert_match(/simulated cleanup failure/, errors.first)
  end

  def test_regular_delete_expired_logs_adapter_failure_without_raising
    errors = []
    auth = build_api_key_auth(default_key_length: 12)
    logger = Object.new
    logger.define_singleton_method(:error) { |message, *| errors << message }
    auth.context.define_singleton_method(:logger) { logger }
    auth.context.adapter.define_singleton_method(:delete_many) do |**|
      raise StandardError, "simulated cleanup failure"
    end
    config = BetterAuth::APIKey::Configuration.normalize({})

    BetterAuth::APIKey::Routes.delete_expired(auth.context, config, bypass_last_check: true)

    assert_equal 1, errors.length
    assert_match(/simulated cleanup failure/, errors.first)
  end

  private

  def create_expired_record(auth, key)
    now = Time.now
    auth.context.adapter.create(model: "apikey", data: base_api_key_row(key, now - 60, reference_id: "reference-id"))
  end

  def base_api_key_row(key_material, expires_at, reference_id:)
    now = Time.now
    {
      configId: "default",
      createdAt: now,
      updatedAt: now,
      name: nil,
      prefix: nil,
      start: key_material.to_s[0, 6],
      key: key_material,
      enabled: true,
      expiresAt: expires_at,
      referenceId: reference_id,
      lastRefillAt: nil,
      lastRequest: nil,
      metadata: nil,
      rateLimitMax: 10,
      rateLimitTimeWindow: 86_400_000,
      remaining: nil,
      refillAmount: nil,
      refillInterval: nil,
      rateLimitEnabled: true,
      requestCount: 0,
      permissions: nil
    }
  end

  RecordingSQLConnection = Struct.new(:sql, :params) do
    def initialize
      super([], [])
    end

    def exec_params(statement, bind_params)
      sql << statement
      params << bind_params
      []
    end
  end
end

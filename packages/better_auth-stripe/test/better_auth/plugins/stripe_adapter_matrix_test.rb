# frozen_string_literal: true

require "json"
require "tempfile"
require_relative "../../test_helper"
require_relative "../../support/stripe_helpers"

class BetterAuthPluginsStripeAdapterMatrixTest < Minitest::Test
  include BetterAuthStripeTestHelpers

  SECRET = "phase-twelve-secret-with-enough-entropy-123"
  FakeStripeClient = BetterAuthStripeTestHelpers::FakeStripeClient

  def test_memory_adapter_persists_representative_stripe_flow
    stripe = FakeStripeClient.new
    auth = build_matrix_auth(stripe: stripe, database: :memory)

    assert_stripe_flow_persists_subscription(auth, stripe, email: "stripe-memory@example.com")
  end

  def test_sqlite_adapter_persists_representative_stripe_flow
    require "sqlite3"

    Tempfile.create(["better-auth-stripe", ".sqlite3"]) do |file|
      stripe = FakeStripeClient.new
      plugin = stripe_plugin(stripe)
      config = matrix_config(plugin)
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      BetterAuth::Schema::SQL.create_statements(config, dialect: :sqlite).each { |statement| connection.execute(statement) }
      auth = build_matrix_auth(stripe: stripe, plugin: plugin, database: ->(options) { BetterAuth::Adapters::SQLite.new(options, connection: connection) })

      assert_stripe_flow_persists_subscription(auth, stripe, email: "stripe-sqlite@example.com")
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_postgres_adapter_persists_representative_stripe_flow_when_available
    require "pg"

    connection = PG.connect(ENV.fetch("BETTER_AUTH_POSTGRES_URL", "postgres://user:password@localhost:5432/better_auth"))
    stripe = FakeStripeClient.new
    plugin = stripe_plugin(stripe)
    config = matrix_config(plugin)
    reset_postgres_schema(connection)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :postgres).each { |statement| connection.exec(statement) }
    auth = build_matrix_auth(stripe: stripe, plugin: plugin, database: ->(options) { BetterAuth::Adapters::Postgres.new(options, connection: connection) })

    assert_stripe_flow_persists_subscription(auth, stripe, email: "stripe-postgres@example.com")
  rescue LoadError
    skip "pg gem is not installed"
  rescue PG::ConnectionBad
    skip "PostgreSQL test service is not available"
  ensure
    connection&.close
  end

  def test_mysql_adapter_persists_representative_stripe_flow_when_available
    require "mysql2"

    connection = mysql_connection
    stripe = FakeStripeClient.new
    plugin = stripe_plugin(stripe)
    config = matrix_config(plugin)
    reset_mysql_schema(connection)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :mysql).each { |statement| connection.query(statement) }
    auth = build_matrix_auth(stripe: stripe, plugin: plugin, database: ->(options) { BetterAuth::Adapters::MySQL.new(options, connection: connection) })

    assert_stripe_flow_persists_subscription(auth, stripe, email: "stripe-mysql@example.com")
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  ensure
    connection&.close
  end

  def test_mssql_adapter_persists_representative_stripe_flow_when_available
    require "sequel"
    require "tiny_tds"

    ensure_mssql_database
    connection = Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_URL", "tinytds://sa:Password123!@127.0.0.1:1433/better_auth?timeout=30"))
    stripe = FakeStripeClient.new
    plugin = stripe_plugin(stripe)
    config = matrix_config(plugin)
    reset_mssql_schema(connection)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :mssql).each { |statement| connection.run(statement) }
    auth = build_matrix_auth(stripe: stripe, plugin: plugin, database: ->(options) { BetterAuth::Adapters::MSSQL.new(options, connection: connection) })

    assert_stripe_flow_persists_subscription(auth, stripe, email: "stripe-mssql@example.com")
  rescue LoadError
    skip "sequel or tiny_tds gem is not installed"
  rescue Sequel::DatabaseConnectionError
    skip "MSSQL test service is not available"
  ensure
    connection&.disconnect
  end

  def test_mongodb_adapter_persists_representative_stripe_flow_when_available
    load_mongodb_test_support!

    stripe = FakeStripeClient.new
    plugin = stripe_plugin(stripe)
    database = BetterAuthMongoAdapterTestSupport::FakeMongoDatabase.new
    auth = build_matrix_auth(
      stripe: stripe,
      plugin: plugin,
      database: ->(options) { BetterAuth::Adapters::MongoDB.new(options, database: database) }
    )

    assert_stripe_flow_persists_subscription(auth, stripe, email: "stripe-mongodb@example.com")
  rescue LoadError
    skip "MongoDB adapter test support or mongo gem is not available"
  end

  private

  def stripe_plugin(stripe)
    BetterAuth::Plugins.stripe(stripe_client: stripe, stripe_webhook_secret: "whsec_test", subscription: subscription_options)
  end

  def matrix_config(plugin)
    BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: [plugin])
  end

  def build_matrix_auth(stripe:, database:, plugin: nil)
    plugin ||= stripe_plugin(stripe)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: database,
      email_and_password: {enabled: true},
      session: {cookie_cache: {enabled: false}},
      plugins: [plugin]
    )
  end

  def assert_stripe_flow_persists_subscription(auth, stripe, email:)
    cookie = sign_up_cookie(auth, email: email)
    checkout = auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", successUrl: "/success", cancelUrl: "/cancel"})
    user = auth.context.internal_adapter.find_user_by_email(email)[:user]
    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "referenceId", value: user.fetch("id")}])

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    assert_equal 1, stripe.customers.created.length
    assert_equal "pro", subscription.fetch("plan")
    assert_equal "incomplete", subscription.fetch("status")
    assert_equal user.fetch("stripeCustomerId"), subscription.fetch("stripeCustomerId")
    assert_equal 1, subscription.fetch("seats")
    assert_equal({"projects" => 10}, stringify_keys(subscription.fetch("limits")))

    updated = auth.context.adapter.update(
      model: "subscription",
      where: [{field: "id", value: subscription.fetch("id")}],
      update: {
        stripeSubscriptionId: "sub_matrix",
        cancelAtPeriodEnd: false,
        billingInterval: "month",
        stripeScheduleId: "sched_matrix"
      }
    )

    assert_equal "sub_matrix", updated.fetch("stripeSubscriptionId")
    assert_equal false, updated.fetch("cancelAtPeriodEnd")
    assert_equal "month", updated.fetch("billingInterval")
    assert_equal "sched_matrix", updated.fetch("stripeScheduleId")
  end

  def reset_postgres_schema(connection)
    %w[rate_limits subscriptions accounts sessions users].each do |table|
      connection.exec(%(DROP TABLE IF EXISTS "#{table}" CASCADE))
    end
  end

  def stringify_keys(value)
    return value unless value.is_a?(Hash)

    value.transform_keys(&:to_s)
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
      connection.query("DROP TABLE IF EXISTS `#{table.to_s.gsub("`", "``")}`")
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

  def ensure_mssql_database
    master = Sequel.connect(ENV.fetch("BETTER_AUTH_MSSQL_MASTER_URL", "tinytds://sa:Password123!@127.0.0.1:1433/master?timeout=30"))
    master.run("IF DB_ID(N'better_auth') IS NULL CREATE DATABASE [better_auth]")
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

  def load_mongodb_test_support!
    package_root = File.expand_path("../../../../..", __dir__)
    mongodb_lib = File.join(package_root, "better_auth-mongodb", "lib")
    $LOAD_PATH.unshift(mongodb_lib) unless $LOAD_PATH.include?(mongodb_lib)
    require "better_auth/mongodb"
    require File.join(package_root, "better_auth-mongodb", "test", "support", "fake_mongo")
  end
end

# frozen_string_literal: true

require "minitest/autorun"
require "mysql2"
require "better_auth"
require "better_auth/api_key"
require "better_auth/passkey"
require "better_auth/oauth_provider"
require "better_auth/scim"
require "better_auth/sso"
require "better_auth/stripe"

class BetterAuthMySQLPluginSchemaSmokeTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def setup
    @connection = mysql_connection
    reset_mysql_schema
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  end

  def teardown
    reset_mysql_schema if @connection
    @connection&.close
  end

  def test_mysql_ddl_supports_representative_plugin_schemas
    plugin_cases.each do |name, data|
      reset_mysql_schema
      config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, plugins: data.fetch(:plugins))

      BetterAuth::Schema::SQL.create_statements(config, dialect: :mysql).each do |statement|
        @connection.query(statement)
      end

      data.fetch(:tables).each do |table|
        assert_includes mysql_table_names, table, "expected #{name} to create #{table}"
      end
    end
  end

  private

  def plugin_cases
    {
      "core" => {
        plugins: [],
        tables: %w[users sessions accounts verifications]
      },
      "organization" => {
        plugins: [BetterAuth::Plugins.organization(teams: {enabled: true}, dynamic_access_control: {enabled: true})],
        tables: %w[organizations members invitations teams team_members organization_roles]
      },
      "identity" => {
        plugins: [
          BetterAuth::Plugins.username,
          BetterAuth::Plugins.anonymous,
          BetterAuth::Plugins.phone_number,
          BetterAuth::Plugins.siwe(get_nonce: -> { "nonce" }, verify_message: ->(**) { true })
        ],
        tables: %w[users wallet_addresses]
      },
      "two_factor_passkey" => {
        plugins: [BetterAuth::Plugins.two_factor, BetterAuth::Plugins.passkey],
        tables: %w[two_factors passkeys]
      },
      "api_key" => {
        plugins: [BetterAuth::Plugins.api_key],
        tables: %w[api_keys]
      },
      "oauth_provider" => {
        plugins: [BetterAuth::Plugins.oauth_provider(allow_dynamic_client_registration: true)],
        tables: %w[oauth_clients oauth_access_tokens oauth_refresh_tokens oauth_consents]
      },
      "scim_sso" => {
        plugins: [BetterAuth::Plugins.scim, BetterAuth::Plugins.sso],
        tables: %w[scim_providers sso_providers]
      },
      "stripe_subscription" => {
        plugins: [BetterAuth::Plugins.stripe(subscription: {enabled: true, plans: []}, organization: {enabled: true})],
        tables: %w[subscriptions organizations]
      },
      "mcp_oidc" => {
        plugins: [BetterAuth::Plugins.mcp, oidc_provider_plugin],
        tables: %w[oauth_clients oauth_applications oauth_access_tokens oauth_consents]
      }
    }
  end

  def oidc_provider_plugin
    plugin = nil
    capture_io { plugin = BetterAuth::Plugins.oidc_provider }
    plugin
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

  def reset_mysql_schema
    @connection.query("SET FOREIGN_KEY_CHECKS = 0")
    mysql_table_names.each do |table|
      @connection.query("DROP TABLE IF EXISTS #{quote_mysql_identifier(table)}")
    end
  ensure
    @connection&.query("SET FOREIGN_KEY_CHECKS = 1")
  end

  def mysql_table_names
    @connection.query(<<~SQL).map { |row| row["table_name"] || row.fetch("TABLE_NAME") }
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
    SQL
  end

  def quote_mysql_identifier(identifier)
    "`#{identifier.to_s.gsub("`", "``")}`"
  end
end

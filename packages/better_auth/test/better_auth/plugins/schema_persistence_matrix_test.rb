# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPluginsSchemaPersistenceMatrixTest < Minitest::Test
  SECRET = "plugin-schema-secret-with-enough-entropy"

  def test_core_schema_adding_plugins_render_for_supported_sql_dialects
    config = schema_config
    table_names = BetterAuth::Schema.auth_tables(config).values.map { |table| table.fetch(:model_name) }

    %i[sqlite postgres mysql mssql].each do |dialect|
      sql = BetterAuth::Schema::SQL.create_statements(config, dialect: dialect).join("\n")

      table_names.each do |table_name|
        assert_includes sql, table_name, "expected #{dialect} SQL to include #{table_name}"
      end
    end
  end

  def test_core_schema_adding_plugins_execute_combined_schema_on_sqlite
    require "sqlite3"

    db = SQLite3::Database.new(":memory:")
    BetterAuth::Schema::SQL.create_statements(schema_config, dialect: :sqlite).each { |statement| db.execute(statement) }
    tables = db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").flatten.sort

    assert_equal %w[
      accounts
      device_codes
      invitations
      jwks
      members
      organization_roles
      organizations
      rate_limits
      sessions
      team_members
      teams
      two_factors
      users
      verifications
      wallet_addresses
    ], tables
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_core_schema_adding_plugins_merge_expected_memory_fields
    tables = BetterAuth::Schema.auth_tables(schema_config)

    user_fields = tables.fetch("user").fetch(:fields)
    assert_includes user_fields, "username"
    assert_includes user_fields, "displayUsername"
    assert_includes user_fields, "isAnonymous"
    assert_includes user_fields, "phoneNumber"
    assert_includes user_fields, "phoneNumberVerified"
    assert_includes user_fields, "twoFactorEnabled"
    assert_includes user_fields, "lastLoginMethod"
    assert_includes user_fields, "plan"

    session_fields = tables.fetch("session").fetch(:fields)
    assert_includes session_fields, "activeOrganizationId"
    assert_includes session_fields, "activeTeamId"
    assert_includes session_fields, "traceId"

    assert_includes tables.fetch("twoFactor").fetch(:fields), "backupCodes"
    assert_includes tables.fetch("deviceCode").fetch(:fields), "pollingInterval"
    assert_includes tables.fetch("walletAddress").fetch(:fields), "address"
    assert_includes tables.fetch("jwks").fetch(:fields), "privateKey"
    assert_includes tables.fetch("organizationRole").fetch(:fields), "permission"
  end

  private

  def schema_config
    BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      rate_limit: {storage: "database"},
      plugins: [
        BetterAuth::Plugins.username,
        BetterAuth::Plugins.anonymous,
        BetterAuth::Plugins.phone_number(send_otp: ->(_data, _ctx = nil) {}),
        BetterAuth::Plugins.two_factor,
        BetterAuth::Plugins.organization(teams: {enabled: true}, dynamic_access_control: {enabled: true}),
        BetterAuth::Plugins.jwt,
        BetterAuth::Plugins.device_authorization,
        BetterAuth::Plugins.siwe,
        BetterAuth::Plugins.last_login_method(store_in_database: true),
        BetterAuth::Plugins.additional_fields(
          user: {plan: {type: "string", required: false}},
          session: {traceId: {type: "string", required: false}}
        ),
        BetterAuth::Plugins.custom_session(->(session, _ctx) { session })
      ]
    )
  end
end

# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthSchemaTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_core_tables_preserve_logical_names_and_default_to_postgres_snake_case_storage_names
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    schema = BetterAuth::Schema.auth_tables(config)

    assert_equal %w[user session account verification], schema.keys
    assert_equal "users", schema["user"][:model_name]
    assert_equal "sessions", schema["session"][:model_name]
    assert_equal "accounts", schema["account"][:model_name]
    assert_equal "verifications", schema["verification"][:model_name]

    assert_equal %w[id name email emailVerified image createdAt updatedAt], schema["user"][:fields].keys
    assert_equal "boolean", schema["user"][:fields]["emailVerified"][:type]
    assert_equal false, schema["user"][:fields]["emailVerified"][:input]
    assert_equal true, schema["user"][:fields]["email"][:unique]
    assert_equal true, schema["account"][:fields]["userId"][:index]
    assert_equal true, schema["session"][:fields]["token"][:unique]
    assert_equal true, schema["session"][:fields]["userId"][:index]
    assert_equal true, schema["verification"][:fields]["identifier"][:index]
    assert_equal "users", schema["session"][:fields]["userId"][:references][:model]
    assert_equal "email_verified", schema["user"][:fields]["emailVerified"][:field_name]
    assert_equal "created_at", schema["user"][:fields]["createdAt"][:field_name]
    assert_equal "updated_at", schema["user"][:fields]["updatedAt"][:field_name]
    assert_equal "user_id", schema["session"][:fields]["userId"][:field_name]
    assert_equal "ip_address", schema["session"][:fields]["ipAddress"][:field_name]
    assert_equal "user_agent", schema["session"][:fields]["userAgent"][:field_name]
    assert_equal "access_token", schema["account"][:fields]["accessToken"][:field_name]
    assert_equal "refresh_token_expires_at", schema["account"][:fields]["refreshTokenExpiresAt"][:field_name]
    assert_equal "last_request", BetterAuth::Schema.auth_tables(
      BetterAuth::Configuration.new(secret: SECRET, database: :memory, rate_limit: {storage: "database"})
    ).fetch("rateLimit").fetch(:fields).fetch("lastRequest").fetch(:field_name)
    assert_equal "rate_limits", BetterAuth::Schema.auth_tables(
      BetterAuth::Configuration.new(secret: SECRET, database: :memory, rate_limit: {storage: "database"})
    ).fetch("rateLimit").fetch(:model_name)
  end

  def test_custom_field_mappings_and_additional_fields_merge_into_core_tables
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      user: {
        fields: {
          email: "email_address",
          emailVerified: "email_verified"
        },
        additional_fields: {
          "role" => {type: "string", default_value: "member"}
        }
      },
      session: {
        fields: {
          userId: "user_id"
        }
      }
    )

    schema = BetterAuth::Schema.auth_tables(config)

    assert_equal "email_address", schema["user"][:fields]["email"][:field_name]
    assert_equal "email_verified", schema["user"][:fields]["emailVerified"][:field_name]
    assert_equal "member", schema["user"][:fields]["role"][:default_value]
    assert_equal "user_id", schema["session"][:fields]["userId"][:field_name]
  end

  def test_custom_model_names_are_applied_to_core_tables
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      user: {model_name: "app_users"},
      session: {model_name: "app_sessions"},
      account: {model_name: "app_accounts"},
      verification: {model_name: "app_verifications"}
    )

    schema = BetterAuth::Schema.auth_tables(config)

    assert_equal "app_users", schema["user"][:model_name]
    assert_equal "app_sessions", schema["session"][:model_name]
    assert_equal "app_accounts", schema["account"][:model_name]
    assert_equal "app_verifications", schema["verification"][:model_name]
    assert_equal "app_users", schema["session"][:fields]["userId"][:references][:model]
    assert_equal "app_users", schema["account"][:fields]["userId"][:references][:model]
  end

  def test_returned_false_fields_are_valid_input_and_excluded_from_output
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [
        {
          id: "secret-fields",
          schema: {
            secretRecord: {
              fields: {
                name: {type: "string", required: true},
                secretField: {type: "string", required: true, returned: false}
              }
            }
          }
        }
      ]
    )
    adapter = BetterAuth::Adapters::Memory.new(config)

    stored = adapter.create(model: "secretRecord", data: {name: "visible", secretField: "hidden"})
    output = BetterAuth::Schema.parse_output(config, "secretRecord", stored)

    assert_equal "hidden", stored["secretField"]
    assert_equal "visible", output["name"]
    refute output.key?("secretField")
  end

  def test_plugin_schema_merges_fields_and_tables
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [
        {
          id: "organization",
          schema: {
            session: {
              fields: {
                activeOrganizationId: {type: "string", required: false}
              }
            },
            organization: {
              model_name: "organization",
              fields: {
                name: {type: "string", required: true}
              }
            }
          }
        }
      ]
    )

    schema = BetterAuth::Schema.auth_tables(config)

    assert_equal "string", schema["session"][:fields]["activeOrganizationId"][:type]
    assert_equal "active_organization_id", schema["session"][:fields]["activeOrganizationId"][:field_name]
    assert_equal "organization", schema["organization"][:model_name]
    assert_equal "string", schema["organization"][:fields]["name"][:type]
  end

  def test_organization_schema_matches_upstream_conditionals
    without_teams = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.organization]
    )
    base_schema = BetterAuth::Schema.auth_tables(without_teams)

    refute base_schema["invitation"][:fields].key?("teamId")
    assert_equal true, base_schema["invitation"][:fields]["expiresAt"][:required]
    assert_equal true, base_schema["member"][:fields]["role"][:sortable]
    assert_equal true, base_schema["organization"][:fields]["slug"][:index]
    assert_equal true, base_schema["invitation"][:fields]["email"][:index]
    assert_equal true, base_schema["invitation"][:fields]["organizationId"][:index]
    assert_equal true, base_schema["member"][:fields]["userId"][:index]
    assert_equal true, base_schema["member"][:fields]["organizationId"][:index]

    with_teams = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.organization(teams: {enabled: true}, dynamic_access_control: {enabled: true})]
    )
    full_schema = BetterAuth::Schema.auth_tables(with_teams)

    assert full_schema["invitation"][:fields].key?("teamId")
    assert_equal true, full_schema["organizationRole"][:fields]["role"][:index]
  end

  def test_two_factor_schema_marks_recommended_lookup_fields_as_indexed
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.two_factor]
    )

    schema = BetterAuth::Schema.auth_tables(config)

    assert_equal true, schema["twoFactor"][:fields]["secret"][:index]
    assert_equal true, schema["twoFactor"][:fields]["userId"][:index]
  end

  def test_plugin_schema_defaults_physical_table_names_to_plural_snake_case
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [
        {
          id: "api-key",
          schema: {
            apiKey: {
              fields: {
                userId: {type: "string", required: true},
                lastRequest: {type: "date", required: false}
              }
            }
          }
        }
      ]
    )

    schema = BetterAuth::Schema.auth_tables(config)

    assert_equal "api_keys", schema["apiKey"][:model_name]
    assert_equal "user_id", schema["apiKey"][:fields]["userId"][:field_name]
    assert_equal "last_request", schema["apiKey"][:fields]["lastRequest"][:field_name]
  end

  def test_plugin_schema_pluralizes_common_default_table_names
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [
        {
          id: "table-normalization",
          schema: {
            apikey: {fields: {id: {type: "string", required: true}}},
            oauthClient: {fields: {id: {type: "string", required: true}}},
            oauthRefreshToken: {fields: {id: {type: "string", required: true}}},
            oauthAccessToken: {fields: {id: {type: "string", required: true}}},
            oauthConsent: {fields: {id: {type: "string", required: true}}},
            scimProvider: {fields: {id: {type: "string", required: true}}},
            ssoProvider: {fields: {id: {type: "string", required: true}}},
            subscription: {fields: {id: {type: "string", required: true}}},
            deviceCode: {fields: {id: {type: "string", required: true}}},
            twoFactor: {fields: {id: {type: "string", required: true}}},
            walletAddress: {fields: {id: {type: "string", required: true}}}
          }
        }
      ]
    )

    schema = BetterAuth::Schema.auth_tables(config)

    assert_equal "api_keys", schema["apikey"][:model_name]
    assert_equal "oauth_clients", schema["oauthClient"][:model_name]
    assert_equal "oauth_refresh_tokens", schema["oauthRefreshToken"][:model_name]
    assert_equal "oauth_access_tokens", schema["oauthAccessToken"][:model_name]
    assert_equal "oauth_consents", schema["oauthConsent"][:model_name]
    assert_equal "scim_providers", schema["scimProvider"][:model_name]
    assert_equal "sso_providers", schema["ssoProvider"][:model_name]
    assert_equal "subscriptions", schema["subscription"][:model_name]
    assert_equal "device_codes", schema["deviceCode"][:model_name]
    assert_equal "two_factors", schema["twoFactor"][:model_name]
    assert_equal "wallet_addresses", schema["walletAddress"][:model_name]
  end

  def test_plugin_foreign_keys_default_to_cascade_delete
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [
        {
          id: "linked",
          schema: {
            linkedThing: {
              fields: {
                userId: {type: "string", required: true, references: {model: "user", field: "id"}}
              }
            }
          }
        }
      ]
    )

    field = BetterAuth::Schema.auth_tables(config).fetch("linkedThing").fetch(:fields).fetch("userId")

    assert_equal "cascade", field.fetch(:references).fetch(:on_delete)
    assert_includes BetterAuth::Schema::SQL.create_statements(config, dialect: :postgres).join("\n"), %(ON DELETE CASCADE)
  end

  def test_phase_eight_identity_plugin_schemas_are_merged
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.username,
        BetterAuth::Plugins.anonymous,
        BetterAuth::Plugins.phone_number,
        BetterAuth::Plugins.siwe(get_nonce: -> { "nonce" }, verify_message: ->(**) { true })
      ]
    )

    schema = BetterAuth::Schema.auth_tables(config)
    user_fields = schema["user"][:fields]

    assert user_fields.key?("username")
    assert user_fields.key?("displayUsername")
    assert user_fields.key?("isAnonymous")
    assert user_fields.key?("phoneNumber")
    assert user_fields.key?("phoneNumberVerified")
    assert schema.key?("walletAddress")
  end

  def test_secondary_storage_omits_session_table_unless_database_storage_enabled
    storage = Object.new
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, secondary_storage: storage)

    refute_includes BetterAuth::Schema.auth_tables(config).keys, "session"
    refute_includes BetterAuth::Schema.auth_tables(config).keys, "verification"

    with_db_sessions = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      secondary_storage: storage,
      session: {store_session_in_database: true}
    )

    assert_includes BetterAuth::Schema.auth_tables(with_db_sessions).keys, "session"

    with_db_verifications = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      secondary_storage: storage,
      verification: {store_in_database: true}
    )

    assert_includes BetterAuth::Schema.auth_tables(with_db_verifications).keys, "verification"
  end

  def test_sql_schema_maps_json_and_array_field_types_per_dialect
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [
        {
          id: "typed-fields",
          schema: {
            typedRecord: {
              fields: {
                id: {type: "string", required: true},
                metadata: {type: "json", required: false},
                tags: {type: "string[]", required: false},
                scores: {type: "number[]", required: false}
              }
            }
          }
        }
      ]
    )

    postgres = BetterAuth::Schema::SQL.create_statements(config, dialect: :postgres).join("\n")
    mysql = BetterAuth::Schema::SQL.create_statements(config, dialect: :mysql).join("\n")
    sqlite = BetterAuth::Schema::SQL.create_statements(config, dialect: :sqlite).join("\n")
    mssql = BetterAuth::Schema::SQL.create_statements(config, dialect: :mssql).join("\n")

    assert_includes postgres, %("metadata" jsonb)
    assert_includes postgres, %("tags" jsonb)
    assert_includes postgres, %("scores" jsonb)
    assert_includes mysql, "`metadata` json"
    assert_includes mysql, "`tags` json"
    assert_includes mysql, "`scores` json"
    assert_includes sqlite, %("metadata" text)
    assert_includes sqlite, %("tags" text)
    assert_includes sqlite, %("scores" text)
    assert_includes mssql, "[metadata] varchar(8000)"
    assert_includes mssql, "[tags] varchar(8000)"
    assert_includes mssql, "[scores] varchar(8000)"
  end
end

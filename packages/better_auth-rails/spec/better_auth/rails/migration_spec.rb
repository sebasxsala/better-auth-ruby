# frozen_string_literal: true

require_relative "../../spec_helper"
require "better_auth/passkey"

RSpec.describe BetterAuth::Rails::Migration do
  let(:config) { BetterAuth::Configuration.new(secret: "test-secret-that-is-long-enough-for-validation", database: :memory) }

  it "renders a Rails migration from the core Better Auth schema" do
    migration = described_class.render(config)

    expect(migration).to include("class CreateBetterAuthTables < ActiveRecord::Migration")
    expect(migration).to include("create_table :users, id: false")
    expect(migration).to include("t.string :id, limit: 191, null: false")
    expect(migration).to include("ALTER TABLE \#{quote_table_name(:users)} ADD PRIMARY KEY")
    expect(migration).to include("t.boolean :email_verified, null: false, default: false")
    expect(migration).to include("add_index :users, :email, unique: true")
    expect(migration).to include("add_foreign_key :sessions, :users, column: :user_id, on_delete: :cascade")
  end

  it "renders long unindexed string fields as text while keeping indexed strings bounded" do
    migration = described_class.render(config)

    expect(migration).to include("t.text :access_token")
    expect(migration).to include("t.text :refresh_token")
    expect(migration).to include("t.text :id_token")
    expect(migration).to include("t.text :value, null: false")
    expect(migration).to include("t.string :token, limit: 191, null: false")
    expect(migration).to include("t.string :user_id, limit: 191, null: false")
  end

  it "renders string fields with defaults as bounded strings" do
    default_config = BetterAuth::Configuration.new(
      secret: "test-secret-that-is-long-enough-for-validation",
      database: :memory,
      user: {
        additional_fields: {
          role: {type: "string", required: false, default_value: "member"}
        }
      }
    )

    migration = described_class.render(default_config)

    expect(migration).to include("t.string :role, limit: 191, default: \"member\"")
    expect(migration).not_to include("t.text :role, default: \"member\"")
  end

  it "renders database rate-limit tables with generated primary keys" do
    rate_limit_config = BetterAuth::Configuration.new(
      secret: "test-secret-that-is-long-enough-for-validation",
      database: :memory,
      rate_limit: {storage: "database"}
    )

    migration = described_class.render(rate_limit_config)

    expect(migration).to include("create_table :rate_limits, id: false")
    expect(migration).to include("t.string :id, limit: 191, null: false")
    expect(migration).to include("t.string :key, limit: 191, null: false")
    expect(migration).to include("add_index :rate_limits, :key, unique: true")
    expect(migration).to include("ALTER TABLE \#{quote_table_name(:rate_limits)} ADD PRIMARY KEY")
  end

  it "renders plugin tables and maps logical foreign-key targets to physical Rails tables" do
    plugin = BetterAuth::Plugin.new(
      id: "audit",
      schema: {
        auditLog: {
          model_name: "audit_logs",
          fields: {
            id: {type: "string", required: true},
            userId: {type: "string", required: false, references: {model: "user", field: "id", on_delete: "cascade"}, index: true},
            action: {type: "string", required: true, unique: true},
            attempts: {type: "number", required: true, default_value: 0},
            createdAt: {type: "date", required: true}
          }
        }
      }
    )
    plugin_config = BetterAuth::Configuration.new(
      secret: "test-secret-that-is-long-enough-for-validation",
      database: :memory,
      plugins: [plugin]
    )

    migration = described_class.render(plugin_config)

    expect(migration).to include("create_table :audit_logs, id: false")
    expect(migration).to include("t.string :user_id, limit: 191")
    expect(migration).to include("t.string :action, limit: 191, null: false")
    expect(migration).to include("t.integer :attempts, null: false, default: 0")
    expect(migration).to include("t.datetime :created_at, null: false")
    expect(migration).to include("add_index :audit_logs, :user_id")
    expect(migration).to include("add_index :audit_logs, :action, unique: true")
    expect(migration).to include("add_foreign_key :audit_logs, :users, column: :user_id, on_delete: :cascade")
  end

  it "renders foreign keys against physical target field names" do
    plugin = BetterAuth::Plugin.new(
      id: "oauth-like",
      schema: {
        oauthClient: {
          model_name: "oauth_clients",
          fields: {
            clientId: {type: "string", required: true, unique: true}
          }
        },
        oauthToken: {
          model_name: "oauth_tokens",
          fields: {
            clientId: {type: "string", required: true, references: {model: "oauthClient", field: "clientId"}}
          }
        }
      }
    )
    plugin_config = BetterAuth::Configuration.new(secret: "test-secret-that-is-long-enough-for-validation", database: :memory, plugins: [plugin])

    migration = described_class.render(plugin_config)

    expect(migration).to include("add_foreign_key :oauth_tokens, :oauth_clients, column: :client_id, primary_key: :client_id, on_delete: :cascade")
  end

  it "renders default plugin table names as plural snake case" do
    plugin = BetterAuth::Plugin.new(
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
    )
    plugin_config = BetterAuth::Configuration.new(
      secret: "test-secret-that-is-long-enough-for-validation",
      database: :memory,
      plugins: [plugin]
    )

    migration = described_class.render(plugin_config)

    expect(migration).to include("create_table :api_keys, id: false")
    expect(migration).to include("create_table :oauth_clients, id: false")
    expect(migration).to include("create_table :oauth_refresh_tokens, id: false")
    expect(migration).to include("create_table :oauth_access_tokens, id: false")
    expect(migration).to include("create_table :oauth_consents, id: false")
    expect(migration).to include("create_table :scim_providers, id: false")
    expect(migration).to include("create_table :sso_providers, id: false")
    expect(migration).to include("create_table :subscriptions, id: false")
    expect(migration).to include("create_table :device_codes, id: false")
    expect(migration).to include("create_table :two_factors, id: false")
    expect(migration).to include("create_table :wallet_addresses, id: false")
  end

  it "renders json and array schema field types" do
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
    plugin_config = BetterAuth::Configuration.new(
      secret: "test-secret-that-is-long-enough-for-validation",
      database: :memory,
      plugins: [plugin]
    )

    migration = described_class.render(plugin_config)

    expect(migration).to include("t.json :metadata")
    expect(migration).to include("t.json :tags")
    expect(migration).to include("t.json :scores")
  end

  it "renders PostgreSQL-native jsonb and timestamptz types" do
    plugin = BetterAuth::Plugin.new(
      id: "typed",
      schema: {
        typedRecord: {
          model_name: "typed_records",
          fields: {
            id: {type: "string", required: true},
            metadata: {type: "json", required: false},
            tags: {type: "string[]", required: false},
            createdAt: {type: "date", required: true}
          }
        }
      }
    )
    plugin_config = BetterAuth::Configuration.new(
      secret: "test-secret-that-is-long-enough-for-validation",
      database: :memory,
      plugins: [plugin]
    )

    migration = described_class.render(plugin_config, dialect: :postgres)

    expect(migration).to include("t.column :created_at, :timestamptz, null: false")
    expect(migration).to include("t.jsonb :metadata")
    expect(migration).to include("t.jsonb :tags")
  end

  it "renders organization and passkey plugin schema migrations" do
    plugin_config = BetterAuth::Configuration.new(
      secret: "test-secret-that-is-long-enough-for-validation",
      database: :memory,
      plugins: [
        BetterAuth::Plugins.organization(teams: {enabled: true}, dynamic_access_control: {enabled: true}),
        BetterAuth::Plugins.passkey
      ]
    )

    migration = described_class.render(plugin_config)

    expect(migration).to include("create_table :organizations, id: false")
    expect(migration).to include("create_table :members, id: false")
    expect(migration).to include("create_table :invitations, id: false")
    expect(migration).to include("create_table :teams, id: false")
    expect(migration).to include("create_table :team_members, id: false")
    expect(migration).to include("create_table :organization_roles, id: false")
    expect(migration).to include("create_table :passkeys, id: false")
    expect(migration).to include("t.string :active_organization_id, limit: 191")
    expect(migration).to include("t.string :active_team_id, limit: 191")
    expect(migration).to include("t.string :credential_id, limit: 191, null: false")
    expect(migration).to include("add_index :passkeys, :user_id")
  end

  it "renders pending Rails migrations from the shared migration plan" do
    plugin = BetterAuth::Plugin.new(
      id: "audit",
      schema: {
        auditLog: {
          model_name: "audit_logs",
          fields: {
            id: {type: "string", required: true},
            userId: {type: "string", references: {model: "user", field: "id"}, index: true},
            action: {type: "string", required: true, unique: true}
          }
        }
      }
    )
    plugin_config = BetterAuth::Configuration.new(
      secret: "test-secret-that-is-long-enough-for-validation",
      database: :memory,
      plugins: [plugin],
      user: {
        additional_fields: {
          role: {type: "string", required: false, index: true}
        }
      }
    )
    existing = {
      "users" => {
        name: "users",
        columns: {"id" => "varchar", "email" => "varchar", "name" => "varchar", "email_verified" => "boolean", "image" => "text", "created_at" => "datetime", "updated_at" => "datetime"},
        indexes: {names: Set.new(["index_users_on_email"]), columns: Set.new(["email"]), unique_columns: Set.new(["email"])}
      },
      "sessions" => {name: "sessions", columns: {}, indexes: {names: Set.new, columns: Set.new, unique_columns: Set.new}},
      "accounts" => {name: "accounts", columns: {}, indexes: {names: Set.new, columns: Set.new, unique_columns: Set.new}},
      "verifications" => {name: "verifications", columns: {}, indexes: {names: Set.new, columns: Set.new, unique_columns: Set.new}}
    }
    plan = BetterAuth::SQLMigration.plan_from_existing(plugin_config, existing: existing, dialect: :postgres)

    migration = described_class.render_pending(plan, class_name: "UpdateBetterAuthTables")

    expect(migration).to include("class UpdateBetterAuthTables < ActiveRecord::Migration")
    expect(migration).to include("create_table :audit_logs, id: false")
    expect(migration).to include("add_column :users, :role, :string, limit: 191")
    expect(migration).to include("add_index :users, :role")
    expect(migration).not_to include("create_table :users")
  end
end

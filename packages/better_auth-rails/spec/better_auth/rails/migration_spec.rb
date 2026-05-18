# frozen_string_literal: true

require_relative "../../spec_helper"
require "better_auth/passkey"

RSpec.describe BetterAuth::Rails::Migration do
  let(:config) { BetterAuth::Configuration.new(secret: "test-secret-that-is-long-enough-for-validation", database: :memory) }

  it "renders a Rails migration from the core Better Auth schema" do
    migration = described_class.render(config)

    expect(migration).to include("class CreateBetterAuthTables < ActiveRecord::Migration")
    expect(migration).to include("create_table :users, id: false")
    expect(migration).to include("t.string :id, null: false")
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
    expect(migration).to include("t.string :token, null: false")
    expect(migration).to include("t.string :user_id, null: false")
  end

  it "renders database rate-limit tables without synthetic primary keys" do
    rate_limit_config = BetterAuth::Configuration.new(
      secret: "test-secret-that-is-long-enough-for-validation",
      database: :memory,
      rate_limit: {storage: "database"}
    )

    migration = described_class.render(rate_limit_config)

    expect(migration).to include("create_table :rate_limits, id: false")
    expect(migration).to include("t.string :key, null: false")
    expect(migration).to include("add_index :rate_limits, :key, unique: true")
    expect(migration).not_to include("ALTER TABLE \#{quote_table_name(:rate_limits)} ADD PRIMARY KEY")
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
    expect(migration).to include("t.string :user_id")
    expect(migration).to include("t.string :action, null: false")
    expect(migration).to include("t.integer :attempts, null: false, default: 0")
    expect(migration).to include("t.datetime :created_at, null: false")
    expect(migration).to include("add_index :audit_logs, :user_id")
    expect(migration).to include("add_index :audit_logs, :action, unique: true")
    expect(migration).to include("add_foreign_key :audit_logs, :users, column: :user_id, on_delete: :cascade")
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
    expect(migration).to include("t.string :active_organization_id")
    expect(migration).to include("t.string :active_team_id")
    expect(migration).to include("t.string :credential_id, null: false")
    expect(migration).to include("add_index :passkeys, :user_id")
  end
end

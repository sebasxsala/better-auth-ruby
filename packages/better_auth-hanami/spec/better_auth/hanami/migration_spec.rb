# frozen_string_literal: true

require_relative "../../spec_helper"
require "better_auth/sql_migration"

RSpec.describe BetterAuth::Hanami::Migration do
  let(:config) { BetterAuth::Configuration.new(secret: secret, database: :memory) }

  it "renders a ROM SQL migration from the core Better Auth schema" do
    migration = described_class.render(config)

    expect(migration).to include("ROM::SQL.migration do")
    expect(migration).to include("create_table :users do")
    expect(migration).to include("column :id, String, null: false")
    expect(migration).to include("primary_key [:id]")
    expect(migration).to include("column :email_verified, TrueClass, null: false, default: false")
    expect(migration).to include("index :email, unique: true")
    expect(migration).to include("foreign_key :user_id, :users, type: String, null: false, on_delete: :cascade")
  end

  it "renders plugin tables, defaults, indexes, and foreign keys" do
    plugin = BetterAuth::Plugin.new(
      id: "audit",
      schema: {
        auditLog: {
          model_name: "audit_logs",
          fields: {
            id: {type: "string", required: true},
            userId: {type: "string", references: {model: "user", field: "id", on_delete: "cascade"}, index: true},
            action: {type: "string", required: true, unique: true},
            attempts: {type: "number", required: true, default_value: 0},
            createdAt: {type: "date", required: true}
          }
        }
      }
    )
    plugin_config = BetterAuth::Configuration.new(secret: secret, database: :memory, plugins: [plugin])

    migration = described_class.render(plugin_config)

    expect(migration).to include("create_table :audit_logs do")
    expect(migration).to include("foreign_key :user_id, :users, type: String, on_delete: :cascade")
    expect(migration).to include("column :action, String, null: false")
    expect(migration).to include("column :attempts, Integer, null: false, default: 0")
    expect(migration).to include("column :created_at, DateTime, null: false")
    expect(migration).to include("index :user_id")
    expect(migration).to include("index :action, unique: true")
  end

  it "renders bigint number fields for database rate limit millisecond timestamps" do
    rate_limit_config = BetterAuth::Configuration.new(secret: secret, database: :memory, rate_limit: {storage: "database"})

    migration = described_class.render(rate_limit_config)

    expect(migration).to include("create_table :rate_limits do")
    expect(migration).to include("column :last_request, :Bignum, null: false")
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
    plugin_config = BetterAuth::Configuration.new(secret: secret, database: :memory, plugins: [plugin])

    migration = described_class.render(plugin_config)

    expect(migration).to include("column :metadata, JSON")
    expect(migration).to include("column :tags, JSON")
    expect(migration).to include("column :scores, JSON")
  end

  it "renders pending ROM migrations from the shared migration plan" do
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
      secret: secret,
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

    migration = described_class.render_pending(plan)

    expect(migration).to include("ROM::SQL.migration do")
    expect(migration).to include("create_table :audit_logs do")
    expect(migration).to include("alter_table :users do")
    expect(migration).to include("add_column :role, String")
    expect(migration).to include("add_index :role")
    expect(migration).not_to include("create_table :users")
  end

  def secret
    "test-secret-that-is-long-enough-for-validation"
  end
end

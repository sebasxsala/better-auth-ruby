# frozen_string_literal: true

require "tmpdir"
require_relative "../../spec_helper"
require "generators/better_auth/migration/migration_generator"

BetterAuthRailsMigrationGeneratorColumn = Struct.new(:name, :sql_type, keyword_init: true)
BetterAuthRailsMigrationGeneratorIndex = Struct.new(:name, :columns, :unique, keyword_init: true)

class BetterAuthRailsMigrationGeneratorConnection
  def initialize(schema)
    @schema = schema
  end

  def tables
    @schema.keys
  end

  def columns(table)
    @schema.fetch(table).fetch(:columns).map { |name, type| BetterAuthRailsMigrationGeneratorColumn.new(name: name, sql_type: type) }
  end

  def indexes(table)
    data = @schema.fetch(table).fetch(:indexes)
    data[:columns].map do |column|
      BetterAuthRailsMigrationGeneratorIndex.new(
        name: "index_#{table}_on_#{column}",
        columns: [column],
        unique: data[:unique_columns].include?(column)
      )
    end
  end
end

RSpec.describe BetterAuth::Generators::MigrationGenerator do
  around do |example|
    Dir.mktmpdir("better-auth-rails-migration-generator") do |dir|
      @destination = dir
      example.run
    end
  end

  it "creates the Better Auth base migration" do
    described_class.start([], destination_root: @destination)

    migrations = Dir[File.join(@destination, "db/migrate/*_create_better_auth_tables.rb")]

    expect(migrations.length).to eq(1)
    expect(File.read(migrations.first)).to include("class CreateBetterAuthTables < ActiveRecord::Migration")
  end

  it "does not create a duplicate base migration" do
    path = File.join(@destination, "db/migrate")
    FileUtils.mkdir_p(path)
    File.write(File.join(path, "20260425000000_create_better_auth_tables.rb"), "# existing\n")

    described_class.start([], destination_root: @destination)

    expect(Dir[File.join(path, "*_create_better_auth_tables.rb")].length).to eq(1)
  end

  it "creates an incremental migration for missing plugin schema when the base migration already exists" do
    path = File.join(@destination, "db/migrate")
    FileUtils.mkdir_p(path)
    File.write(File.join(path, "20260425000000_create_better_auth_tables.rb"), "# existing\n")
    BetterAuth::Rails.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
      config.plugins = [
        BetterAuth::Plugin.new(
          id: "api-key-test",
          schema: {
            apiKey: {
              model_name: "api_keys",
              fields: {
                id: {type: "string", required: true},
                key: {type: "string", required: true, unique: true}
              }
            }
          }
        )
      ]
    end
    allow(ActiveRecord::Base).to receive(:connection).and_return(BetterAuthRailsMigrationGeneratorConnection.new(core_schema))

    described_class.start([], destination_root: @destination)

    migrations = Dir[File.join(path, "*.rb")]
    update = migrations.find { |file| File.basename(file).include?("update_better_auth_tables") }
    expect(migrations.length).to eq(2)
    expect(File.read(update)).to include("create_table :api_keys, id: :string")
    expect(File.read(update)).not_to include("create_table :users")
  ensure
    BetterAuth::Rails.instance_variable_set(:@auth, nil)
    BetterAuth::Rails.instance_variable_set(:@configuration, nil)
  end

  it "creates migrations with plugin schemas configured through BetterAuth::Rails" do
    BetterAuth::Rails.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
      config.plugins = [
        BetterAuth::Plugin.new(
          id: "api-key-test",
          schema: {
            apiKey: {
              model_name: "api_keys",
              fields: {
                id: {type: "string", required: true},
                userId: {type: "string", required: true, references: {model: "user", field: "id"}, index: true},
                key: {type: "string", required: true, unique: true}
              }
            }
          }
        )
      ]
    end

    described_class.start([], destination_root: @destination)

    migration = File.read(Dir[File.join(@destination, "db/migrate/*_create_better_auth_tables.rb")].first)
    expect(migration).to include("create_table :api_keys, id: :string")
    expect(migration).to include("add_index :api_keys, :key, unique: true")
    expect(migration).to include("add_foreign_key :api_keys, :users, column: :user_id")
  ensure
    BetterAuth::Rails.instance_variable_set(:@auth, nil)
    BetterAuth::Rails.instance_variable_set(:@configuration, nil)
  end

  def core_schema
    config = BetterAuth::Configuration.new(secret: "test-secret-that-is-long-enough-for-validation", database: :memory)
    BetterAuth::Schema.auth_tables(config).each_with_object({}) do |(_logical_name, table), schema|
      columns = table.fetch(:fields).to_h do |field, attributes|
        [attributes[:field_name] || BetterAuth::Schema.send(:physical_name, field), "varchar"]
      end
      indexes = {names: Set.new, columns: Set.new, unique_columns: Set.new}
      table.fetch(:fields).each do |field, attributes|
        next unless attributes[:index] || attributes[:unique]

        column = attributes[:field_name] || BetterAuth::Schema.send(:physical_name, field)
        indexes[:names] << "index_#{table.fetch(:model_name)}_on_#{column}"
        indexes[:columns] << column
        indexes[:unique_columns] << column if attributes[:unique]
      end
      schema[table.fetch(:model_name)] = {name: table.fetch(:model_name), columns: columns, indexes: indexes}
    end
  end
end

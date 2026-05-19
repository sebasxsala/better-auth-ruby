# frozen_string_literal: true

require_relative "../../../spec_helper"

RSpec.describe BetterAuth::Hanami::Generators::MigrationGenerator do
  around do |example|
    Dir.mktmpdir("better-auth-hanami-migration-generator") do |dir|
      @destination = dir
      example.run
    end
  ensure
    BetterAuth::Hanami.instance_variable_set(:@auth, nil)
    BetterAuth::Hanami.instance_variable_set(:@configuration, nil)
  end

  it "creates the Better Auth base migration" do
    described_class.new(destination_root: @destination).run

    migrations = Dir[File.join(@destination, "config/db/migrate/*_create_better_auth_tables.rb")]

    expect(migrations.length).to eq(1)
    expect(File.read(migrations.first)).to include("ROM::SQL.migration")
    expect(File.read(migrations.first)).to include("create_table :users")
  end

  it "does not create a duplicate base migration" do
    path = File.join(@destination, "config/db/migrate")
    FileUtils.mkdir_p(path)
    File.write(File.join(path, "20260427000000_create_better_auth_tables.rb"), "# existing\n")

    described_class.new(destination_root: @destination).run

    migrations = Dir[File.join(@destination, "config/db/migrate/*_create_better_auth_tables.rb")]
    expect(migrations.length).to eq(1)
    expect(File.read(migrations.first)).to eq("# existing\n")
  end

  it "creates an incremental migration for missing plugin schema when the base migration already exists" do
    path = File.join(@destination, "config/db/migrate")
    FileUtils.mkdir_p(path)
    File.write(File.join(path, "20260427000000_create_better_auth_tables.rb"), "# existing\n")
    db = Sequel.sqlite
    core_config = BetterAuth::Configuration.new(secret: "test-secret-that-is-long-enough-for-validation", database: :memory)
    BetterAuth::Schema::SQL.create_statements(core_config, dialect: :sqlite).each { |statement| db.run(statement) }
    config = BetterAuth::Configuration.new(
      secret: "test-secret-that-is-long-enough-for-validation",
      database: ->(options) { BetterAuth::Hanami::SequelAdapter.new(options, connection: db) },
      plugins: [
        BetterAuth::Plugin.new(
          id: "audit",
          schema: {
            auditLog: {
              model_name: "audit_logs",
              fields: {
                id: {type: "string", required: true},
                action: {type: "string", required: true, unique: true}
              }
            }
          }
        )
      ]
    )

    described_class.new(destination_root: @destination, configuration: config).run

    migrations = Dir[File.join(path, "*.rb")]
    update = migrations.find { |file| File.basename(file).include?("update_better_auth_tables") }
    expect(migrations.length).to eq(2)
    expect(File.read(update)).to include("create_table :audit_logs")
    expect(File.read(update)).not_to include("create_table :users")
  end

  it "overwrites an existing base migration when force is true" do
    path = File.join(@destination, "config/db/migrate")
    FileUtils.mkdir_p(path)
    migration = File.join(path, "20260427000000_create_better_auth_tables.rb")
    File.write(migration, "# existing\n")

    result = described_class.new(destination_root: @destination).run(force: true)

    migrations = Dir[File.join(@destination, "config/db/migrate/*_create_better_auth_tables.rb")]
    expect(result).to eq(migration)
    expect(migrations.length).to eq(1)
    expect(File.read(migration)).to include("ROM::SQL.migration")
    expect(File.read(migration)).to include("create_table :users")
  end

  it "creates migrations with plugin schemas configured through BetterAuth::Hanami" do
    BetterAuth::Hanami.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
      config.plugins = [
        BetterAuth::Plugin.new(
          id: "audit",
          schema: {
            auditLog: {
              model_name: "audit_logs",
              fields: {
                id: {type: "string", required: true},
                action: {type: "string", required: true, unique: true}
              }
            }
          }
        )
      ]
    end

    described_class.new(destination_root: @destination).run

    migration = Dir[File.join(@destination, "config/db/migrate/*_create_better_auth_tables.rb")].first
    expect(File.read(migration)).to include("create_table :audit_logs")
    expect(File.read(migration)).to include("index :action, unique: true")
  end
end

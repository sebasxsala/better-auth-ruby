# frozen_string_literal: true

require "fileutils"
require "rake"
require "better_auth/roda"

namespace :better_auth do
  desc "Create the Better Auth Roda config and migration directory"
  task :install do
    config_path = "config/better_auth.rb"
    FileUtils.mkdir_p(File.dirname(config_path))
    if File.exist?(config_path)
      puts "skip #{config_path} already exists"
    else
      File.write(config_path, BetterAuth::Roda.default_config_template)
      puts "create #{config_path}"
    end

    FileUtils.mkdir_p(BetterAuth::Roda::Migration::DEFAULT_MIGRATIONS_PATH)
  end

  namespace :generate do
    desc "Create the Better Auth SQL migration"
    task :migration do
      BetterAuth::Roda.load_app_config!
      dialect = BetterAuth::Roda::Migration.normalize_dialect(BetterAuth::Env.get("BETTER_AUTH_DIALECT") || BetterAuth::Env.get("BETTER_AUTH_DATABASE_DIALECT") || "postgres")
      config = BetterAuth::Roda.migration_configuration
      adapter = begin
        BetterAuth::Roda.auth.context.adapter
      rescue
        nil
      end
      connection = if adapter&.respond_to?(:connection) && adapter.respond_to?(:dialect) && BetterAuth::Roda::Migration.normalize_dialect(adapter.dialect) == dialect
        adapter.connection
      end
      path = BetterAuth::Roda::Migration.generate(config, dialect: dialect, connection: connection)
      puts(path ? "create #{path}" : "no migrations needed")
    end
  end

  desc "Run pending Better Auth SQL migrations"
  task :migrate do
    BetterAuth::Roda.load_app_config!
    BetterAuth::Roda::Migration.migrate(BetterAuth::Roda.auth)
  end

  namespace :migrate do
    desc "Print pending Better Auth SQL migration status"
    task :status do
      BetterAuth::Roda.load_app_config!
      auth = BetterAuth::Roda.auth
      adapter = auth.context.adapter
      unless adapter.respond_to?(:connection) && adapter.respond_to?(:dialect)
        raise BetterAuth::Roda::Migration::UnsupportedAdapterError, "Better Auth SQL migrations require core SQL adapters with connection and dialect support"
      end
      plan = BetterAuth::Roda::Migration.plan(auth.options, connection: adapter.connection, dialect: adapter.dialect)
      if plan.empty?
        puts "No migrations needed."
      else
        plan.to_create.each { |change| puts "create table #{change.table_name}" }
        plan.to_add.each { |change| puts "add #{change.fields.keys.join(", ")} to #{change.table_name}" }
        plan.to_index.each { |change| puts "create index #{change.name}" }
        plan.warnings.each { |warning| puts "warning: #{warning}" }
      end
    end
  end

  desc "Check Better Auth configuration and schema health"
  task :doctor do
    BetterAuth::Roda.load_app_config!
    exit_code = BetterAuth::Doctor.print(BetterAuth::Doctor.check(BetterAuth::Roda.migration_configuration), stdout: $stdout, stderr: $stderr)
    abort if exit_code != 0
  end

  desc "Print Better Auth Roda mount information"
  task :routes do
    BetterAuth::Roda.load_app_config!
    mount_path = BetterAuth::Roda.configuration.base_path
    puts "#{mount_path}/* -> BetterAuth.auth"
    puts "Core routes are handled by Better Auth; use the OpenAPI plugin or HTTP API docs for endpoint details."
  end
end

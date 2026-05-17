# frozen_string_literal: true

require "fileutils"
require "rake"
require "better_auth/sinatra"

namespace :better_auth do
  desc "Create the Better Auth Sinatra config and migration directory"
  task :install do
    config_path = "config/better_auth.rb"
    FileUtils.mkdir_p(File.dirname(config_path))
    if File.exist?(config_path)
      puts "skip #{config_path} already exists"
    else
      File.write(config_path, BetterAuth::Sinatra.default_config_template)
      puts "create #{config_path}"
    end

    FileUtils.mkdir_p(BetterAuth::Sinatra::Migration::DEFAULT_MIGRATIONS_PATH)
  end

  namespace :generate do
    desc "Create the Better Auth SQL migration"
    task :migration do
      BetterAuth::Sinatra.load_app_config
      dialect = BetterAuth::Sinatra::Migration.normalize_dialect(BetterAuth::Env.get("BETTER_AUTH_DIALECT") || BetterAuth::Env.get("BETTER_AUTH_DATABASE_DIALECT") || "postgres")
      config = BetterAuth::Sinatra.migration_configuration
      path = BetterAuth::Sinatra::Migration.generate(config, dialect: dialect)
      puts "create #{path}"
    end
  end

  desc "Run pending Better Auth SQL migrations"
  task :migrate do
    BetterAuth::Sinatra.load_app_config
    BetterAuth::Sinatra::Migration.migrate(BetterAuth::Sinatra.auth)
  end

  desc "Print Better Auth Sinatra mount information"
  task :routes do
    BetterAuth::Sinatra.load_app_config
    mount_path = BetterAuth::Sinatra.configuration.base_path
    puts "#{mount_path}/* -> BetterAuth.auth"
    puts "Core routes are handled by Better Auth; use the OpenAPI plugin or HTTP API docs for endpoint details."
  end
end

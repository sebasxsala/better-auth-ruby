# frozen_string_literal: true

namespace :better_auth do
  desc "Create the Better Auth initializer and base migration"
  task init: :environment do
    require "generators/better_auth/install/install_generator"
    BetterAuth::Generators::InstallGenerator.start([])
  end

  namespace :generate do
    desc "Create the Better Auth base migration"
    task migration: :environment do
      require "generators/better_auth/migration/migration_generator"
      BetterAuth::Generators::MigrationGenerator.start([])
    end
  end

  desc "Check Better Auth configuration and schema health"
  task doctor: :environment do
    options = BetterAuth::Rails.configuration.to_auth_options
    config = BetterAuth::Configuration.new(options)
    exit_code = BetterAuth::Doctor.print(BetterAuth::Doctor.check(config), stdout: $stdout, stderr: $stderr)
    abort if exit_code != 0
  end
end

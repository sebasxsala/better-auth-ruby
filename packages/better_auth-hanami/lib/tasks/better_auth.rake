# frozen_string_literal: true

require "better_auth/hanami"

namespace :better_auth do
  desc "Create Better Auth Hanami provider, routes, settings, tasks, and base migration"
  task :init do
    BetterAuth::Hanami::Generators::InstallGenerator.new.run
  end

  namespace :generate do
    desc "Create the Better Auth Hanami base migration"
    task :migration do
      BetterAuth::Hanami::Generators::MigrationGenerator.new.run
    end

    desc "Create Hanami relations and repos for Better Auth tables"
    task :relations do
      BetterAuth::Hanami::Generators::RelationGenerator.new.run
    end
  end

  desc "Check Better Auth configuration and schema health"
  task :doctor do
    config = BetterAuth::Configuration.new(BetterAuth::Hanami.configuration.to_auth_options)
    exit_code = BetterAuth::Doctor.print(BetterAuth::Doctor.check(config), stdout: $stdout, stderr: $stderr)
    abort if exit_code != 0
  end
end

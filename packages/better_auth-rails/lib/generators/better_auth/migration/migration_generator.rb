# frozen_string_literal: true

require "rails/generators"
require "better_auth/rails"

module BetterAuth
  module Generators
    class MigrationGenerator < ::Rails::Generators::Base
      def create_migration
        if existing_migration?
          create_incremental_migration
          return
        end

        create_file migration_path, BetterAuth::Rails::Migration.render(generator_config)
      end

      private

      def existing_migration?
        Dir[File.join(destination_root, "db/migrate/*_create_better_auth_tables.rb")].any?
      end

      def create_incremental_migration
        plan = BetterAuth::Rails::Migration.plan_pending(generator_config)
        if plan.empty?
          say_status :skip, "Better Auth schema is up to date"
          return
        end

        create_file incremental_migration_path, BetterAuth::Rails::Migration.render_pending(plan, class_name: incremental_class_name)
      rescue => _error
        say_status :skip, "db/migrate/*_create_better_auth_tables.rb already exists"
      end

      def migration_path
        File.join("db/migrate", "#{timestamp}_create_better_auth_tables.rb")
      end

      def incremental_migration_path
        File.join("db/migrate", "#{timestamp}_update_better_auth_tables_#{timestamp}.rb")
      end

      def incremental_class_name
        "UpdateBetterAuthTables#{timestamp}"
      end

      def timestamp
        @timestamp ||= Time.now.utc.strftime("%Y%m%d%H%M%S")
      end

      def generator_config
        options = BetterAuth::Rails.configuration.to_auth_options
        options[:secret] ||= BetterAuth::Configuration::DEFAULT_SECRET
        options[:database] ||= :memory
        BetterAuth::Configuration.new(options)
      end
    end
  end
end

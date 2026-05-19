# frozen_string_literal: true

require "better_auth/sql_migration"

module BetterAuth
  module Grape
    module Migration
      DEFAULT_MIGRATIONS_PATH = BetterAuth::SQLMigration::DEFAULT_MIGRATIONS_PATH
      UnsupportedAdapterError = BetterAuth::SQLMigration::UnsupportedAdapterError
      GENERATOR = "better_auth-grape"

      module_function

      def render(options, dialect:)
        BetterAuth::SQLMigration.render(options, dialect: dialect, generator: GENERATOR)
      end

      def generate(options, dialect:, migrations_path: DEFAULT_MIGRATIONS_PATH, timestamp: Time.now.utc.strftime("%Y%m%d%H%M%S"), connection: nil)
        BetterAuth::SQLMigration.generate(
          options,
          dialect: dialect,
          generator: GENERATOR,
          migrations_path: migrations_path,
          timestamp: timestamp,
          connection: connection
        )
      end

      def migrate(auth_or_options, migrations_path: DEFAULT_MIGRATIONS_PATH)
        BetterAuth::SQLMigration.migrate(auth_or_options, migrations_path: migrations_path)
      end

      def statements(sql)
        BetterAuth::SQLMigration.statements(sql)
      end

      def normalize_dialect(value)
        BetterAuth::SQLMigration.normalize_dialect(value)
      end
    end
  end
end

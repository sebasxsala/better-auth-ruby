# frozen_string_literal: true

module BetterAuth
  module Roda
    module Migration
      DEFAULT_MIGRATIONS_PATH = BetterAuth::Migration::SQL::DEFAULT_MIGRATIONS_PATH
      MISSING_MIGRATIONS_TABLE_MESSAGES = BetterAuth::Migration::SQL::MISSING_MIGRATIONS_TABLE_MESSAGES
      UnsupportedAdapterError = BetterAuth::Migration::SQL::UnsupportedAdapterError

      module_function

      def render(options, dialect:)
        BetterAuth::Migration::SQL.render(options, dialect: dialect, source: "better_auth-roda")
      end

      def generate(options, dialect:, migrations_path: DEFAULT_MIGRATIONS_PATH, timestamp: Time.now.utc.strftime("%Y%m%d%H%M%S"))
        BetterAuth::Migration::SQL.generate(
          options,
          dialect: dialect,
          migrations_path: migrations_path,
          timestamp: timestamp,
          source: "better_auth-roda"
        )
      end

      def migrate(auth_or_options, migrations_path: DEFAULT_MIGRATIONS_PATH)
        BetterAuth::Migration::SQL.migrate(auth_or_options, migrations_path: migrations_path, package_name: "better_auth-roda")
      end

      def method_missing(name, *args, **kwargs, &block)
        return BetterAuth::Migration::SQL.public_send(name, *args, **kwargs, &block) if BetterAuth::Migration::SQL.respond_to?(name)

        super
      end

      def respond_to_missing?(name, include_private = false)
        BetterAuth::Migration::SQL.respond_to?(name, include_private) || super
      end
    end
  end
end

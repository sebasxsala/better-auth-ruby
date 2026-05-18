# frozen_string_literal: true

require "better_auth"
require "roda"
require_relative "roda/version"
require_relative "roda/configuration"
require_relative "roda/mounted_app"
require_relative "roda/migration"
require_relative "roda/plugin"

module BetterAuth
  module Roda
    class << self
      def configuration
        @configuration ||= Configuration.new
      end

      def configure
        yield configuration
        @auth = nil
        self
      end

      def reset!
        @configuration = nil
        @auth = nil
      end

      def auth(overrides = nil)
        options = configuration.to_auth_options
        return @auth ||= BetterAuth.auth(options) if overrides.nil? || overrides.empty?

        BetterAuth.auth(options.merge(overrides))
      end

      def migration_configuration
        options = configuration.to_auth_options
        options[:secret] ||= BetterAuth::Configuration::DEFAULT_SECRET
        BetterAuth::Configuration.new(options)
      end

      def app_config_path(path = nil)
        path || BetterAuth::Env.get("BETTER_AUTH_CONFIG") || "config/better_auth.rb"
      end

      def load_app_config(path = nil)
        config_path = app_config_path(path)
        return false unless File.exist?(config_path)

        load config_path
        true
      end

      def load_app_config!(path = nil)
        config_path = app_config_path(path)
        return true if load_app_config(config_path)

        raise ArgumentError,
          "Better Auth Roda config not found at #{config_path.inspect}. " \
          "Run `rake better_auth:install` or set BETTER_AUTH_CONFIG to a shared config file."
      end

      def default_config_template
        <<~RUBY
          # frozen_string_literal: true

          require "better_auth/roda"

          BetterAuth::Roda.configure do |config|
            config.secret = BetterAuth::Env.fetch("BETTER_AUTH_SECRET", "change-me-roda-secret-12345678901234567890")
            config.base_url = BetterAuth::Env.get("BETTER_AUTH_URL")
            config.base_path = "/api/auth"

            config.database = ->(options) do
              case BetterAuth::Env.fetch("BETTER_AUTH_DATABASE_DIALECT", "postgres")
              when "postgres", "postgresql"
                BetterAuth::Adapters::Postgres.new(options, url: ENV.fetch("DATABASE_URL"))
              when "mysql"
                BetterAuth::Adapters::MySQL.new(options, url: ENV.fetch("DATABASE_URL"))
              when "sqlite", "sqlite3"
                BetterAuth::Adapters::SQLite.new(options, path: ENV.fetch("DATABASE_URL", "db/better_auth.sqlite3"))
              else
                raise "Unsupported BETTER_AUTH_DATABASE_DIALECT for better_auth-roda"
              end
            end

            config.email_and_password = {
              enabled: true
            }

            config.plugins = []
          end
        RUBY
      end
    end
  end
end

# frozen_string_literal: true

require "better_auth"
require "sinatra/base"

require_relative "sinatra/version"
require_relative "sinatra/configuration"
require_relative "sinatra/mounted_app"
require_relative "sinatra/helpers"
require_relative "sinatra/migration"
require_relative "sinatra/extension"

module BetterAuth
  module Sinatra
    class << self
      def registered(app)
        Extension.registered(app)
      end

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

      def load_app_config(path = "config/better_auth.rb")
        load path if File.exist?(path)
      end

      def default_config_template
        <<~RUBY
          # frozen_string_literal: true

          require "better_auth/sinatra"

          BetterAuth::Sinatra.configure do |config|
            config.secret = BetterAuth::Env.fetch("BETTER_AUTH_SECRET", "change-me-sinatra-secret-12345678901234567890")
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
                raise "Unsupported OPEN_AUTH_DATABASE_DIALECT or BETTER_AUTH_DATABASE_DIALECT for better_auth-sinatra"
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

# frozen_string_literal: true

require "better_auth/sql_migration"

module BetterAuth
  module Doctor
    Result = Struct.new(:ok, :warnings, :errors, keyword_init: true) do
      def success?
        errors.empty?
      end
    end

    module_function

    def check(config_or_options)
      config = BetterAuth::SQLMigration.configuration_for(config_or_options)
      result = Result.new(ok: ["config loaded"], warnings: [], errors: [])

      check_secret(config, result)
      check_base_url(config, result)
      check_rate_limit(config, result)
      check_database(config, result)

      result
    end

    def print(result, stdout:, stderr:)
      result.ok.each { |message| stdout.puts "OK #{message}" }
      result.warnings.each { |message| stdout.puts "WARN #{message}" }
      result.errors.each { |message| stderr.puts "ERROR #{message}" }
      result.success? ? 0 : 1
    end

    def check_secret(config, result)
      secret = config.secret.to_s
      if secret.empty?
        result.errors << "secret is missing"
      elsif secret == BetterAuth::Configuration::DEFAULT_SECRET
        result.errors << "secret uses the default development value"
      elsif secret.length < 32
        result.errors << "secret should be at least 32 characters"
      elsif entropy(secret) < 120
        result.errors << "secret appears low-entropy; use a random production secret"
      else
        result.ok << "secret length and entropy look acceptable"
      end
    end

    def check_base_url(config, result)
      base_url = config.base_url.to_s
      if base_url.empty?
        result.warnings << "base_url is not configured; set it explicitly in production"
      elsif !base_url.start_with?("https://")
        result.warnings << "base_url is not HTTPS"
      else
        result.ok << "base_url uses HTTPS"
      end
    end

    def check_rate_limit(config, result)
      rate_limit = config.rate_limit || {}
      result.warnings << "rate_limit is disabled" unless rate_limit[:enabled]
      if rate_limit[:storage].to_s == "memory"
        result.warnings << "rate_limit uses memory storage; use database or secondary-storage for multi-process production deployments"
      else
        result.ok << "rate_limit storage is #{rate_limit[:storage]}"
      end
    end

    def check_database(config, result)
      auth = BetterAuth.auth(config.to_h)
      adapter = auth.context.adapter
      unless adapter.respond_to?(:dialect) && adapter.respond_to?(:connection)
        result.warnings << "database adapter does not expose SQL migration introspection; schema drift check skipped"
        return
      end

      result.ok << "database adapter supports SQL migrations"
      plan = BetterAuth::SQLMigration.plan(config, connection: adapter.connection, dialect: adapter.dialect)
      if plan.empty?
        result.ok << "database schema is up to date"
      else
        result.warnings << "database has pending Better Auth migrations"
        plan.warnings.each { |warning| result.warnings << warning }
      end
    rescue BetterAuth::SQLMigration::UnsupportedAdapterError => error
      result.warnings << error.message
    end

    def entropy(value)
      unique = value.chars.uniq.length
      return 0 if unique.zero?

      Math.log2(unique**value.length)
    end
  end
end

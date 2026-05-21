# frozen_string_literal: true

require "better_auth"
require "better_auth/cli/version"
require "better_auth/doctor"
require "better_auth/sql_migration"
require "fileutils"
require "optparse"

module BetterAuth
  class CLI
    class Error < StandardError; end

    class << self
      attr_accessor :configuration

      def configure(value = nil)
        @configuration = block_given? ? yield : value
      end

      def run(argv = ARGV, stdout: $stdout, stderr: $stderr)
        new(argv, stdout: stdout, stderr: stderr).run
      rescue Error, BetterAuth::SQLMigration::UnsupportedAdapterError, BetterAuth::Error, OptionParser::ParseError => error
        stderr.puts error.message
        1
      end
    end

    def initialize(argv, stdout:, stderr:)
      @argv = argv.dup
      @stdout = stdout
      @stderr = stderr
    end

    def run
      command = argv.shift
      case command
      when "generate"
        generate(argv)
      when "migrate"
        migrate(argv)
      when "doctor"
        doctor(argv)
      when "mongo"
        mongo(argv)
      when "-h", "--help", "help", nil
        stdout.puts usage
        0
      else
        raise Error, "Unknown command: #{command}"
      end
    end

    private

    attr_reader :argv, :stdout, :stderr

    def generate(args)
      options = parse_generate_options(args)
      config = load_config(options.fetch(:config))
      adapter = sql_adapter_for(config)
      connection = adapter&.connection
      dialect = BetterAuth::SQLMigration.normalize_dialect(options[:dialect] || adapter&.dialect || "postgres")
      sql = if connection
        BetterAuth::SQLMigration.render_pending(config, connection: connection, dialect: dialect, generator: "better_auth-cli")
      else
        BetterAuth::SQLMigration.render(config, dialect: dialect, generator: "better_auth-cli")
      end

      if sql.empty?
        stdout.puts "No migrations needed."
        return 0
      end

      output = options.fetch(:output)
      FileUtils.mkdir_p(File.dirname(output))
      File.write(output, sql)
      stdout.puts "generated #{output}"
      0
    end

    def migrate(args)
      if args.first == "status"
        args.shift
        return migration_status(args)
      end

      options = parse_migrate_options(args)
      raise Error, "Pass --yes to apply migrations." unless options[:yes]

      auth = auth_for(load_config(options.fetch(:config)))
      migrated = BetterAuth::SQLMigration.migrate_pending(auth)
      stdout.puts(migrated ? "migration completed successfully." : "No migrations needed.")
      0
    end

    def migration_status(args)
      options = parse_config_options(args, "migrate status --config PATH is required")
      config = load_config(options.fetch(:config))
      adapter = required_sql_adapter_for(config)
      plan = BetterAuth::SQLMigration.plan(config, connection: adapter.connection, dialect: adapter.dialect)

      if plan.empty?
        stdout.puts "No migrations needed."
      else
        plan.to_create.each { |change| stdout.puts "create table #{change.table_name}" }
        plan.to_add.each { |change| stdout.puts "add #{change.fields.keys.join(", ")} to #{change.table_name}" }
        plan.to_index.each { |change| stdout.puts "create index #{change.name}" }
        plan.warnings.each { |warning| stdout.puts "warning: #{warning}" }
      end
      0
    end

    def doctor(args)
      options = parse_config_options(args, "doctor --config PATH is required")
      config = load_config(options.fetch(:config))
      BetterAuth::Doctor.print(BetterAuth::Doctor.check(config), stdout: stdout, stderr: stderr)
    end

    def mongo(args)
      command = args.shift
      case command
      when "indexes"
        mongo_indexes(args)
      else
        raise Error, "Unknown mongo command: #{command || "(none)"}"
      end
    end

    def mongo_indexes(args)
      options = parse_config_options(args, "mongo indexes --config PATH is required")
      auth = auth_for(load_config(options.fetch(:config)))
      adapter = auth.context.adapter
      unless adapter.respond_to?(:ensure_indexes!)
        raise Error, "MongoDB index setup requires an adapter that supports ensure_indexes!"
      end

      indexes = adapter.ensure_indexes!
      if indexes.empty?
        stdout.puts "No MongoDB indexes needed."
      else
        indexes.each do |index|
          validate_mongo_index!(index)
          unique = index[:unique] ? " unique" : ""
          stdout.puts "ensured#{unique} index #{index[:collection]}.#{index[:field]}"
        end
      end
      0
    end

    def parse_generate_options(args)
      options = {}
      OptionParser.new do |parser|
        parser.on("--config PATH") { |value| options[:config] = value }
        parser.on("--dialect DIALECT") { |value| options[:dialect] = value }
        parser.on("--output PATH") { |value| options[:output] = value }
      end.parse!(args)
      require_option!(options, :config, "generate --config PATH is required")
      require_option!(options, :output, "generate --output PATH is required")
      options
    end

    def parse_migrate_options(args)
      options = {yes: false}
      OptionParser.new do |parser|
        parser.on("--config PATH") { |value| options[:config] = value }
        parser.on("--yes", "-y") { options[:yes] = true }
      end.parse!(args)
      require_option!(options, :config, "migrate --config PATH is required")
      options
    end

    def parse_config_options(args, missing_message)
      options = {}
      OptionParser.new do |parser|
        parser.on("--config PATH") { |value| options[:config] = value }
      end.parse!(args)
      require_option!(options, :config, missing_message)
      options
    end

    def require_option!(options, key, message)
      raise Error, message unless options[key]
    end

    def load_config(path)
      raise Error, "Config file not found: #{path}" unless File.exist?(path)

      self.class.configure(nil)
      result = TOPLEVEL_BINDING.eval(File.read(path), path)
      value = normalize_config_value(result) || self.class.configuration
      raise Error, "Config file must return a Hash, BetterAuth::Configuration, or BetterAuth::Auth" unless value

      BetterAuth::SQLMigration.configuration_for(value)
    end

    def normalize_config_value(value)
      value if value.is_a?(Hash) || value.is_a?(BetterAuth::Configuration) || value.is_a?(BetterAuth::Auth)
    end

    def validate_mongo_index!(index)
      return if index[:collection] && index[:field]

      raise Error, "MongoDB index metadata must include collection and field"
    end

    def sql_adapter_for(config)
      required_sql_adapter_for(config)
    rescue BetterAuth::SQLMigration::UnsupportedAdapterError
      nil
    end

    def required_sql_adapter_for(config)
      adapter = auth_for(config).context.adapter
      unless adapter.respond_to?(:dialect) && adapter.respond_to?(:connection)
        raise BetterAuth::SQLMigration::UnsupportedAdapterError,
          "Better Auth SQL migrations require core SQL adapters with connection and dialect support"
      end

      adapter
    end

    def auth_for(config)
      return config if config.is_a?(BetterAuth::Auth)

      BetterAuth.auth(config.to_h)
    end

    def usage
      <<~TEXT
        Usage:
          better-auth generate --config PATH --dialect DIALECT --output PATH
          better-auth migrate --config PATH --yes
          better-auth migrate status --config PATH
          better-auth doctor --config PATH
          better-auth mongo indexes --config PATH
      TEXT
    end
  end
end

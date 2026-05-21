# frozen_string_literal: true

require "fileutils"
require "sqlite3"
require "stringio"
require "tmpdir"

class BetterAuthCLIFakeSQLConnection
  attr_reader :statements

  def initialize
    @statements = []
  end

  def execute(sql)
    statements << sql
    []
  end
end

class BetterAuthCLIFakeSQLAdapter < BetterAuth::Adapters::Base
  attr_reader :connection, :dialect

  def initialize(options, dialect:)
    super(options)
    @dialect = dialect.to_sym
    @connection = BetterAuthCLIFakeSQLConnection.new
  end
end

class BetterAuthCLIFakeMongoAdapter < BetterAuth::Adapters::Base
  def initialize(options, indexes:)
    super(options)
    @indexes = indexes
  end

  def ensure_indexes!
    @indexes
  end
end

module BetterAuthCLITestHelpers
  SECRET = "cli-secret-that-is-long-enough-for-validation"
  HARDENED_SECRET = "cli-hardened-secret-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ"

  def run_cli(*argv)
    stdout = StringIO.new
    stderr = StringIO.new
    status = BetterAuth::CLI.run(argv, stdout: stdout, stderr: stderr)
    [status, stdout.string, stderr.string]
  end

  def write_config(dir, source, filename: "better_auth.rb")
    path = File.join(dir, filename)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, source)
    path
  end

  def write_hash_config(dir, options = {})
    write_config(dir, ruby_hash(options))
  end

  def write_sqlite_config(dir, secret: SECRET, base_url: nil, rate_limit: nil, plugins_source: nil)
    db_path = File.join(dir, "auth.sqlite3")
    write_config(
      dir,
      <<~RUBY
        {
          secret: #{secret.inspect},
          database: ->(options) { BetterAuth::Adapters::SQLite.new(options, path: #{db_path.inspect}) },
          email_and_password: {enabled: true}#{option_line(:base_url, base_url)}#{option_line(:rate_limit, rate_limit)}#{plugins_line(plugins_source)}
        }
      RUBY
    )
  end

  def write_fake_sql_config(dir, dialect:, secret: SECRET, rate_limit: nil)
    write_config(
      dir,
      <<~RUBY
        {
          secret: #{secret.inspect},
          database: ->(options) { BetterAuthCLIFakeSQLAdapter.new(options, dialect: #{dialect.inspect}) },
          email_and_password: {enabled: true}#{option_line(:rate_limit, rate_limit)}
        }
      RUBY
    )
  end

  def write_mongo_config(dir, indexes:)
    write_config(
      dir,
      <<~RUBY
        {
          secret: #{SECRET.inspect},
          database: ->(options) { BetterAuthCLIFakeMongoAdapter.new(options, indexes: #{ruby_hash(indexes)}) }
        }
      RUBY
    )
  end

  def sqlite_tables(dir)
    db = SQLite3::Database.new(File.join(dir, "auth.sqlite3"))
    db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").flatten
  ensure
    db&.close
  end

  def db_integration_enabled?
    ENV["BETTER_AUTH_CLI_RUN_DB_INTEGRATION"] == "1"
  end

  def skip_db_integration_unless_enabled!
    skip "set BETTER_AUTH_CLI_RUN_DB_INTEGRATION=1 to run optional CLI database integration tests" unless db_integration_enabled?
  end

  private

  def option_line(name, value)
    value.nil? ? "" : ",\n  #{name}: #{ruby_hash(value)}"
  end

  def plugins_line(source)
    source ? ",\n  plugins: #{source}" : ""
  end

  def ruby_hash(value)
    case value
    when Hash
      "{" + value.map { |key, item| "#{key.inspect} => #{ruby_hash(item)}" }.join(", ") + "}"
    when Array
      "[" + value.map { |item| ruby_hash(item) }.join(", ") + "]"
    when Symbol
      ":#{value}"
    else
      value.inspect
    end
  end
end

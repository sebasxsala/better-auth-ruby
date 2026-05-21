# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "better_auth"

require "minitest/autorun"
require "minitest/mock"
require "minitest/spec"

module BetterAuthMySQLTestHelpers
  def mysql_connection
    Mysql2::Client.new(
      host: ENV.fetch("BETTER_AUTH_MYSQL_HOST", "127.0.0.1"),
      port: ENV.fetch("BETTER_AUTH_MYSQL_PORT", "3306").to_i,
      username: ENV.fetch("BETTER_AUTH_MYSQL_USER", "user"),
      password: ENV.fetch("BETTER_AUTH_MYSQL_PASSWORD", "password"),
      database: ENV.fetch("BETTER_AUTH_MYSQL_DATABASE", "better_auth"),
      symbolize_keys: false
    )
  end

  def reset_mysql_schema(connection)
    connection.query("SET FOREIGN_KEY_CHECKS = 0")
    mysql_table_names(connection).each do |table|
      connection.query("DROP TABLE IF EXISTS #{quote_mysql_identifier(table)}")
    end
  ensure
    connection&.query("SET FOREIGN_KEY_CHECKS = 1")
  end

  def mysql_table_names(connection)
    connection.query(<<~SQL).map { |row| row["table_name"] || row.fetch("TABLE_NAME") }
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
    SQL
  end

  def quote_mysql_identifier(identifier)
    "`#{identifier.to_s.gsub("`", "``")}`"
  end
end

# Configure SimpleCov if running coverage
if ENV["COVERAGE"]
  require "simplecov"
  SimpleCov.start do
    add_filter "/test/"
  end
end

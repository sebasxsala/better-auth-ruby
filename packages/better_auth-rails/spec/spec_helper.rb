# frozen_string_literal: true

require "bundler/setup"
require "better_auth/rails"
require "better_auth_rails"

module BetterAuthRailsMySQLSpecHelpers
  def reset_mysql_schema(connection = ActiveRecord::Base.connection)
    connection.execute("SET FOREIGN_KEY_CHECKS = 0")
    mysql_table_names(connection).each do |table|
      connection.execute("DROP TABLE IF EXISTS #{connection.quote_table_name(table)}")
    end
  ensure
    connection&.execute("SET FOREIGN_KEY_CHECKS = 1")
  end

  def mysql_table_names(connection = ActiveRecord::Base.connection)
    connection.select_values(<<~SQL)
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
    SQL
  end
end

RSpec.configure do |config|
  config.example_status_persistence_file_path = ".rspec_status"
  config.disable_monkey_patching!
  config.include BetterAuthRailsMySQLSpecHelpers

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

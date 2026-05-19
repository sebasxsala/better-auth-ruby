# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../../better_auth-cli/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../../better_auth/lib", __dir__)

require "fileutils"
require "minitest/autorun"
require "open3"
require "rbconfig"
require "sqlite3"
require "tmpdir"

class OpenAuthCLITest < Minitest::Test
  SECRET = "openauth-cli-secret-that-is-long-enough-for-validation"

  def test_openauth_executable_is_packaged
    spec = Gem::Specification.load(File.expand_path("../../openauth-cli.gemspec", __dir__))

    assert_includes spec.executables, "openauth"
    assert_equal "better_auth-cli", spec.dependencies.find { |dependency| dependency.name == "better_auth-cli" }.name
  end

  def test_openauth_executable_runs_generate_command
    Dir.mktmpdir("openauth-cli") do |dir|
      config_path = write_sqlite_config(dir)
      output = File.join(dir, "openauth.sql")
      ruby_lib = [
        File.expand_path("../../lib", __dir__),
        File.expand_path("../../../better_auth-cli/lib", __dir__),
        File.expand_path("../../../better_auth/lib", __dir__)
      ].join(File::PATH_SEPARATOR)

      stdout, stderr, status = Open3.capture3(
        {"RUBYLIB" => ruby_lib},
        RbConfig.ruby,
        File.expand_path("../../exe/openauth", __dir__),
        "generate",
        "--config",
        config_path,
        "--dialect",
        "sqlite",
        "--output",
        output
      )

      assert status.success?, stderr
      assert_includes stdout, "generated #{output}"
      assert_includes File.read(output), 'CREATE TABLE IF NOT EXISTS "users"'
    end
  end

  private

  def write_sqlite_config(dir)
    path = File.join(dir, "better_auth.rb")
    db_path = File.join(dir, "auth.sqlite3")
    File.write(
      path,
      <<~RUBY
        {
          secret: #{SECRET.inspect},
          database: ->(options) { BetterAuth::Adapters::SQLite.new(options, path: #{db_path.inspect}) },
          email_and_password: {enabled: true}
        }
      RUBY
    )
    path
  end
end

# frozen_string_literal: true

require "rake"
require_relative "../../spec_helper"

RSpec.describe "BetterAuth Hanami rake tasks" do
  around do |example|
    old_application = Rake.application
    Rake.application = Rake::Application.new
    load File.expand_path("../../../lib/tasks/better_auth.rake", __dir__)
    example.run
  ensure
    Rake.application = old_application
    BetterAuth::Hanami.instance_variable_set(:@auth, nil)
    BetterAuth::Hanami.instance_variable_set(:@configuration, nil)
  end

  it "defines the public Hanami task surface" do
    expect(Rake::Task.task_defined?("better_auth:init")).to be(true)
    expect(Rake::Task.task_defined?("better_auth:generate:migration")).to be(true)
    expect(Rake::Task.task_defined?("better_auth:generate:relations")).to be(true)
    expect(Rake::Task.task_defined?("better_auth:doctor")).to be(true)
  end

  it "runs init from a Hanami app root" do
    Dir.mktmpdir("better-auth-hanami-rake") do |dir|
      write_hanami_app_files(dir)

      Dir.chdir(dir) { Rake::Task["better_auth:init"].invoke }

      expect(File.read(File.join(dir, "config/providers/better_auth.rb"))).to include("Hanami.app.register_provider(:better_auth)")
      expect(Dir[File.join(dir, "config/db/migrate/*_create_better_auth_tables.rb")].length).to eq(1)
      expect(File.read(File.join(dir, "app/relations/users.rb"))).to include("schema :users, infer: true")
    end
  end

  it "runs migration and relation generators from rake tasks" do
    Dir.mktmpdir("better-auth-hanami-rake") do |dir|
      write_hanami_app_files(dir)

      Dir.chdir(dir) do
        Rake::Task["better_auth:generate:migration"].invoke
        Rake::Task["better_auth:generate:relations"].invoke
      end

      expect(Dir[File.join(dir, "config/db/migrate/*_create_better_auth_tables.rb")].length).to eq(1)
      expect(File.read(File.join(dir, "app/repos/user_repo.rb"))).to include("class UserRepo < Repo[:users]")
    end
  end

  it "runs the doctor task against Hanami configuration" do
    BetterAuth::Hanami.configure do |config|
      config.secret = "0123456789abcdef0123456789abcdef"
      config.database = :memory
      config.base_url = "https://example.test"
      config.rate_limit = {enabled: true, storage: "memory"}
    end
    output = StringIO.new
    errors = StringIO.new
    old_stdout = $stdout
    old_stderr = $stderr
    $stdout = output
    $stderr = errors

    expect { Rake::Task["better_auth:doctor"].invoke }.not_to raise_error

    expect(output.string).to include("OK config loaded")
    expect(errors.string).to eq("")
  ensure
    $stdout = old_stdout
    $stderr = old_stderr
  end

  def write_hanami_app_files(dir)
    FileUtils.mkdir_p(File.join(dir, "config"))
    File.write(File.join(dir, "config/routes.rb"), <<~RUBY)
      # frozen_string_literal: true

      module Bookshelf
        class Routes < Hanami::Routes
        end
      end
    RUBY
    File.write(File.join(dir, "config/settings.rb"), <<~RUBY)
      # frozen_string_literal: true

      module Bookshelf
        class Settings < Hanami::Settings
        end
      end
    RUBY
  end
end

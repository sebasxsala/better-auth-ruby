# frozen_string_literal: true

require "tmpdir"
require_relative "../../spec_helper"
require "generators/better_auth/install/install_generator"

RSpec.describe BetterAuth::Generators::InstallGenerator do
  around do |example|
    Dir.mktmpdir("better-auth-rails-generator") do |dir|
      @destination = dir
      example.run
    end
  end

  it "creates the initializer and base migration" do
    described_class.start(["--database=postgresql"], destination_root: @destination)

    initializer = File.join(@destination, "config/initializers/better_auth.rb")
    migrations = Dir[File.join(@destination, "db/migrate/*_create_better_auth_tables.rb")]
    initializer_contents = File.read(initializer)

    expect(initializer_contents).to include("BetterAuth::Rails.configure")
    expect(initializer_contents).not_to include("config.database = ->")
    expect(initializer_contents).to include('BetterAuth::Env.get("BETTER_AUTH_URL")')
    expect(initializer_contents).to include("config.trusted_origins")
    expect(initializer_contents).to include("config.session do |session|")
    expect(initializer_contents).to include("cookie.strategy = \"jwe\"")
    expect(initializer_contents).to include("config.advanced do |advanced|")
    expect(initializer_contents).to include("config.experimental do |experimental|")
    expect(initializer_contents).to include("config.social_providers do |providers|")
    expect(initializer_contents).to include("config.plugins")
    expect(initializer_contents).to include("config.hooks do |hooks|")
    expect(migrations.length).to eq(1)
    expect(File.read(migrations.first)).to include("create_table :users, id: :string")
  end

  it "does not overwrite an existing initializer" do
    path = File.join(@destination, "config/initializers")
    FileUtils.mkdir_p(path)
    initializer = File.join(path, "better_auth.rb")
    File.write(initializer, "# existing\n")

    described_class.start([], destination_root: @destination)

    expect(File.read(initializer)).to eq("# existing\n")
  end

  it "keeps the README initializer snippet aligned with the generated template" do
    readme = File.read(File.expand_path("../../../README.md", __dir__))

    expect(readme).to include('BetterAuth::Env.get("BETTER_AUTH_URL")')
    expect(readme).not_to include('ENV["BETTER_AUTH_URL"]')
    expect(readme).not_to include("/Users/")
  end
end

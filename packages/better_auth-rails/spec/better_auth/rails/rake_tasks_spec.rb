# frozen_string_literal: true

require "rake"
require_relative "../../spec_helper"

RSpec.describe "BetterAuth Rails rake tasks" do
  around do |example|
    previous_application = Rake.application
    Rake.application = Rake::Application.new
    Rake::Task.define_task(:environment)
    load File.expand_path("../../../lib/tasks/better_auth.rake", __dir__)
    example.run
  ensure
    Rake.application = previous_application
  end

  it "loads the Rails environment before running the install task" do
    expect(Rake::Task["better_auth:init"].prerequisites).to include("environment")
  end

  it "loads the Rails environment before generating migrations" do
    expect(Rake::Task["better_auth:generate:migration"].prerequisites).to include("environment")
  end

  it "loads the Rails environment before running doctor" do
    expect(Rake::Task["better_auth:doctor"].prerequisites).to include("environment")
  end
end

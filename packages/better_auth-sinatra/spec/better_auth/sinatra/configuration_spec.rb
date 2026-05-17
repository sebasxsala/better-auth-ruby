# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe BetterAuth::Sinatra do
  after do
    described_class.reset!
  end

  it "builds a memoized core auth instance from Sinatra configuration" do
    described_class.configure do |config|
      config.secret = secret
      config.base_url = "http://localhost:9292"
      config.base_path = "/api/auth"
      config.database = :memory
      config.email_and_password = {enabled: true}
      config.trusted_origins = ["http://localhost:9292"]
      config.password_hasher = :bcrypt
    end

    auth = described_class.auth

    expect(auth).to be_a(BetterAuth::Auth)
    expect(described_class.auth).to equal(auth)
    expect(auth.options.secret).to eq(secret)
    expect(auth.options.base_path).to eq("/api/auth")
    expect(auth.options.email_and_password[:enabled]).to be(true)
    expect(auth.options.trusted_origins).to include("http://localhost:9292")
    expect(auth.options.password_hasher).to eq(:bcrypt)
  end

  it "does not memoize override auth instances" do
    described_class.configure do |config|
      config.secret = secret
      config.database = :memory
    end

    default_auth = described_class.auth
    override_auth = described_class.auth(base_path: "/custom-auth")

    expect(override_auth).to be_a(BetterAuth::Auth)
    expect(override_auth.options.base_path).to eq("/custom-auth")
    expect(described_class.auth).to equal(default_auth)
  end

  it "clears the memoized auth when configuration changes" do
    described_class.configure do |config|
      config.secret = secret
      config.database = :memory
    end
    first_auth = described_class.auth

    described_class.configure do |config|
      config.base_path = "/auth"
    end

    expect(described_class.auth).not_to equal(first_auth)
    expect(described_class.auth.options.base_path).to eq("/auth")
  end

  it "includes versioned secrets in auth options when set" do
    described_class.configure do |config|
      config.secret = secret
      config.database = :memory
      config.secrets = [{version: 1, value: "rotated-secret-that-is-long-enough-for-validation"}]
    end

    options = described_class.configuration.to_auth_options

    expect(options[:secrets]).to eq([{version: 1, value: "rotated-secret-that-is-long-enough-for-validation"}])
  end

  it "generates a default config template that supports open auth env aliases" do
    template = described_class.default_config_template

    expect(template).to include('BetterAuth::Env.fetch("BETTER_AUTH_SECRET"')
    expect(template).to include('BetterAuth::Env.get("BETTER_AUTH_URL")')
    expect(template).to include('BetterAuth::Env.fetch("BETTER_AUTH_DATABASE_DIALECT"')
  end

  def secret
    "sinatra-secret-that-is-long-enough-for-validation"
  end
end

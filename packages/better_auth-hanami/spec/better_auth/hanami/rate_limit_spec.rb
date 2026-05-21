# frozen_string_literal: true

require_relative "../../spec_helper"

class BetterAuthHanamiRateLimitStorage
  attr_reader :data

  def initialize
    @data = {}
  end

  def get(key)
    data[key]
  end

  def set(key, value, ttl:, update:)
    data[key] = value
  end

  def keys
    data.keys
  end
end

class BetterAuthHanamiSecondaryStorage
  attr_reader :data, :ttls

  def initialize
    @data = {}
    @ttls = {}
  end

  def get(key)
    data[key]
  end

  def set(key, value, ttl)
    data[key] = value
    ttls[key] = ttl
  end
end

RSpec.describe "BetterAuth::Hanami mounted rate limits" do
  let(:secret) { "test-secret-that-is-long-enough-for-validation" }

  it "applies default memory rate limits through the mounted path" do
    app = mounted_limited_app(rate_limit: {enabled: true, window: 60, max: 1})

    expect(app.call(rack_env("GET", "/api/auth/limited")).first).to eq(200)
    status, headers, body = app.call(rack_env("GET", "/api/auth/limited"))

    expect(status).to eq(429)
    expect(headers.fetch("x-retry-after")).to match(/\A\d+\z/)
    expect(JSON.parse(body.join)).to eq("message" => "Too many requests. Please try again later.")
  end

  it "uses custom rate limit storage with mount-stripped route keys" do
    storage = BetterAuthHanamiRateLimitStorage.new
    app = mounted_limited_app(rate_limit: {enabled: true, window: 60, max: 1, custom_storage: storage})

    expect(app.call(rack_env("GET", "/api/auth/limited")).first).to eq(200)
    expect(app.call(rack_env("GET", "/api/auth/limited")).first).to eq(429)

    expect(storage.keys).to eq(["127.0.0.1|/limited"])
  end

  it "uses secondary storage with TTL payloads through the mounted path" do
    storage = BetterAuthHanamiSecondaryStorage.new
    app = mounted_limited_app(
      secondary_storage: storage,
      rate_limit: {enabled: true, window: 60, max: 1, storage: "secondary-storage"}
    )

    expect(app.call(rack_env("GET", "/api/auth/limited")).first).to eq(200)
    stored = JSON.parse(storage.data.fetch("127.0.0.1|/limited"))
    expect(stored.keys.sort).to eq(%w[count key lastRequest])
    expect(stored.fetch("count")).to eq(1)
    expect(stored.fetch("lastRequest")).to be_a(Integer)
    expect(storage.ttls.fetch("127.0.0.1|/limited")).to eq(60)
    expect(app.call(rack_env("GET", "/api/auth/limited")).first).to eq(429)
  end

  it "uses Sequel database storage for mounted route rate limits" do
    db = Sequel.sqlite
    config = BetterAuth::Configuration.new(secret: secret, database: :memory, rate_limit: {storage: "database"})
    apply_migration(db, config)
    auth = limited_auth(
      database: ->(options) { BetterAuth::Hanami::SequelAdapter.new(options, connection: db) },
      rate_limit: {enabled: true, window: 60, max: 1, storage: "database"}
    )
    app = BetterAuth::Hanami::MountedApp.new(auth, mount_path: "/api/auth")

    expect(app.call(rack_env("GET", "/api/auth/limited")).first).to eq(200)
    record = auth.context.adapter.find_one(model: "rateLimit", where: [{field: "key", value: "127.0.0.1|/limited"}])
    expect(record).to include("key" => "127.0.0.1|/limited", "count" => 1)
    expect(record.fetch("lastRequest")).to be_a(Integer)
    expect(app.call(rack_env("GET", "/api/auth/limited")).first).to eq(429)
  end

  def mounted_limited_app(**options)
    BetterAuth::Hanami::MountedApp.new(limited_auth(**options), mount_path: "/api/auth")
  end

  def limited_auth(**options)
    BetterAuth.auth(
      {
        base_url: "http://localhost:2300",
        secret: secret,
        plugins: [
          BetterAuth::Plugin.new(
            id: "rate-limit-test",
            endpoints: {
              limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
            }
          )
        ]
      }.merge(options)
    )
  end

  # rubocop:disable Security/Eval
  def apply_migration(db, config)
    require "rom-sql"
    gateway = ROM::SQL::Gateway.new(db)
    migration = ROM::SQL.with_gateway(gateway) do
      eval(BetterAuth::Hanami::Migration.render(config), binding, __FILE__, __LINE__)
    end
    migration.apply(db, :up)
  end
  # rubocop:enable Security/Eval

  def rack_env(method, path, body: "")
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "2300",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(body)
    }
  end
end

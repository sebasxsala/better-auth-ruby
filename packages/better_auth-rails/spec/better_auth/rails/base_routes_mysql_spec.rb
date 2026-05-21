# frozen_string_literal: true

require "json"
require "stringio"
require "tmpdir"
require_relative "../../spec_helper"

RSpec.describe "BetterAuth::Rails ActiveRecord base routes (MySQL)" do
  let(:url) { ENV.fetch("BETTER_AUTH_MYSQL_URL", "mysql2://user:password@127.0.0.1:3306/better_auth") }
  let(:secret) { "test-secret-that-is-long-enough-for-validation" }

  before do
    require "mysql2"
    require "active_record"
    ActiveRecord::Base.establish_connection(url)
    reset_schema
    run_generated_migration
  end

  after do
    reset_schema if ActiveRecord::Base.connected?
    ActiveRecord::Base.connection_pool.disconnect! if ActiveRecord::Base.connected?
  end

  it "runs signup, signin, and get-session routes against ActiveRecord persistence" do
    signup_auth = build_auth

    signup_status, signup_headers, signup_body = signup_auth.call(
      rack_env(
        "POST",
        "/api/auth/sign-up/email",
        body: JSON.generate(email: "Ada@Example.com", password: "password123", name: "Ada")
      )
    )
    signup_data = JSON.parse(signup_body.join)

    expect(signup_status).to eq(200)
    expect(signup_data.fetch("user").fetch("email")).to eq("ada@example.com")
    expect(signup_headers.fetch("set-cookie")).to include("better-auth.session_token=")

    signin_auth = build_auth
    signin_status, signin_headers, signin_body = signin_auth.call(
      rack_env(
        "POST",
        "/api/auth/sign-in/email",
        body: JSON.generate(email: "ada@example.com", password: "password123")
      )
    )
    signin_data = JSON.parse(signin_body.join)
    cookie = cookie_header(signin_headers.fetch("set-cookie"))

    expect(signin_status).to eq(200)
    expect(signin_data.fetch("user").fetch("id")).to eq(signup_data.fetch("user").fetch("id"))

    session_status, _session_headers, session_body = signin_auth.call(
      rack_env("GET", "/api/auth/get-session", body: "", extra_headers: {"HTTP_COOKIE" => cookie})
    )
    session_data = JSON.parse(session_body.join)

    expect(session_status).to eq(200)
    expect(session_data.fetch("user").fetch("email")).to eq("ada@example.com")
    expect(session_data.fetch("session").fetch("userId")).to eq(signup_data.fetch("user").fetch("id"))
  end

  def build_auth
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: secret,
      email_and_password: {enabled: true},
      database: ->(options) { BetterAuth::Rails::ActiveRecordAdapter.new(options, connection: ActiveRecord::Base) }
    )
  end

  def rack_env(method, path, body:, content_type: "application/json", extra_headers: {})
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(body),
      "CONTENT_TYPE" => content_type,
      "CONTENT_LENGTH" => body.bytesize.to_s,
      "HTTP_ORIGIN" => "http://localhost:3000"
    }.merge(extra_headers)
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end

  def run_generated_migration
    Object.send(:remove_const, :CreateBetterAuthTables) if Object.const_defined?(:CreateBetterAuthTables)
    Dir.mktmpdir("better-auth-migration") do |dir|
      path = File.join(dir, "create_better_auth_tables.rb")
      File.write(path, BetterAuth::Rails::Migration.render(BetterAuth::Configuration.new(secret: secret, database: :memory)))
      load path
    end
    CreateBetterAuthTables.migrate(:up)
  end

  def reset_schema
    reset_mysql_schema
  end
end

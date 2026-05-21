# frozen_string_literal: true

require_relative "../../spec_helper"
require "action_dispatch"
require "rack/mock"

class BetterAuthRailsFakeRouteSet
  attr_reader :calls

  def initialize
    @calls = []
  end

  def mount(app, at:)
    calls << [app, at]
  end
end

RSpec.describe BetterAuth::Rails::Routing do
  it "mounts the configured Better Auth Rack app at /api/auth by default" do
    routes = BetterAuthRailsFakeRouteSet.new
    auth = instance_double(BetterAuth::Auth)

    routes.extend(described_class)
    routes.better_auth(auth: auth)

    mounted_app, mount_path = routes.calls.first
    expect(mounted_app).to be_a(BetterAuth::Rails::MountedApp)
    expect(mounted_app.instance_variable_get(:@auth)).to eq(auth)
    expect(mount_path).to eq("/api/auth")
  end

  it "dispatches core endpoints through a real Rails route mount" do
    auth = BetterAuth.auth(secret: secret)
    app = build_route_set do
      better_auth auth: auth
    end

    response = Rack::MockRequest.new(app).get("/api/auth/ok")

    expect(response.status).to eq(200)
    expect(JSON.parse(response.body)).to eq("ok" => true)
  end

  it "builds the auth instance with a custom base path when mounted at a custom path" do
    BetterAuth::Rails.configure do |config|
      config.secret = secret
      config.database = :memory
    end
    app = build_route_set do
      better_auth at: "/auth"
    end

    response = Rack::MockRequest.new(app).get("/auth/ok")

    expect(response.status).to eq(200)
    expect(JSON.parse(response.body)).to eq("ok" => true)
  end

  it "dispatches plugin endpoints through the Rails mount wrapper" do
    plugin = BetterAuth::Plugin.new(
      id: "rails-plugin",
      endpoints: {
        rails_probe: BetterAuth::Endpoint.new(path: "/rails-probe", method: "GET") do |ctx|
          ctx.set_cookie("rails_probe", "1", path: "/")
          {mounted: true, path: ctx.path, cookie: ctx.get_cookie("rails_input")}
        end
      }
    )
    auth = BetterAuth.auth(secret: secret, plugins: [plugin])
    app = build_route_set do
      better_auth auth: auth
    end

    response = Rack::MockRequest.new(app).get("/api/auth/rails-probe", "HTTP_COOKIE" => "rails_input=present")

    expect(response.status).to eq(200)
    expect(JSON.parse(response.body)).to eq("mounted" => true, "path" => "/rails-probe", "cookie" => "present")
    expect(response["set-cookie"]).to include("rails_probe=1")
  end

  it "preserves auth cookies across mounted Rails requests" do
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: secret,
      database: :memory,
      email_and_password: {enabled: true},
      session: {store_session_in_database: true}
    )
    app = build_route_set do
      better_auth auth: auth
    end
    request = Rack::MockRequest.new(app)

    signup = request.post(
      "/api/auth/sign-up/email",
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "http://localhost:3000",
      :input => JSON.generate(email: "rails-session@example.com", password: "password123", name: "Rails Session")
    )
    cookie = signup["set-cookie"].to_s.lines.map { |line| line.split(";").first }.join("; ")
    session = request.get("/api/auth/get-session?disableCookieCache=true", "HTTP_COOKIE" => cookie)

    expect(signup.status).to eq(200)
    expect(JSON.parse(session.body).dig("user", "email")).to eq("rails-session@example.com")
  end

  it "keeps server-only plugin endpoints unreachable through the Rails mount" do
    called = false
    plugin = BetterAuth::Plugin.new(
      id: "server-only",
      endpoints: {
        private_probe: BetterAuth::Endpoint.new(path: "/private-probe", method: "GET", metadata: {SERVER_ONLY: true}) do |_ctx|
          called = true
          {private: true}
        end,
        scoped_probe: BetterAuth::Endpoint.new(path: "/scoped-probe", method: "GET", metadata: {scope: "server"}) do |_ctx|
          called = true
          {private: true}
        end
      }
    )
    auth = BetterAuth.auth(secret: secret, plugins: [plugin])
    app = build_route_set do
      better_auth auth: auth
    end

    private_response = Rack::MockRequest.new(app).get("/api/auth/private-probe")
    scoped_response = Rack::MockRequest.new(app).get("/api/auth/scoped-probe")

    expect(private_response.status).to eq(403)
    expect(scoped_response.status).to eq(403)
    expect(called).to be(false)
  end

  it "keeps core origin checks active for mutating mounted requests with cookies" do
    auth = BetterAuth.auth(secret: secret)
    app = build_route_set do
      better_auth auth: auth
    end

    response = Rack::MockRequest.new(app).post(
      "/api/auth/sign-out",
      "CONTENT_TYPE" => "application/json",
      "HTTP_COOKIE" => "better-auth.session_token=stale-token",
      :input => "{}"
    )

    expect(response.status).to eq(403)
    expect(JSON.parse(response.body)).to eq("code" => "FORBIDDEN", "message" => "Missing or null Origin")
  end

  it "rejects malicious callback URLs through the Rails mount" do
    auth = BetterAuth.auth(
      secret: secret,
      database: :memory,
      email_and_password: {enabled: true},
      trusted_origins: ["http://localhost:3000"]
    )
    app = build_route_set do
      better_auth auth: auth
    end

    response = Rack::MockRequest.new(app).post(
      "/api/auth/sign-up/email",
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "http://localhost:3000",
      :input => JSON.generate(email: "ada@example.com", password: "password123", name: "Ada", callbackURL: "https://evil.example/callback")
    )

    expect(response.status).to eq(403)
    expect(JSON.parse(response.body)).to eq("code" => "FORBIDDEN", "message" => "Invalid callbackURL")
  end

  it "dispatches correctly when Rails is mounted below an outer script name" do
    auth = BetterAuth.auth(secret: secret, base_path: "/api/auth")
    app = BetterAuth::Rails::MountedApp.new(auth, mount_path: "/api/auth")

    status, _headers, body = app.call(
      Rack::MockRequest.env_for(
        "/tenant/api/auth/ok",
        "SCRIPT_NAME" => "/tenant/api/auth",
        "PATH_INFO" => "/ok"
      )
    )

    expect(status).to eq(200)
    expect(JSON.parse(body.join)).to eq("ok" => true)
  end

  it "converts unexpected mounted endpoint errors into Better Auth JSON errors" do
    plugin = BetterAuth::Plugin.new(
      id: "raising",
      endpoints: {
        boom: BetterAuth::Endpoint.new(path: "/boom", method: "GET") do |_ctx|
          raise "boom"
        end
      }
    )
    auth = BetterAuth.auth(secret: secret, plugins: [plugin])
    app = build_route_set do
      better_auth auth: auth
    end

    response = Rack::MockRequest.new(app).get("/api/auth/boom")

    expect(response.status).to eq(500)
    expect(JSON.parse(response.body)).to eq("code" => "INTERNAL_SERVER_ERROR", "message" => "Internal Server Error")
  end

  it "converts unexpected errors for dynamic mounted auth apps without masking the cause" do
    dynamic_auth = Class.new do
      def call(_env)
        raise "dynamic boom"
      end
    end.new
    app = BetterAuth::Rails::MountedApp.new(dynamic_auth, mount_path: "/api/auth")
    errors = StringIO.new

    status, _headers, body = app.call(Rack::MockRequest.env_for("/api/auth/boom", "rack.errors" => errors))

    expect(status).to eq(500)
    expect(JSON.parse(body.join)).to eq("code" => "INTERNAL_SERVER_ERROR", "message" => "Internal Server Error")
    expect(errors.string).to include("BetterAuth::Rails mounted app error: RuntimeError: dynamic boom")
    expect(errors.string).to include("routing_spec.rb")
  end

  it "honors on_api_error callbacks for unexpected mounted endpoint errors" do
    captured = []
    plugin = BetterAuth::Plugin.new(
      id: "callback-raising",
      endpoints: {
        boom: BetterAuth::Endpoint.new(path: "/boom", method: "GET") do |_ctx|
          raise "boom"
        end
      }
    )
    auth = BetterAuth.auth(
      secret: secret,
      plugins: [plugin],
      on_api_error: {on_error: ->(error, ctx) { captured << [error.message, ctx.path] }}
    )
    app = build_route_set do
      better_auth auth: auth
    end

    response = Rack::MockRequest.new(app).get("/api/auth/boom")

    expect(response.status).to eq(500)
    expect(captured).to eq([["boom", "/boom"]])
  end

  it "re-raises unexpected mounted endpoint errors when on_api_error throw is enabled" do
    plugin = BetterAuth::Plugin.new(
      id: "throwing",
      endpoints: {
        boom: BetterAuth::Endpoint.new(path: "/boom", method: "GET") do |_ctx|
          raise "boom"
        end
      }
    )
    auth = BetterAuth.auth(secret: secret, plugins: [plugin], on_api_error: {throw: true})
    app = build_route_set do
      better_auth auth: auth
    end

    expect {
      Rack::MockRequest.new(app).get("/api/auth/boom")
    }.to raise_error(RuntimeError, "boom")
  end

  def build_route_set(&block)
    ActionDispatch::Routing::Mapper.include(BetterAuth::Rails::Routing)
    ActionDispatch::Routing::RouteSet.new.tap { |routes| routes.draw(&block) }
  end

  def secret
    "test-secret-that-is-long-enough-for-validation"
  end

  after do
    BetterAuth::Rails.instance_variable_set(:@auth, nil)
    BetterAuth::Rails.instance_variable_set(:@configuration, nil)
  end
end

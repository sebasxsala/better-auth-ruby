# frozen_string_literal: true

require_relative "../../spec_helper"

class BetterAuthHanamiFakeRoutes
  include BetterAuth::Hanami::Routing

  attr_reader :calls

  def initialize
    @calls = []
  end

  BetterAuth::Hanami::Routing::HTTP_METHODS.each do |method_name|
    define_method(method_name) do |path, to:, **options|
      calls << [method_name, path, to, options]
    end
  end
end

RSpec.describe BetterAuth::Hanami::Routing do
  it "registers all supported methods for the base path and wildcard path" do
    routes = BetterAuthHanamiFakeRoutes.new
    auth = BetterAuth.auth(secret: secret, database: :memory)

    routes.better_auth(auth: auth)

    expect(routes.calls.map { |call| call[0] }.uniq).to eq(%i[get post put patch delete options])
    expect(routes.calls.map { |call| call[1] }).to include("/api/auth", "/api/auth/*path")
    expect(routes.calls.all? { |call| call[2].is_a?(BetterAuth::Hanami::MountedApp) }).to be(true)
  end

  it "normalizes custom mount paths" do
    routes = BetterAuthHanamiFakeRoutes.new
    routes.better_auth(auth: BetterAuth.auth(secret: secret, database: :memory), at: "auth/")

    expect(routes.calls.map { |call| call[1] }).to include("/auth", "/auth/*path")
  end

  it "uses the memoized Hanami auth instance when mounted at the configured base path" do
    BetterAuth::Hanami.configure do |config|
      config.secret = secret
      config.database = :memory
      config.base_path = "/api/auth"
    end
    memoized_auth = BetterAuth::Hanami.auth
    routes = BetterAuthHanamiFakeRoutes.new

    routes.better_auth

    mounted_apps = routes.calls.map { |call| call[2] }.uniq
    expect(mounted_apps.length).to eq(1)
    expect(mounted_apps.first.instance_variable_get(:@auth)).to equal(memoized_auth)
  ensure
    BetterAuth::Hanami.instance_variable_set(:@auth, nil)
    BetterAuth::Hanami.instance_variable_set(:@configuration, nil)
  end

  it "dispatches core endpoints through a real Hanami route set" do
    auth = BetterAuth.auth(secret: secret, database: :memory)
    router = build_hanami_router(auth)

    response = Rack::MockRequest.new(router).get("/api/auth/ok")

    expect(response.status).to eq(200)
    expect(JSON.parse(response.body)).to eq("ok" => true)
  end

  it "dispatches core endpoints through a real Hanami route set at a custom mount path" do
    auth = BetterAuth.auth(secret: secret, database: :memory, base_path: "/auth")
    router = build_hanami_router(auth, at: "/auth")

    response = Rack::MockRequest.new(router).get("/auth/ok")

    expect(response.status).to eq(200)
    expect(JSON.parse(response.body)).to eq("ok" => true)
  end

  it "dispatches plugin endpoints with request cookies and response Set-Cookie headers" do
    plugin = BetterAuth::Plugin.new(
      id: "hanami-plugin",
      endpoints: {
        hanami_probe: BetterAuth::Endpoint.new(path: "/hanami-probe", method: "GET") do |ctx|
          ctx.set_cookie("hanami_probe", "1", path: "/")
          {mounted: true, path: ctx.path, cookie: ctx.get_cookie("hanami_input")}
        end
      }
    )
    auth = BetterAuth.auth(secret: secret, database: :memory, plugins: [plugin])
    router = build_hanami_router(auth)

    response = Rack::MockRequest.new(router).get("/api/auth/hanami-probe", "HTTP_COOKIE" => "hanami_input=present")

    expect(response.status).to eq(200)
    expect(JSON.parse(response.body)).to eq("mounted" => true, "path" => "/hanami-probe", "cookie" => "present")
    expect(response["set-cookie"]).to include("hanami_probe=1")
  end

  it "supports the generated route require path on its own" do
    ruby = <<~RUBY
      $LOAD_PATH.unshift("#{File.expand_path("../../../lib", __dir__)}")
      require "better_auth/hanami"
      require "hanami/routes"

      Class.new(Hanami::Routes) do
        include BetterAuth::Hanami::Routing
        better_auth auth: BetterAuth.auth(secret: "#{secret}", database: :memory)
      end
    RUBY

    output = IO.popen([RbConfig.ruby, "-e", ruby], err: [:child, :out], &:read)
    status = $?

    expect(status).to be_success, output
  end

  it "forwards requests under the auth mount path when Rack script name is non-root" do
    auth = BetterAuth.auth(secret: secret, database: :memory)
    app = BetterAuth::Hanami::MountedApp.new(auth, mount_path: "/api/auth")

    status, _headers, body = app.call(
      "REQUEST_METHOD" => "GET",
      "PATH_INFO" => "/api/auth/ok",
      "SCRIPT_NAME" => "/myapp",
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "2300",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new("")
    )

    expect(status).to eq(200)
    expect(JSON.parse(body.join)).to eq("ok" => true)
  end

  def secret
    "test-secret-that-is-long-enough-for-validation"
  end

  def build_hanami_router(auth, at: "/api/auth")
    require "hanami/routes"
    require "hanami/slice/router"
    require "dry/inflector"

    routes = Class.new(Hanami::Routes) do
      include BetterAuth::Hanami::Routing

      better_auth auth: auth, at: at
    end
    Hanami::Slice::Router.new(routes: routes.routes, inflector: Dry::Inflector.new) {}
  end
end

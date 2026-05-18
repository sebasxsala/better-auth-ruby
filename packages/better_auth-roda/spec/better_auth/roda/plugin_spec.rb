# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe "BetterAuth::Roda plugin" do
  include Rack::Test::Methods

  attr_accessor :app

  after do
    BetterAuth::Roda.reset! if BetterAuth::Roda.respond_to?(:reset!)
  end

  it "mounts core Better Auth routes at /api/auth by default" do
    self.app = build_app

    get "/api/auth/ok"

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("ok" => true)
  end

  it "mounts core Better Auth routes at a custom path" do
    self.app = build_app(mount_path: "/auth")

    get "/auth/ok"

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("ok" => true)
  end

  it "preserves trailing slashes so core handles default route parity" do
    self.app = build_app

    get "/api/auth/ok/"

    expect(last_response.status).to eq(404)
    expect(JSON.parse(last_response.body)).to eq("error" => "Not Found")
  end

  it "lets core skip trailing slashes when configured" do
    self.app = build_app(overrides: {advanced: {skip_trailing_slashes: true}})

    get "/api/auth/ok/"

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("ok" => true)
  end

  it "dispatches auth when SCRIPT_NAME and PATH_INFO split the mount prefix" do
    self.app = build_app(mount_path: "/api/auth")

    get "/ok", {}, {"SCRIPT_NAME" => "/api/auth", "PATH_INFO" => "/ok"}

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("ok" => true)
  end

  it "preserves trailing slashes when SCRIPT_NAME and PATH_INFO split the mount prefix" do
    self.app = build_app(mount_path: "/api/auth")

    get "/ok/", {}, {"SCRIPT_NAME" => "/api/auth", "PATH_INFO" => "/ok/"}

    expect(last_response.status).to eq(404)
    expect(JSON.parse(last_response.body)).to eq("error" => "Not Found")
  end

  it "dispatches auth when the Roda app is nested under a parent Rack mount" do
    self.app = build_app(mount_path: "/auth")

    get "/auth/ok", {}, {"SCRIPT_NAME" => "/api", "PATH_INFO" => "/auth/ok"}

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("ok" => true)
  end

  it "does not duplicate SCRIPT_NAME in Rack request path for shared auth mounts" do
    plugin = BetterAuth::Plugin.new(
      id: "roda-request-url",
      endpoints: {
        request_url_probe: BetterAuth::Endpoint.new(path: "/request-url-probe", method: "GET") do |ctx|
          {
            path: ctx.request.path,
            url: ctx.request.url
          }
        end
      }
    )
    self.app = build_app(mount_path: "/api/auth", plugins: [plugin])

    get "/request-url-probe", {}, {
      "SCRIPT_NAME" => "/api/auth",
      "PATH_INFO" => "/request-url-probe",
      "HTTP_HOST" => "example.org"
    }

    expect(last_response.status).to eq(200)
    data = JSON.parse(last_response.body)
    expect(data.fetch("path")).to eq("/api/auth/request-url-probe")
    expect(data.fetch("url")).to eq("http://example.org/api/auth/request-url-probe")
  end

  it "dispatches plugin endpoints with request cookies and response Set-Cookie headers" do
    plugin = BetterAuth::Plugin.new(
      id: "roda-plugin",
      endpoints: {
        roda_probe: BetterAuth::Endpoint.new(path: "/roda-probe", method: "GET") do |ctx|
          ctx.set_cookie("roda_probe", "1", path: "/")
          {mounted: true, path: ctx.path, cookie: ctx.get_cookie("roda_input")}
        end
      }
    )
    self.app = build_app(plugins: [plugin])

    get "/api/auth/roda-probe", {}, "HTTP_COOKIE" => "roda_input=present"

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("mounted" => true, "path" => "/roda-probe", "cookie" => "present")
    expect(last_response["set-cookie"]).to include("roda_probe=1")
  end

  it "keeps server-only plugin endpoints unreachable through the Roda mount" do
    called = false
    plugin = BetterAuth::Plugin.new(
      id: "server-only",
      endpoints: {
        private_probe: BetterAuth::Endpoint.new(path: "/private-probe", method: "GET", metadata: {SERVER_ONLY: true}) do
          called = true
          {private: true}
        end
      }
    )
    self.app = build_app(plugins: [plugin])

    get "/api/auth/private-probe"

    expect(last_response.status).to eq(403)
    expect(called).to be(false)
  end

  it "keeps core origin checks active for mutating mounted requests with cookies" do
    self.app = build_app

    post "/api/auth/sign-out", "{}", "CONTENT_TYPE" => "application/json", "HTTP_COOKIE" => "better-auth.session_token=stale-token"

    expect(last_response.status).to eq(403)
    expect(JSON.parse(last_response.body)).to eq("code" => "FORBIDDEN", "message" => "Missing or null Origin")
  end

  it "rejects malicious callback URLs through the Roda mount" do
    self.app = build_app(trusted_origins: ["http://example.org"])

    post(
      "/api/auth/sign-up/email",
      JSON.generate(email: "ada@example.com", password: "password123", name: "Ada", callbackURL: "https://evil.example/callback"),
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "http://example.org"
    )

    expect(last_response.status).to eq(403)
    expect(JSON.parse(last_response.body)).to eq("code" => "FORBIDDEN", "message" => "Invalid callbackURL")
  end

  it "converts unexpected mounted endpoint errors into Better Auth JSON errors" do
    plugin = BetterAuth::Plugin.new(
      id: "raising",
      endpoints: {
        boom: BetterAuth::Endpoint.new(path: "/boom", method: "GET") { raise "boom" }
      }
    )
    self.app = build_app(plugins: [plugin])

    get "/api/auth/boom"

    expect(last_response.status).to eq(500)
    expect(JSON.parse(last_response.body)).to eq("code" => "INTERNAL_SERVER_ERROR", "message" => "Internal Server Error")
  end

  it "honors on_api_error callbacks for unexpected mounted endpoint errors" do
    captured = []
    plugin = BetterAuth::Plugin.new(
      id: "callback-raising",
      endpoints: {
        boom: BetterAuth::Endpoint.new(path: "/boom", method: "GET") { raise "boom" }
      }
    )
    self.app = build_app(plugins: [plugin], on_api_error: {on_error: ->(error, ctx) { captured << [error.message, ctx.path] }})

    get "/api/auth/boom"

    expect(last_response.status).to eq(500)
    expect(captured).to eq([["boom", "/boom"]])
  end

  it "re-raises unexpected mounted endpoint errors when on_api_error throw is enabled" do
    plugin = BetterAuth::Plugin.new(
      id: "throwing",
      endpoints: {
        boom: BetterAuth::Endpoint.new(path: "/boom", method: "GET") { raise "boom" }
      }
    )
    self.app = build_app(plugins: [plugin], on_api_error: {throw: true})

    expect {
      get "/api/auth/boom"
    }.to raise_error(RuntimeError, "boom")
  end

  it "lets helpers resolve the current Better Auth user from real cookies" do
    self.app = build_app
    sign_up_email("ada@example.com")

    get "/dashboard", {}, "HTTP_COOKIE" => cookie_header(last_response["set-cookie"])

    expect(last_response.status).to eq(200)
    data = JSON.parse(last_response.body)
    expect(data.fetch("authenticated")).to eq(true)
    expect(data.fetch("user").fetch("email")).to eq("ada@example.com")
  end

  it "lets helpers resolve the current user from the bearer plugin" do
    self.app = build_app(plugins: [BetterAuth::Plugins.bearer])
    sign_up_email("ada@example.com")
    token_cookie = cookie_header(last_response["set-cookie"]).split("; ").find { |pair| pair.start_with?("better-auth.session_token=") }
    signed_token = token_cookie.split("=", 2).last

    clear_cookies
    get "/dashboard", {}, "HTTP_AUTHORIZATION" => "Bearer #{signed_token}"

    expect(last_response.status).to eq(200)
    data = JSON.parse(last_response.body)
    expect(data.fetch("authenticated")).to eq(true)
    expect(data.fetch("user").fetch("email")).to eq("ada@example.com")
  end

  it "applies Better Auth response cookies emitted during helper session lookup" do
    self.app = build_app
    sign_up_email("ada@example.com")
    original_cookie = cookie_header(last_response["set-cookie"])

    post "/api/auth/sign-out", "{}", {
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "http://example.org",
      "HTTP_COOKIE" => original_cookie
    }
    expect(last_response.status).to eq(200)

    clear_cookies
    get "/dashboard", {}, "HTTP_COOKIE" => original_cookie

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body).fetch("authenticated")).to eq(false)
    expect(last_response["set-cookie"]).to include("better-auth.session_token=")
    expect(last_response["set-cookie"].downcase).to include("max-age=0")
  end

  it "preserves app cookies when helper lookup appends Better Auth cookies" do
    self.app = build_app
    sign_up_email("ada@example.com")
    original_cookie = cookie_header(last_response["set-cookie"])

    post "/api/auth/sign-out", "{}", {
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "http://example.org",
      "HTTP_COOKIE" => original_cookie
    }
    expect(last_response.status).to eq(200)

    clear_cookies
    get "/cookie-dashboard", {}, "HTTP_COOKIE" => original_cookie

    expect(last_response.status).to eq(200)
    cookies = last_response["set-cookie"].lines
    expect(cookies.any? { |line| line.include?("app_cookie=1") }).to be(true)
    expect(cookies.any? { |line| line.include?("better-auth.session_token=") && line.downcase.include?("max-age=0") }).to be(true)
  end

  it "does not reuse a helper session across requests without cookies" do
    self.app = build_app
    sign_up_email("ada@example.com")

    get "/dashboard", {}, "HTTP_COOKIE" => cookie_header(last_response["set-cookie"])
    expect(JSON.parse(last_response.body).fetch("authenticated")).to eq(true)

    clear_cookies
    get "/dashboard"

    expect(last_response.status).to eq(200)
    data = JSON.parse(last_response.body)
    expect(data.fetch("authenticated")).to eq(false)
    expect(data.fetch("user")).to be_nil
  end

  it "halts protected Roda routes with 401 when no Better Auth user is present" do
    self.app = build_app

    get "/private"

    expect(last_response.status).to eq(401)
    expect(last_response.body).to eq("")
  end

  it "halts protected Roda routes with a JSON 401 when JSON is preferred" do
    self.app = build_app

    get "/private", {}, "HTTP_ACCEPT" => "application/vnd.api+json"

    expect(last_response.status).to eq(401)
    expect(last_response["content-type"]).to include("application/json")
    expect(JSON.parse(last_response.body)).to eq("code" => "UNAUTHORIZED", "message" => "Unauthorized")
  end

  it "halts protected Roda routes with plain 401 when HTML is preferred over JSON" do
    self.app = build_app

    get "/private", {}, "HTTP_ACCEPT" => "text/html, application/json;q=0.1"

    expect(last_response.status).to eq(401)
    expect(last_response.body).to eq("")
  end

  it "keeps the mount path as the core base path when overrides include base_path" do
    self.app = build_app(mount_path: "/auth", overrides: {base_path: "/api/auth"})

    get "/auth/ok"

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("ok" => true)
  end

  it "allows a subclassed Roda app to configure its own better_auth mount" do
    secret = "roda-secret-that-is-long-enough-for-validation"
    parent = Class.new(::Roda) do
      plugin :better_auth

      better_auth at: "/parent-auth" do |config|
        config.secret = secret
        config.base_url = "http://example.org"
        config.database = :memory
      end
    end

    self.app = Class.new(parent) do
      better_auth at: "/child-auth" do |config|
        config.secret = secret
        config.base_url = "http://example.org"
        config.database = :memory
      end

      route do |r|
        r.better_auth
      end
    end

    get "/child-auth/ok"

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("ok" => true)
  end

  it "supports the public Roda require path on its own" do
    ruby = <<~RUBY
      $LOAD_PATH.unshift("#{File.expand_path("../../../lib", __dir__)}")
      require "better_auth/roda"
      require "roda"

      Class.new(Roda) do
        plugin :better_auth
        better_auth auth: BetterAuth.auth(secret: "#{secret}", database: :memory)
      end
    RUBY

    output = IO.popen([RbConfig.ruby, "-e", ruby], err: [:child, :out], &:read)
    status = $?

    expect(status).to be_success, output
  end

  it "raises when better_auth mount path is root" do
    expect {
      Class.new(::Roda) do
        plugin :better_auth
        better_auth at: "/" do |config|
          config.secret = "roda-secret-that-is-long-enough-for-validation"
          config.base_url = "http://example.org"
          config.database = :memory
        end
      end
    }.to raise_error(ArgumentError, /better_auth mount path cannot be/)
  end

  it "raises when better_auth is configured twice on the same app class" do
    secret = "roda-secret-that-is-long-enough-for-validation"

    expect {
      Class.new(::Roda) do
        plugin :better_auth
        better_auth at: "/api/auth" do |config|
          config.secret = secret
          config.base_url = "http://example.org"
          config.database = :memory
        end
        better_auth at: "/auth2" do |config|
          config.secret = secret
          config.base_url = "http://example.org"
          config.database = :memory
        end
      end
    }.to raise_error(ArgumentError, /better_auth is already configured/)
  end

  def build_app(mount_path: "/api/auth", plugins: [], trusted_origins: nil, on_api_error: nil, overrides: {})
    secret = "roda-secret-that-is-long-enough-for-validation"

    Class.new(::Roda) do
      plugin :better_auth

      better_auth at: mount_path, **overrides do |config|
        config.secret = secret
        config.base_url = "http://example.org"
        config.database = :memory
        config.email_and_password = {enabled: true}
        config.plugins = plugins
        config.trusted_origins = trusted_origins if trusted_origins
        config.on_api_error = on_api_error if on_api_error
      end

      route do |r|
        r.better_auth

        r.get "dashboard" do
          response["content-type"] = "application/json"
          JSON.generate(authenticated: authenticated?, user: current_user)
        end

        r.get "cookie-dashboard" do
          response["set-cookie"] = "app_cookie=1; path=/"
          response["content-type"] = "application/json"
          JSON.generate(authenticated: authenticated?, user: current_user)
        end

        r.get "private" do
          require_authentication
          "private"
        end
      end
    end
  end

  def sign_up_email(email)
    post(
      "/api/auth/sign-up/email",
      JSON.generate(email: email, password: "password123", name: "Ada"),
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "http://example.org"
    )
    expect(last_response.status).to eq(200)
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end

  def secret
    "roda-secret-that-is-long-enough-for-validation"
  end
end

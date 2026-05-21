# frozen_string_literal: true

require_relative "../../spec_helper"

class SinatraRateLimitStorage
  attr_reader :data

  def initialize
    @data = {}
  end

  def get(key)
    data[key]
  end

  def set(key, value, ttl: nil, update: false)
    data[key] = value
  end

  def keys
    data.keys
  end
end

class SinatraSecondaryStorage
  attr_reader :data, :ttls

  def initialize
    @data = {}
    @ttls = {}
  end

  def get(key)
    data[key]
  end

  def set(key, value, ttl = nil)
    data[key] = value
    ttls[key] = ttl
  end
end

RSpec.describe "BetterAuth::Sinatra extension" do
  include Rack::Test::Methods

  attr_accessor :app

  after do
    BetterAuth::Sinatra.reset!
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

  it "dispatches auth when the Sinatra app is nested under a parent Rack mount" do
    self.app = build_app(mount_path: "/auth")

    get "/auth/ok", {}, {"SCRIPT_NAME" => "/api", "PATH_INFO" => "/auth/ok"}

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("ok" => true)
  end

  it "does not duplicate SCRIPT_NAME in Rack request path for shared auth mounts" do
    plugin = BetterAuth::Plugin.new(
      id: "sinatra-request-url",
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

  it "dispatches plugin endpoints through the Sinatra mount" do
    plugin = BetterAuth::Plugin.new(
      id: "sinatra-plugin",
      endpoints: {
        sinatra_probe: BetterAuth::Endpoint.new(path: "/sinatra-probe", method: "GET") do |ctx|
          ctx.set_cookie("sinatra_probe", "1", path: "/")
          {mounted: true, path: ctx.path, cookie: ctx.get_cookie("sinatra_input")}
        end
      }
    )
    self.app = build_app(plugins: [plugin])

    get "/api/auth/sinatra-probe", {}, "HTTP_COOKIE" => "sinatra_input=present"

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("mounted" => true, "path" => "/sinatra-probe", "cookie" => "present")
    expect(last_response["set-cookie"]).to include("sinatra_probe=1")
  end

  it "keeps core origin checks active for mutating mounted requests with cookies" do
    self.app = build_app

    post "/api/auth/sign-out", "{}", "CONTENT_TYPE" => "application/json", "HTTP_COOKIE" => "better-auth.session_token=stale-token"

    expect(last_response.status).to eq(403)
    expect(JSON.parse(last_response.body)).to eq("code" => "FORBIDDEN", "message" => "Missing or null Origin")
  end

  it "keeps mounted origin checks active for callback URLs and fetch metadata" do
    plugin = origin_probe_plugin
    self.app = build_app(plugins: [plugin])

    post "/api/auth/post", JSON.generate(callbackURL: "https://evil.example"), "CONTENT_TYPE" => "application/json"
    expect(last_response.status).to eq(403)

    post "/api/auth/post", "{}", {
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "https://evil.example",
      "HTTP_COOKIE" => "better-auth.session_token=stale-token"
    }
    expect(last_response.status).to eq(403)

    post "/api/auth/post", "{}", {
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "https://evil.example"
    }
    expect(last_response.status).to eq(403)

    post "/api/auth/post", "{}", {
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "https://evil.example",
      "HTTP_SEC_FETCH_SITE" => "cross-site",
      "HTTP_SEC_FETCH_MODE" => "navigate",
      "HTTP_SEC_FETCH_DEST" => "document"
    }
    expect(last_response.status).to eq(403)
    expect(JSON.parse(last_response.body).fetch("message")).to eq("Invalid origin")
  end

  it "rejects null or malformed mounted origins when cookies are present" do
    self.app = build_app(plugins: [origin_probe_plugin])

    post "/api/auth/post", "{}", {
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "null",
      "HTTP_COOKIE" => "better-auth.session_token=stale-token"
    }
    expect(last_response.status).to eq(403)

    post "/api/auth/post", "{}", {
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "malicious.com",
      "HTTP_COOKIE" => "better-auth.session_token=stale-token"
    }
    expect(last_response.status).to eq(403)
  end

  it "applies mounted rate limits with custom storage" do
    storage = SinatraRateLimitStorage.new
    self.app = build_app(plugins: [limited_plugin], overrides: {rate_limit: {enabled: true, window: 60, max: 1, custom_storage: storage}})

    get "/api/auth/limited?nonce=1"
    expect(last_response.status).to eq(200)

    get "/api/auth/limited?nonce=2"

    expect(last_response.status).to eq(429)
    expect(last_response["x-retry-after"]).to match(/\A\d+\z/)
    expect(JSON.parse(last_response.body)).to eq("message" => "Too many requests. Please try again later.")
    expect(storage.keys).to eq(["127.0.0.1|/limited"])
  end

  it "applies mounted rate limits against the logical path for shared auth mounts" do
    storage = SinatraRateLimitStorage.new
    self.app = build_app(plugins: [limited_plugin], overrides: {rate_limit: {enabled: true, window: 60, max: 1, custom_storage: storage}})

    get "/limited", {}, {"SCRIPT_NAME" => "/api/auth", "PATH_INFO" => "/limited"}
    expect(last_response.status).to eq(200)

    get "/limited", {}, {"SCRIPT_NAME" => "/api/auth", "PATH_INFO" => "/limited"}

    expect(last_response.status).to eq(429)
    expect(storage.keys).to eq(["127.0.0.1|/limited"])
  end

  it "applies mounted rate limits with secondary storage" do
    storage = SinatraSecondaryStorage.new
    self.app = build_app(
      plugins: [limited_plugin],
      overrides: {
        secondary_storage: storage,
        rate_limit: {enabled: true, window: 60, max: 1, storage: "secondary-storage"}
      }
    )

    get "/api/auth/limited"

    expect(last_response.status).to eq(200)
    stored = JSON.parse(storage.data.fetch("127.0.0.1|/limited"))
    expect(stored.keys.sort).to eq(["count", "key", "lastRequest"])
    expect(stored.fetch("key")).to eq("127.0.0.1|/limited")
    expect(stored.fetch("count")).to eq(1)
    expect(stored.fetch("lastRequest")).to be_a(Integer)
    expect(storage.ttls.fetch("127.0.0.1|/limited")).to eq(60)
  end

  it "applies mounted rate limits with database storage" do
    self.app = build_app(plugins: [limited_plugin], overrides: {rate_limit: {enabled: true, window: 60, max: 1, storage: "database"}})

    get "/api/auth/limited"

    expect(last_response.status).to eq(200)
    stored = app.settings.better_auth_auth.context.adapter.find_one(model: "rateLimit", where: [{field: "key", value: "127.0.0.1|/limited"}])
    expect(stored.fetch("count")).to eq(1)
    expect(stored.fetch("lastRequest")).to be_a(Integer)
  end

  it "lets Sinatra helpers resolve the current Better Auth user from real cookies" do
    self.app = build_app
    sign_up_email("ada@example.com")

    get "/dashboard", {}, "HTTP_COOKIE" => cookie_header(last_response["set-cookie"])

    expect(last_response.status).to eq(200)
    data = JSON.parse(last_response.body)
    expect(data.fetch("authenticated")).to eq(true)
    expect(data.fetch("user").fetch("email")).to eq("ada@example.com")
  end

  it "lets Sinatra helpers resolve the current user from the bearer plugin" do
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

  it "passes the original Rack request to helper session lookup hooks" do
    captured = []
    self.app = build_app(
      hooks: {
        before: lambda do |ctx|
          next unless ctx.path == "/get-session"

          captured << {
            request_class: ctx.request&.class&.name,
            method: ctx.method,
            script_name: ctx.request&.script_name,
            path_info: ctx.request&.path_info,
            path: ctx.request&.path
          }
          nil
        end
      }
    )
    sign_up_email("ada@example.com")

    get "/dashboard", {}, {
      "SCRIPT_NAME" => "",
      "PATH_INFO" => "/dashboard",
      "HTTP_COOKIE" => cookie_header(last_response["set-cookie"])
    }

    expect(last_response.status).to eq(200)
    expect(captured.last).to include(
      request_class: "Rack::Request",
      method: "GET",
      script_name: "",
      path_info: "/dashboard",
      path: "/dashboard"
    )
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

  it "raises Better Auth API errors from helper session lookup" do
    self.app = build_app(
      hooks: {
        before: lambda do |ctx|
          raise BetterAuth::APIError.new("INTERNAL_SERVER_ERROR", message: "session lookup failed") if ctx.path == "/get-session"
        end
      }
    )

    expect {
      get "/dashboard"
    }.to raise_error(BetterAuth::APIError, /session lookup failed/)
  end

  it "returns JSON from protected helpers for vendor JSON accept headers" do
    self.app = build_app

    get "/private", {}, "HTTP_ACCEPT" => "application/vnd.api+json"

    expect(last_response.status).to eq(401)
    expect(last_response["content-type"]).to include("application/json")
    expect(JSON.parse(last_response.body)).to eq("code" => "UNAUTHORIZED", "message" => "Unauthorized")
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

  it "halts protected Sinatra routes with 401 when no Better Auth user is present" do
    self.app = build_app

    get "/private"

    expect(last_response.status).to eq(401)
    expect(last_response.body).to eq("")
  end

  it "halts protected Sinatra routes with a JSON 401 when JSON is preferred" do
    self.app = build_app

    get "/private", {}, "HTTP_ACCEPT" => "application/json"

    expect(last_response.status).to eq(401)
    expect(last_response["content-type"]).to include("application/json")
    expect(JSON.parse(last_response.body)).to eq("code" => "UNAUTHORIZED", "message" => "Unauthorized")
  end

  it "keeps the mount path as the core base path when overrides include base_path" do
    self.app = build_app(mount_path: "/auth", overrides: {base_path: "/api/auth"})

    get "/auth/ok"

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("ok" => true)
  end

  it "raises when better_auth mount path is root" do
    expect {
      Class.new(Sinatra::Base) do
        register BetterAuth::Sinatra
        set :environment, :test
        better_auth at: "/" do |config|
          config.secret = "sinatra-secret-that-is-long-enough-for-validation"
          config.base_url = "http://example.org"
          config.database = :memory
        end
      end
    }.to raise_error(ArgumentError, /better_auth mount path cannot be/)
  end

  it "raises when better_auth is configured twice on the same app class" do
    secret = "sinatra-secret-that-is-long-enough-for-validation"

    expect {
      Class.new(Sinatra::Base) do
        register BetterAuth::Sinatra
        set :environment, :test
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

  def build_app(mount_path: "/api/auth", plugins: [], hooks: nil, overrides: {})
    secret = "sinatra-secret-that-is-long-enough-for-validation"

    Class.new(Sinatra::Base) do
      register BetterAuth::Sinatra

      set :environment, :test
      set :raise_errors, true
      set :show_exceptions, false

      better_auth at: mount_path, **overrides do |config|
        config.secret = secret
        config.base_url = "http://example.org"
        config.database = :memory
        config.email_and_password = {enabled: true}
        config.plugins = plugins
        config.hooks = hooks if hooks
      end

      get "/dashboard" do
        content_type :json
        JSON.generate(authenticated: authenticated?, user: current_user)
      end

      get "/cookie-dashboard" do
        response.set_cookie("app_cookie", value: "1", path: "/")
        content_type :json
        JSON.generate(authenticated: authenticated?, user: current_user)
      end

      get "/private" do
        require_authentication
        "private"
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

  def origin_probe_plugin
    BetterAuth::Plugin.new(
      id: "sinatra-origin-probe",
      endpoints: {
        post: BetterAuth::Endpoint.new(path: "/post", method: "POST") { {ok: true} }
      }
    )
  end

  def limited_plugin
    BetterAuth::Plugin.new(
      id: "sinatra-rate-limit",
      endpoints: {
        limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
      }
    )
  end
end

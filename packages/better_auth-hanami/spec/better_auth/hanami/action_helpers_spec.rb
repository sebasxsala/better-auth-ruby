# frozen_string_literal: true

require_relative "../../spec_helper"

class BetterAuthHanamiAction
  include BetterAuth::Hanami::ActionHelpers
end

RSpec.describe BetterAuth::Hanami::ActionHelpers do
  let(:action) { BetterAuthHanamiAction.new }

  after do
    BetterAuth::Hanami.instance_variable_set(:@auth, nil)
    BetterAuth::Hanami.instance_variable_set(:@configuration, nil)
  end

  it "exposes the current session and user from the Rack request env" do
    request = fake_request({"better_auth.session" => {session: {"id" => "session-1"}, user: {"id" => "user-1"}}})

    expect(action.current_session(request)).to eq({"id" => "session-1"})
    expect(action.current_user(request)).to eq({"id" => "user-1"})
    expect(action.authenticated?(request)).to be(true)
  end

  it "resolves and caches session data from Better Auth cookies" do
    BetterAuth::Hanami.configure do |config|
      config.secret = secret
      config.database = :memory
      config.base_url = "http://localhost:2300"
      config.email_and_password = {enabled: true}
    end
    signup_headers = sign_up_headers
    request = fake_request({}, cookie: cookie_header(signup_headers.fetch("set-cookie")))

    expect(action.current_user(request)).to include("email" => "ada@example.com")
    expect(request.env["better_auth.session"]).to include(:session, :user)
  end

  it "prepares auth context for the request before resolving session" do
    BetterAuth::Hanami.configure do |config|
      config.secret = secret
      config.database = :memory
      config.base_url = "http://localhost:2300"
      config.email_and_password = {enabled: true}
    end

    auth = BetterAuth::Hanami.auth
    signup_headers = sign_up_headers
    prepared = false
    allow(auth.context).to receive(:prepare_for_request!).and_wrap_original do |method, req|
      prepared = true
      method.call(req)
    end

    request = fake_request({}, cookie: cookie_header(signup_headers.fetch("set-cookie")))
    action.current_user(request)

    expect(prepared).to be(true)
  end

  it "halts with unauthorized status when authentication is required and missing" do
    request = fake_request({"better_auth.session" => nil})
    response = Struct.new(:status).new

    expect(action.require_authentication(request, response)).to be(false)
    expect(response.status).to eq(401)
  end

  it "resolves sessions from bearer authorization headers" do
    BetterAuth::Hanami.configure do |config|
      config.secret = secret
      config.database = :memory
      config.base_url = "http://localhost:2300"
      config.email_and_password = {enabled: true}
      config.plugins = [BetterAuth::Plugins.bearer]
    end
    signup_status, _headers, signup_body = BetterAuth::Hanami.auth.call(
      rack_env("POST", "/api/auth/sign-up/email", body: JSON.generate(email: "bearer@example.com", password: "password123", name: "Bearer"))
    )
    token = JSON.parse(signup_body.join).fetch("token")

    request = fake_request({}, authorization: "Bearer #{token}")

    expect(signup_status).to eq(200)
    expect(action.current_user(request)).to include("email" => "bearer@example.com")
  end

  it "passes the Hanami request object through auth hooks while resolving helper sessions" do
    observed_request = nil
    BetterAuth::Hanami.configure do |config|
      config.secret = secret
      config.database = :memory
      config.base_url = "http://localhost:2300"
      config.email_and_password = {enabled: true}
      config.hooks = {
        before: ->(ctx) {
          observed_request = ctx.request if ctx.path == "/get-session"
          nil
        }
      }
    end
    signup_headers = sign_up_headers
    request = fake_request({}, cookie: cookie_header(signup_headers.fetch("set-cookie")))

    action.current_user(request)

    expect(observed_request).to equal(request)
  end

  it "resolves helper sessions on protected POST actions with the internal get-session endpoint as GET" do
    BetterAuth::Hanami.configure do |config|
      config.secret = secret
      config.database = :memory
      config.base_url = "http://localhost:2300"
      config.email_and_password = {enabled: true}
    end
    signup_headers = sign_up_headers
    request = fake_request({}, cookie: cookie_header(signup_headers.fetch("set-cookie")), method: "POST")

    expect(action.current_user(request)).to include("email" => "ada@example.com")
  end

  it "copies stale session cleanup cookies to the response when authentication is required" do
    BetterAuth::Hanami.configure do |config|
      config.secret = secret
      config.database = :memory
      config.base_url = "http://localhost:2300"
      config.email_and_password = {enabled: true}
    end
    signup_headers = sign_up_headers
    cookie = cookie_header(signup_headers.fetch("set-cookie"))
    BetterAuth::Hanami.auth.context.internal_adapter.delete_session(JSON.parse(signup_headers.fetch("set-auth-token", "null"))["token"]) if signup_headers.key?("set-auth-token")
    token = BetterAuth::Cookies.parse_cookies(cookie).fetch("better-auth.session_token").split(".").first
    BetterAuth::Hanami.auth.context.internal_adapter.delete_session(token)
    request = fake_request({}, cookie: cookie)
    response = fake_response

    expect(action.require_authentication(request, response)).to be(false)
    expect(response.headers.fetch("set-cookie")).to include("better-auth.session_token=")
    expect(response.headers.fetch("set-cookie")).to include("Max-Age=0")
  end

  it "appends session cleanup cookies without replacing existing response cookies" do
    request = fake_request(
      {
        "better_auth.session" => nil,
        "better_auth.session_headers" => {"set-cookie" => "better-auth.session_token=; Max-Age=0"}
      }
    )
    response = fake_response
    response.headers["set-cookie"] = "app=1; Path=/"

    expect(action.require_authentication(request, response)).to be(false)
    expect(response.headers.fetch("set-cookie")).to eq("app=1; Path=/\nbetter-auth.session_token=; Max-Age=0")
  end

  def sign_up_headers
    status, headers, = BetterAuth::Hanami.auth.call(
      rack_env("POST", "/api/auth/sign-up/email", body: JSON.generate(email: "ada@example.com", password: "password123", name: "Ada"))
    )
    expect(status).to eq(200)
    headers
  end

  def fake_request(env, cookie: nil, authorization: nil, method: "GET")
    Struct.new(:env, :path, :request_method, :params, :headers) do
      def get_header(name)
        return headers["cookie"] if name == "HTTP_COOKIE"
        return headers["authorization"] if name == "HTTP_AUTHORIZATION"

        nil
      end
    end.new(env, "/dashboard", method, {}, {"cookie" => cookie, "authorization" => authorization}.compact)
  end

  def fake_response
    Struct.new(:status, :headers) do
      def initialize
        super(nil, {})
      end
    end.new
  end

  def rack_env(method, path, body:, content_type: "application/json", extra_headers: {})
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "2300",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(body),
      "CONTENT_TYPE" => content_type,
      "CONTENT_LENGTH" => body.bytesize.to_s,
      "HTTP_ORIGIN" => "http://localhost:2300"
    }.merge(extra_headers)
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end

  def secret
    "test-secret-that-is-long-enough-for-validation"
  end
end

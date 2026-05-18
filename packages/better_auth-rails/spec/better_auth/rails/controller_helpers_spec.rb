# frozen_string_literal: true

require_relative "../../spec_helper"

class BetterAuthRailsHelperController
  include BetterAuth::Rails::ControllerHelpers

  attr_reader :request, :response, :head_status

  def initialize(request, response: nil)
    @request = request
    @response = response
  end

  def head(status)
    @head_status = status
  end
end

class BetterAuthRailsFakeResponse
  attr_reader :headers

  def initialize
    @headers = {}
  end
end

RSpec.describe BetterAuth::Rails::ControllerHelpers do
  after do
    BetterAuth::Rails.instance_variable_set(:@auth, nil)
    BetterAuth::Rails.instance_variable_set(:@configuration, nil)
  end

  it "exposes the current Better Auth session and user from the Rack request" do
    request = instance_double("Request", env: {
      "better_auth.session" => {
        session: {"id" => "session-1"},
        user: {"id" => "user-1", "email" => "ada@example.com"}
      }
    })
    controller = BetterAuthRailsHelperController.new(request)

    expect(controller.current_session).to eq({"id" => "session-1"})
    expect(controller.current_user).to eq({"id" => "user-1", "email" => "ada@example.com"})
    expect(controller.authenticated?).to be(true)
  end

  it "resolves the session from Better Auth cookies when request env is empty" do
    request = instance_double(
      "Request",
      env: {},
      path: "/posts",
      request_method: "GET",
      query_parameters: {},
      get_header: "better-auth.session_token=signed-token"
    )
    controller = BetterAuthRailsHelperController.new(request)
    session = {
      session: {"id" => "session-1"},
      user: {"id" => "user-1"}
    }

    BetterAuth::Rails.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
    end
    allow(BetterAuth::Session).to receive(:find_current).and_return(session)

    expect(controller.current_user).to eq({"id" => "user-1"})
    expect(request.env["better_auth.session"]).to eq(session)
  end

  it "uses the auth instance registered by the Rails mount when resolving real cookies" do
    BetterAuth::Rails.configure do |config|
      config.secret = "global-secret-that-is-long-enough-for-tests"
      config.database = :memory
      config.base_url = "http://localhost:3000"
    end
    custom_auth = BetterAuth.auth(
      secret: "custom-secret-that-is-long-enough-for-tests",
      database: :memory,
      base_url: "http://localhost:3000"
    )
    BetterAuth::Rails.register_auth(custom_auth, mount_path: "/api/auth")
    user = custom_auth.context.internal_adapter.create_user(name: "Ada", email: "ada@example.com")
    session = custom_auth.context.internal_adapter.create_session(user["id"], false, {"token" => "custom-token"}, true)
    request = instance_double(
      "Request",
      env: {},
      path: "/posts",
      request_method: "GET",
      query_parameters: {},
      get_header: "#{custom_auth.context.auth_cookies[:session_token].name}=#{signed_cookie("custom-token", custom_auth.options.secret)}"
    )
    controller = BetterAuthRailsHelperController.new(request)

    expect(controller.current_user).to include("id" => user.fetch("id"), "email" => "ada@example.com")
    expect(controller.current_session).to include("token" => session.fetch("token"))
  end

  it "forwards stale session cookie cleanup headers to the Rails response" do
    BetterAuth::Rails.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
      config.base_url = "http://localhost:3000"
    end
    auth = BetterAuth::Rails.auth
    cookie_name = auth.context.auth_cookies[:session_token].name
    request = instance_double(
      "Request",
      env: {},
      path: "/posts",
      request_method: "GET",
      query_parameters: {},
      get_header: "#{cookie_name}=#{signed_cookie("missing-token", auth.options.secret)}"
    )
    response = BetterAuthRailsFakeResponse.new
    controller = BetterAuthRailsHelperController.new(request, response: response)

    expect(controller.current_user).to be_nil
    expect(response.headers.fetch("Set-Cookie")).to include("#{cookie_name}=;")
    expect(response.headers.fetch("Set-Cookie")).to include("Max-Age=0")
  end

  it "prepares the auth context before resolving a session from cookies" do
    request = instance_double(
      "Request",
      env: {},
      path: "/posts",
      request_method: "GET",
      query_parameters: {},
      get_header: "better-auth.session_token=signed-token"
    )
    controller = BetterAuthRailsHelperController.new(request)

    BetterAuth::Rails.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
    end
    context = BetterAuth::Rails.auth.context
    allow(BetterAuth::Session).to receive(:find_current).and_return({user: {"id" => "user-1"}})

    expect(context).to receive(:prepare_for_request!).with(request).and_call_original

    expect(controller.current_user).to eq({"id" => "user-1"})
  end

  it "clears request runtime session state between sequential prepares" do
    BetterAuth::Rails.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
    end

    context = BetterAuth::Rails.auth.context
    request_a = instance_double("Request", get_header: nil, scheme: "https", host: "app.example.com", host_with_port: "app.example.com", port: 443)
    request_b = instance_double("Request", get_header: nil, scheme: "https", host: "api.example.com", host_with_port: "api.example.com", port: 443)

    context.prepare_for_request!(request_a)
    context.set_current_session({id: "session-a"})
    context.prepare_for_request!(request_b)

    expect(context.current_session).to be_nil
  end

  it "clears Better Auth runtime state after helper session lookup" do
    request = instance_double(
      "Request",
      env: {},
      path: "/posts",
      request_method: "GET",
      query_parameters: {},
      get_header: nil
    )
    controller = BetterAuthRailsHelperController.new(request)

    BetterAuth::Rails.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
      config.base_url = "http://localhost:3000"
    end
    context = BetterAuth::Rails.auth.context

    controller.current_user

    expect(context.send(:request_runtime?)).to be(false)
  end

  it "allows route protection when a current user is present" do
    request = instance_double("Request", env: {"better_auth.session" => {user: {"id" => "user-1"}}})
    controller = BetterAuthRailsHelperController.new(request)

    expect(controller.require_authentication).to be(true)
    expect(controller.head_status).to be_nil
  end

  it "halts with unauthorized route protection when no current user is present" do
    request = instance_double("Request", env: {"better_auth.session" => nil})
    controller = BetterAuthRailsHelperController.new(request)

    expect(controller.require_authentication).to be(false)
    expect(controller.head_status).to eq(:unauthorized)
  end

  def signed_cookie(value, secret)
    signature = BetterAuth::Crypto.hmac_signature(value, secret, encoding: :base64url)
    "#{value}.#{signature}"
  end
end

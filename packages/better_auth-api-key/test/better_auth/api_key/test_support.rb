# frozen_string_literal: true

require "json"
require "rack/mock_request"
require "stringio"
require_relative "../../test_helper"

module APIKeyTestSupport
  SECRET = "phase-nine-api-key-secret-with-enough-entropy"

  def build_api_key_auth(options = {})
    advanced = options.is_a?(Hash) ? options.delete(:advanced) : nil
    secondary_storage = options.is_a?(Hash) ? options.delete(:secondary_storage) : nil
    session = options.is_a?(Hash) ? options.delete(:session) : nil
    BetterAuth.auth({
      secret: SECRET,
      email_and_password: {enabled: true},
      advanced: advanced,
      secondary_storage: secondary_storage,
      session: session,
      plugins: [BetterAuth::Plugins.api_key(options)]
    }.compact)
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "API Key"},
      as_response: true
    )
    headers.fetch("set-cookie").to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def rack_json_response(auth, method, path, body: nil, cookie: nil)
    payload = body ? JSON.generate(body) : ""
    env = {
      "CONTENT_TYPE" => "application/json",
      "CONTENT_LENGTH" => payload.bytesize.to_s,
      "HTTP_ORIGIN" => "http://localhost:3000",
      :input => payload
    }
    env["HTTP_COOKIE"] = cookie if cookie
    response = Rack::MockRequest.new(auth).request(method, "/api/auth#{path}", env)
    [response.status, JSON.parse(response.body)]
  end

  def request_mode_api_response(auth, endpoint, body:, cookie: nil)
    request = Rack::Request.new({
      "REQUEST_METHOD" => "POST",
      "PATH_INFO" => "/api/auth",
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(""),
      "HTTP_COOKIE" => cookie
    }.compact)
    status, _headers, response_body = auth.api.public_send(endpoint, request: request, body: body)
    [status, JSON.parse(response_body.join)]
  end

  class MemoryStorage
    attr_reader :values, :ttls, :get_calls, :set_calls, :delete_calls

    def initialize
      @values = {}
      @ttls = {}
      @get_calls = []
      @set_calls = []
      @delete_calls = []
    end

    def get(key)
      get_calls << key
      values[key]
    end

    def set(key, value, ttl = nil)
      set_calls << [key, value, ttl]
      values[key] = value
      ttls[key] = ttl if ttl
    end

    def delete(key)
      delete_calls << key
      values.delete(key)
      ttls.delete(key)
    end
  end
end

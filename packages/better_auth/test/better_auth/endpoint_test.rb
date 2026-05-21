# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthEndpointTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_endpoint_collects_status_headers_and_cookies
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/json", method: "GET") do |ctx|
      ctx.set_status(201)
      ctx.set_header("x-test", "yes")
      ctx.set_cookie("session", "value")

      {ok: true}
    end

    result = endpoint.call(context_for(auth, endpoint))

    assert_equal 201, result.status
    assert_equal({ok: true}, result.response)
    assert_equal "yes", result.headers["x-test"]
    assert_includes result.headers["set-cookie"], "session=value"
  end

  def test_endpoint_splits_multiple_set_cookie_values_for_rack
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/cookies", method: "GET") do |ctx|
      ctx.set_cookie("session", "value")
      ctx.set_cookie("method", "email")

      {ok: true}
    end

    result = endpoint.call(context_for(auth, endpoint))
    _status, headers, _body = result.to_rack_response

    assert_equal ["session=value", "method=email"], headers["set-cookie"].map { |line| line.split(";").first }
  end

  def test_set_cookie_header_behaves_like_string_for_direct_response_assertions
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/cookies", method: "GET") do |ctx|
      ctx.set_cookie("session", "value")
      ctx.set_cookie("method", "email")

      {ok: true}
    end

    result = endpoint.call(context_for(auth, endpoint))
    header = result.to_response.headers.fetch("set-cookie")

    assert_match(/session=value/, header)
    assert_equal "session=value", header.split("\n").first.split(";").first
    assert_equal header.to_s, header.to_str
  end

  def test_signed_cookie_round_trips_json_with_cookie_separators
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    payload = JSON.generate({"prompt" => "login", "returnTo" => "/dashboard?x=1;y=2"})
    setter = BetterAuth::Endpoint.new(path: "/cookie", method: "GET") do |ctx|
      ctx.set_signed_cookie("oidc_login_prompt", payload, SECRET)
      {ok: true}
    end

    set_result = setter.call(context_for(auth, setter))
    cookie = set_result.to_response.headers.fetch("set-cookie").split(";").first
    reader = BetterAuth::Endpoint.new(path: "/read", method: "GET") do |ctx|
      ctx.get_signed_cookie("oidc_login_prompt", SECRET)
    end

    read_result = reader.call(context_for(auth, reader, headers: {"cookie" => cookie}))

    assert_equal payload, read_result.response
  end

  def test_endpoint_preserves_raw_rack_responses
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/raw", method: "GET") do
      [202, {"content-type" => "text/plain"}, ["accepted"]]
    end

    result = endpoint.call(context_for(auth, endpoint))

    assert result.raw_response?
    assert_equal [202, {"content-type" => "text/plain"}, ["accepted"]], result.to_rack_response
  end

  def test_endpoint_raises_api_errors_with_status_and_headers
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/error", method: "GET") do |ctx|
      raise ctx.error("BAD_REQUEST", message: "Nope", headers: {"x-error" => "yes"})
    end

    error = assert_raises(BetterAuth::APIError) { endpoint.call(context_for(auth, endpoint)) }

    assert_equal "BAD_REQUEST", error.status
    assert_equal 400, error.status_code
    assert_equal "Nope", error.message
    assert_equal "yes", error.headers["x-error"]
  end

  def test_endpoint_rejects_header_values_with_newlines
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/header", method: "GET") do |ctx|
      ctx.set_header("x-test", "safe\r\nset-cookie: injected=true")
      {ok: true}
    end

    error = assert_raises(BetterAuth::APIError) { endpoint.call(context_for(auth, endpoint)) }

    assert_equal "INTERNAL_SERVER_ERROR", error.status
    assert_equal "Invalid header value", error.message
  end

  def test_endpoint_applies_schema_parsers_before_handler
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    schema = Class.new do
      def parse(value)
        raise ArgumentError, "name is required" unless value["name"]

        value.merge("parsed" => true)
      end
    end.new
    endpoint = BetterAuth::Endpoint.new(path: "/profile", method: "POST", body_schema: schema) do |ctx|
      ctx.body
    end

    result = endpoint.call(context_for(auth, endpoint, body: {"name" => "Ada"}))

    assert_equal({"name" => "Ada", "parsed" => true}, result.response)
  end

  def test_endpoint_applies_all_schema_parsers_before_handler
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    parser = Class.new do
      def initialize(label)
        @label = label
      end

      def parse(value)
        value.merge("#{@label}_parsed" => true)
      end
    end
    endpoint = BetterAuth::Endpoint.new(
      path: "/profiles/:id",
      method: "POST",
      body_schema: parser.new("body"),
      query_schema: parser.new("query"),
      params_schema: parser.new("params"),
      headers_schema: parser.new("headers")
    ) do |ctx|
      {
        body: ctx.body,
        query: ctx.query,
        params: ctx.params,
        headers: ctx.headers.slice("x-name", "headers-parsed")
      }
    end

    result = endpoint.call(
      context_for(
        auth,
        endpoint,
        body: {"name" => "Ada"},
        query: {"page" => "1"},
        params: {"id" => "user-1"},
        headers: {"x_name" => "Ada"}
      )
    )

    assert_equal({"name" => "Ada", "body_parsed" => true}, result.response[:body])
    assert_equal({"page" => "1", "query_parsed" => true}, result.response[:query])
    assert_equal({"id" => "user-1", "params_parsed" => true}, result.response[:params])
    assert_equal({"x-name" => "Ada", "headers-parsed" => true}, result.response[:headers])
  end

  def test_endpoint_schema_errors_become_bad_request_api_errors
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/profile", method: "POST", body_schema: ->(_value) { false }) do
      {ok: true}
    end

    error = assert_raises(BetterAuth::APIError) { endpoint.call(context_for(auth, endpoint, body: {})) }

    assert_equal "BAD_REQUEST", error.status
    assert_equal "Validation Error", error.message
  end

  def test_endpoint_derives_body_schema_from_open_api_required_fields
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(
      path: "/profile",
      method: "POST",
      metadata: {
        openapi: {
          requestBody: BetterAuth::OpenAPI.json_request_body(
            BetterAuth::OpenAPI.object_schema(
              {name: {type: "string"}, image: {type: "string"}},
              required: ["name"]
            )
          )
        }
      }
    ) do |ctx|
      ctx.body
    end

    error = assert_raises(BetterAuth::APIError) { endpoint.call(context_for(auth, endpoint, body: {})) }
    assert_equal "BAD_REQUEST", error.status
    assert_equal "Validation Error", error.message

    result = endpoint.call(context_for(auth, endpoint, body: {name: "Ada"}))
    assert_equal({name: "Ada"}, result.response)
  end

  def test_endpoint_derives_query_schema_from_open_api_required_parameters
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(
      path: "/profile/:id",
      method: "GET",
      metadata: {
        openapi: {
          parameters: [
            {name: "id", in: "path", required: true, schema: {type: "string"}},
            {name: "token", in: "query", required: true, schema: {type: "string"}},
            {name: "optional", in: "query", required: false, schema: {type: "string"}}
          ]
        }
      }
    ) do |ctx|
      {params: ctx.params, query: ctx.query}
    end

    missing_query = assert_raises(BetterAuth::APIError) do
      endpoint.call(context_for(auth, endpoint, params: {id: "user-1"}, query: {}))
    end
    assert_equal "Validation Error", missing_query.message

    result = endpoint.call(context_for(auth, endpoint, params: {id: "user-1"}, query: {token: "reset-token"}))
    assert_equal({id: "user-1"}, result.response[:params])
    assert_equal({token: "reset-token"}, result.response[:query])
  end

  def test_base_endpoints_with_open_api_body_or_query_required_fields_validate_at_runtime
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET, email_and_password: {enabled: true})
    checked = []

    BetterAuth::Core.base_endpoints.each do |name, endpoint|
      body_required = open_api_request_body_required_fields(endpoint)
      if body_required.any?
        checked << [name, :body]
        assert endpoint.body_schema, "#{name} should have a runtime body schema"

        error = assert_raises(BetterAuth::APIError) do
          endpoint.call(context_for(auth, endpoint, body: {}, query: required_query_values(endpoint)))
        end
        assert_equal "Validation Error", error.message, "#{name} should reject missing required body fields"
      end

      if open_api_required_parameter_names(endpoint, "query").any?
        checked << [name, :query]
        assert endpoint.query_schema, "#{name} should have a runtime query schema"

        error = assert_raises(BetterAuth::APIError) do
          endpoint.call(context_for(auth, endpoint, body: required_body_values(endpoint), query: {}))
        end
        assert_equal "Validation Error", error.message, "#{name} should reject missing required query fields"
      end
    end

    refute_empty checked
  end

  private

  def open_api_request_body_required_fields(endpoint)
    schema = dig_keys(endpoint.metadata, :openapi, :requestBody, :content, "application/json", :schema)
    Array(fetch_key(schema, :required))
  end

  def open_api_required_parameter_names(endpoint, location)
    Array(dig_keys(endpoint.metadata, :openapi, :parameters))
      .select { |parameter| fetch_key(parameter, :in).to_s == location && fetch_key(parameter, :required) == true }
      .filter_map { |parameter| fetch_key(parameter, :name) }
  end

  def required_body_values(endpoint)
    open_api_request_body_required_fields(endpoint).to_h { |field| [field, "value"] }
  end

  def required_query_values(endpoint)
    open_api_required_parameter_names(endpoint, "query").to_h { |field| [field, "value"] }
  end

  def dig_keys(hash, *keys)
    keys.reduce(hash) { |value, key| fetch_key(value, key) }
  end

  def fetch_key(hash, key)
    return nil unless hash.respond_to?(:[])

    hash[key] || hash[key.to_s]
  end

  def context_for(auth, endpoint, body: {}, query: {}, params: {}, headers: {})
    BetterAuth::Endpoint::Context.new(
      path: endpoint.path,
      method: "GET",
      query: query,
      body: body,
      params: params,
      headers: headers,
      context: auth.context
    )
  end
end

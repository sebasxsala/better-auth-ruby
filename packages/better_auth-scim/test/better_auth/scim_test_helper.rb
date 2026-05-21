# frozen_string_literal: true

require "base64"
require "json"
require "rack/mock"
require "tempfile"
require_relative "../test_helper"

module SCIMTestHelper
  SECRET = "phase-twelve-secret-with-enough-entropy-123"
  PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

  def build_auth(options = nil, plugins: nil, **kwargs)
    options = (options || {}).merge(kwargs)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: plugins || [BetterAuth::Plugins.scim(options)]
    )
  end

  def sign_up_cookie(auth, email = "owner@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def bearer(token)
    {"authorization" => "Bearer " + token}
  end

  def rack_bearer(token)
    {"HTTP_AUTHORIZATION" => "Bearer " + token}
  end

  def rack_json_request(auth, method, path, body: nil, headers: {})
    env = {"REMOTE_ADDR" => "127.0.0.1"}.merge(headers)
    if body
      env["CONTENT_TYPE"] = "application/json"
      env[:input] = JSON.generate(body)
    end
    Rack::MockRequest.new(auth).request(method, path, env)
  end

  def rack_json(response)
    JSON.parse(response.body)
  end

  def build_scim_auth_with_database(database, plugins: [BetterAuth::Plugins.scim], **options)
    BetterAuth.auth(
      {
        base_url: "http://localhost:3000",
        secret: SECRET,
        database: database,
        email_and_password: {enabled: true},
        session: {cookie_cache: {enabled: false}},
        plugins: plugins
      }.merge(options)
    )
  end

  def scim_schema_config(plugins: [BetterAuth::Plugins.scim], **options)
    BetterAuth::Configuration.new(
      {
        secret: SECRET,
        database: :memory,
        email_and_password: {enabled: true},
        plugins: plugins
      }.merge(options)
    )
  end

  def run_scim_adapter_smoke(auth, provider_id:)
    cookie = sign_up_cookie(auth, "#{provider_id}-owner@example.com")
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: provider_id}).fetch(:scimToken)

    created = auth.api.create_scim_user(
      headers: bearer(token),
      body: {
        userName: "#{provider_id}-user@example.com",
        name: {givenName: "SCIM", familyName: "User"}
      }
    )
    assert_equal "#{provider_id}-user@example.com", created.fetch(:userName)

    provider = auth.context.adapter.find_one(model: "scimProvider", where: [{field: "providerId", value: provider_id}])
    refute_nil provider
    refute_equal token, provider.fetch("scimToken")

    account = auth.context.adapter.find_one(
      model: "account",
      where: [
        {field: "providerId", value: provider_id},
        {field: "userId", value: created.fetch(:id)}
      ]
    )
    refute_nil account

    listed = auth.api.list_scim_users(headers: bearer(token))
    assert_equal 1, listed.fetch(:totalResults)
    assert_equal [created.fetch(:id)], listed.fetch(:Resources).map { |resource| resource.fetch(:id) }

    fetched = auth.api.get_scim_user(headers: bearer(token), params: {userId: created.fetch(:id)})
    assert_equal created.fetch(:id), fetched.fetch(:id)

    patch_status, = auth.api.patch_scim_user(
      headers: bearer(token),
      params: {userId: created.fetch(:id)},
      body: {
        schemas: [PATCH_SCHEMA],
        Operations: [{op: "replace", path: "name.formatted", value: "Patched SCIM User"}]
      },
      as_response: true
    )
    assert_equal 204, patch_status

    updated = auth.api.update_scim_user(
      headers: bearer(token),
      params: {userId: created.fetch(:id)},
      body: {
        userName: "#{provider_id}-updated@example.com",
        externalId: "#{provider_id}-external",
        name: {formatted: "Updated SCIM User"}
      }
    )
    assert_equal "#{provider_id}-updated@example.com", updated.fetch(:userName)
    assert_equal "#{provider_id}-external", updated.fetch(:externalId)

    delete_status, = auth.api.delete_scim_user(headers: bearer(token), params: {userId: created.fetch(:id)}, as_response: true)
    assert_equal 204, delete_status
    assert_equal 0, auth.api.list_scim_users(headers: bearer(token)).fetch(:totalResults)
    assert_nil auth.context.adapter.find_one(model: "account", where: [{field: "userId", value: created.fetch(:id)}, {field: "providerId", value: provider_id}])
  end

  def token_without_organization(token)
    token_parts = Base64.urlsafe_decode64(token).split(":")
    Base64.urlsafe_encode64(token_parts[0, 2].join(":"), padding: false)
  end

  class RateLimitStorage
    attr_reader :data

    def initialize
      @data = {}
    end

    def get(key)
      data[key]
    end

    def set(key, value, ttl: nil, update: false)
      data[key] = value.merge(ttl: ttl, update: update)
    end

    def keys
      data.keys
    end
  end

  class SecondaryStorage
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
end

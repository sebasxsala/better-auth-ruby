# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class OAuthProviderRateLimitTest < Minitest::Test
  include OAuthProviderFlowHelpers

  CustomRateLimitStore = Struct.new(:store, :ttls) do
    def initialize
      super({}, {})
    end

    def get(key)
      store[key]
    end

    def set(key, value, ttl: nil, update: false)
      store[key] = value
      ttls[key] = ttl
    end
  end

  SecondaryRateLimitStore = Struct.new(:store, :ttls) do
    def initialize
      super({}, {})
    end

    def get(key)
      store[key]
    end

    def set(key, value, ttl = nil)
      store[key] = value
      ttls[key] = ttl
    end
  end

  def test_token_endpoint_rate_limit_is_enforced
    auth = build_rate_limited_auth({token: {window: 60, max: 3}})
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        scope: "read"
      }
    )

    statuses = 5.times.map do
      token_request_status(auth, client)
    end

    assert_equal [200, 200, 200, 429, 429], statuses
  end

  def test_token_endpoint_rate_limit_uses_custom_storage
    store = CustomRateLimitStore.new
    auth = build_rate_limited_auth({token: {window: 60, max: 2}}, rate_limit: {enabled: true, custom_storage: store})
    client = machine_client(auth)

    statuses = 4.times.map { token_request_status(auth, client) }

    assert_equal [200, 200, 429, 429], statuses
    key = "203.0.113.10|/oauth2/token"
    assert_equal 2, store.store.fetch(key).fetch(:count)
    assert_equal 60, store.ttls.fetch(key)
  end

  def test_token_endpoint_rate_limit_uses_secondary_storage
    storage = SecondaryRateLimitStore.new
    auth = build_rate_limited_auth(
      {token: {window: 60, max: 2}},
      secondary_storage: storage,
      session: {store_session_in_database: true},
      rate_limit: {enabled: true, storage: "secondary-storage"}
    )
    client = machine_client(auth)

    statuses = 4.times.map { token_request_status(auth, client) }

    assert_equal [200, 200, 429, 429], statuses
    key = "203.0.113.10|/oauth2/token"
    stored = JSON.parse(storage.store.fetch(key))
    assert_equal 2, stored.fetch("count")
    assert_equal 60, storage.ttls.fetch(key)
  end

  def test_token_endpoint_rate_limit_uses_database_storage
    auth = build_rate_limited_auth({token: {window: 60, max: 2}}, rate_limit: {enabled: true, storage: "database"})
    client = machine_client(auth)

    statuses = 4.times.map { token_request_status(auth, client) }

    assert_equal [200, 200, 429, 429], statuses
    stored = auth.context.adapter.find_one(model: "rateLimit", where: [{field: "key", value: "203.0.113.10|/oauth2/token"}])
    assert_equal 2, stored.fetch("count")
  end

  def test_disabled_token_endpoint_rate_limit_is_not_enforced
    auth = build_rate_limited_auth({token: false})
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        scope: "read"
      }
    )

    statuses = 10.times.map do
      token_request_status(auth, client)
    end

    assert_equal [200] * 10, statuses
  end

  def test_provider_rate_limits_include_continue_consent_and_end_session
    rules = BetterAuth::Plugins.oauth_provider(rate_limit: {}).rate_limit
    paths = ["/oauth2/continue", "/oauth2/consent", "/oauth2/end-session"]

    paths.each do |path|
      assert rules.any? { |rule| rule[:path_matcher].call(path) }, "expected rate limit for #{path}"
    end
  end

  private

  def machine_client(auth)
    auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        scope: "read"
      }
    )
  end

  def build_rate_limited_auth(oauth_rate_limit, rate_limit: {enabled: true}, secondary_storage: nil, session: nil)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: OAuthProviderFlowHelpers::SECRET,
      database: :memory,
      secondary_storage: secondary_storage,
      session: session,
      rate_limit: rate_limit,
      plugins: [
        BetterAuth::Plugins.oauth_provider(
          scopes: ["read"],
          allow_dynamic_client_registration: true,
          rate_limit: oauth_rate_limit
        )
      ]
    )
  end

  def token_request_status(auth, client)
    status, = auth.handler.call(
      rack_env(
        "POST",
        "/api/auth/oauth2/token",
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret]
        },
        headers: {"REMOTE_ADDR" => "203.0.113.10"}
      )
    )
    status
  end
end

# frozen_string_literal: true

require_relative "../scim_test_helper"

class BetterAuthPluginsScimRateLimitTest < Minitest::Test
  include SCIMTestHelper

  def test_scim_metadata_routes_are_limited_with_memory_storage
    auth = build_scim_auth_with_database(:memory, rate_limit: {enabled: true, window: 60, max: 1})

    first = rack_json_request(auth, "GET", "/api/auth/scim/v2/ServiceProviderConfig")
    second = rack_json_request(auth, "GET", "/api/auth/scim/v2/ServiceProviderConfig")

    assert_equal 200, first.status
    assert_equal 429, second.status
    assert_equal "Too many requests. Please try again later.", rack_json(second).fetch("message")
  end

  def test_scim_routes_use_normalized_path_keys_with_custom_rate_limit_storage
    storage = RateLimitStorage.new
    auth = build_scim_auth_with_database(:memory, rate_limit: {enabled: true, window: 60, max: 1, custom_storage: storage})

    assert_equal 200, rack_json_request(auth, "GET", "/api/auth/scim/v2/ServiceProviderConfig?ignored=1").status
    response = rack_json_request(auth, "GET", "/api/auth/scim/v2/ServiceProviderConfig?ignored=2")

    assert_equal 429, response.status
    assert_equal ["127.0.0.1|/scim/v2/ServiceProviderConfig"], storage.keys
  end

  def test_scim_routes_can_use_secondary_storage_rate_limits
    storage = SecondaryStorage.new
    auth = build_scim_auth_with_database(
      :memory,
      secondary_storage: storage,
      rate_limit: {enabled: true, window: 60, max: 1, storage: "secondary-storage"}
    )

    assert_equal 200, rack_json_request(auth, "GET", "/api/auth/scim/v2/ServiceProviderConfig").status
    stored = JSON.parse(storage.data.fetch("127.0.0.1|/scim/v2/ServiceProviderConfig"))
    response = rack_json_request(auth, "GET", "/api/auth/scim/v2/ServiceProviderConfig")

    assert_equal ["count", "key", "lastRequest"], stored.keys.sort
    assert_equal 60, storage.ttls.fetch("127.0.0.1|/scim/v2/ServiceProviderConfig")
    assert_equal 429, response.status
  end

  def test_scim_routes_can_use_database_rate_limits_with_scim_schema
    auth = build_scim_auth_with_database(
      :memory,
      rate_limit: {enabled: true, window: 60, max: 1, storage: "database"}
    )

    assert_equal 200, rack_json_request(auth, "GET", "/api/auth/scim/v2/ServiceProviderConfig").status
    stored = auth.context.adapter.find_one(model: "rateLimit", where: [{field: "key", value: "127.0.0.1|/scim/v2/ServiceProviderConfig"}])
    response = rack_json_request(auth, "GET", "/api/auth/scim/v2/ServiceProviderConfig")

    assert_equal 1, stored.fetch("count")
    assert_kind_of Integer, stored.fetch("lastRequest")
    assert_equal 429, response.status
  end

  def test_authenticated_scim_user_routes_are_limited_after_bearer_auth
    auth = build_scim_auth_with_database(:memory, rate_limit: {enabled: true, window: 60, max: 1})
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "limited-provider"}).fetch(:scimToken)

    first = rack_json_request(
      auth,
      "POST",
      "/api/auth/scim/v2/Users",
      body: {userName: "limited-user@example.com"},
      headers: rack_bearer(token)
    )
    second = rack_json_request(
      auth,
      "POST",
      "/api/auth/scim/v2/Users",
      body: {userName: "limited-user-2@example.com"},
      headers: rack_bearer(token)
    )

    assert_equal 201, first.status
    assert_equal 429, second.status
  end
end

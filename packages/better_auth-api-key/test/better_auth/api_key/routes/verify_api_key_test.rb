# frozen_string_literal: true

require_relative "../test_support"

class BetterAuthAPIKeyVerifyRouteTest < Minitest::Test
  include APIKeyTestSupport

  def test_verify_route_returns_upstream_invalid_payload
    auth = build_api_key_auth(default_key_length: 12)

    result = auth.api.verify_api_key(body: {key: "missing-key"})

    assert_equal false, result[:valid]
    assert_equal "INVALID_API_KEY", result[:error][:code]
    assert_nil result[:key]
  end

  def test_verify_route_requires_key_in_body_and_ignores_headers
    auth = build_api_key_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "verify-route-header-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    result = auth.api.verify_api_key(headers: {"x-api-key" => created[:key]}, body: {})

    assert_equal false, result[:valid]
    assert_equal "INVALID_API_KEY", result[:error][:code]
    assert_nil result[:key]
  end

  def test_verify_route_includes_rate_limit_retry_details
    auth = build_api_key_auth(default_key_length: 12, rate_limit: {enabled: true, time_window: 60_000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "verify-route-rate-limit-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    assert_equal true, auth.api.verify_api_key(body: {key: created[:key]})[:valid]
    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal false, result[:valid]
    assert_equal "RATE_LIMITED", result[:error][:code]
    assert_operator result[:error][:details][:tryAgainIn], :>, 0
  end

  def test_verify_route_checks_permissions_and_returns_public_key_shape
    auth = build_api_key_auth(default_key_length: 12, enable_metadata: true, rate_limit: {enabled: false})
    cookie = sign_up_cookie(auth, email: "verify-route-permissions-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(
      body: {userId: user_id, metadata: {scope: "read"}, permissions: {files: ["read", "write"]}}
    )

    valid = auth.api.verify_api_key(body: {key: created[:key], permissions: {files: ["read"]}})
    invalid = auth.api.verify_api_key(body: {key: created[:key], permissions: {files: ["admin"]}})

    assert_equal true, valid[:valid]
    refute valid[:key].key?(:key)
    assert_equal({"scope" => "read"}, valid[:key][:metadata])
    assert_equal({"files" => ["read", "write"]}, valid[:key][:permissions])
    assert_equal false, invalid[:valid]
    assert_equal "KEY_NOT_FOUND", invalid[:error][:code]
  end

  def test_verify_route_accepts_non_default_config_key_without_config_id
    auth = build_api_key_auth([
      {config_id: "default", default_prefix: "def_", default_key_length: 12, rate_limit: {enabled: false}},
      {config_id: "service", default_prefix: "svc_", default_key_length: 12, rate_limit: {enabled: false}}
    ])
    cookie = sign_up_cookie(auth, email: "verify-route-multi-config-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, configId: "service", name: "service-key"})

    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal true, result[:valid]
    assert_equal "service", result[:key][:configId]
    assert_equal "service-key", result[:key][:name]
    refute result[:key].key?(:key)
  end

  def test_verify_route_rejects_explicit_wrong_config_id
    auth = build_api_key_auth([
      {config_id: "default", default_prefix: "def_", default_key_length: 12, rate_limit: {enabled: false}},
      {config_id: "service", default_prefix: "svc_", default_key_length: 12, rate_limit: {enabled: false}}
    ])
    cookie = sign_up_cookie(auth, email: "verify-route-wrong-config-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, configId: "service"})

    result = auth.api.verify_api_key(body: {key: created[:key], configId: "default"})

    assert_equal false, result[:valid]
    assert_equal "INVALID_API_KEY", result[:error][:code]
    assert_nil result[:key]
  end

  def test_verify_route_uses_matched_config_validator_when_config_id_is_omitted
    auth = build_api_key_auth([
      {config_id: "default", default_prefix: "def_", default_key_length: 12, rate_limit: {enabled: false}, custom_api_key_validator: ->(*) { false }},
      {config_id: "service", default_prefix: "svc_", default_key_length: 12, rate_limit: {enabled: false}, custom_api_key_validator: ->(*) { true }}
    ])
    cookie = sign_up_cookie(auth, email: "verify-route-validator-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, configId: "service"})

    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal true, result[:valid]
    assert_equal "service", result[:key][:configId]
  end

  def test_verify_route_rejects_matched_config_validator_failure_when_config_id_is_omitted
    auth = build_api_key_auth([
      {config_id: "default", default_prefix: "def_", default_key_length: 12, rate_limit: {enabled: false}, custom_api_key_validator: ->(*) { true }},
      {config_id: "service", default_prefix: "svc_", default_key_length: 12, rate_limit: {enabled: false}, custom_api_key_validator: ->(*) { false }}
    ])
    cookie = sign_up_cookie(auth, email: "verify-route-validator-failure-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, configId: "service"})

    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal false, result[:valid]
    assert_equal "KEY_NOT_FOUND", result[:error][:code]
  end
end

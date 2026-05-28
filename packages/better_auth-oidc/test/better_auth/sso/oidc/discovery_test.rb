# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthSSOOIDCDiscoveryTest < Minitest::Test
  Discovery = BetterAuth::SSO::OIDC::Discovery
  DiscoveryError = BetterAuth::SSO::OIDC::DiscoveryError

  def test_compute_discovery_url_from_issuer_without_trailing_slash
    assert_equal "https://idp.example.com/.well-known/openid-configuration", Discovery.compute_discovery_url("https://idp.example.com")
  end

  def test_compute_discovery_url_from_issuer_with_trailing_slash
    assert_equal "https://idp.example.com/.well-known/openid-configuration", Discovery.compute_discovery_url("https://idp.example.com/")
  end

  def test_compute_discovery_url_handles_issuer_with_path
    assert_equal "https://idp.example.com/tenant/v1/.well-known/openid-configuration", Discovery.compute_discovery_url("https://idp.example.com/tenant/v1")
  end

  def test_compute_discovery_url_handles_issuer_with_path_and_trailing_slash
    assert_equal "https://idp.example.com/tenant/v1/.well-known/openid-configuration", Discovery.compute_discovery_url("https://idp.example.com/tenant/v1/")
  end

  def test_validate_discovery_url_accepts_valid_https_url
    assert Discovery.validate_discovery_url("https://idp.example.com/.well-known/openid-configuration", trusted)
  end

  def test_validate_discovery_url_accepts_valid_http_url
    assert Discovery.validate_discovery_url("http://localhost:8080/.well-known/openid-configuration", trusted)
  end

  def test_validate_discovery_url_rejects_invalid_url
    error = assert_raises(DiscoveryError) { Discovery.validate_discovery_url("not-a-url", trusted) }

    assert_equal "discovery_invalid_url", error.code
    assert_equal({url: "not-a-url"}, error.details)
    assert_match(/must be valid/, error.message)
  end

  def test_validate_discovery_url_rejects_non_http_protocols
    error = assert_raises(DiscoveryError) { Discovery.validate_discovery_url("ftp://example.com/config", trusted) }

    assert_equal "discovery_invalid_url", error.code
    assert_equal "ftp:", error.details.fetch(:protocol)
    assert_match(/http or https/, error.message)
  end

  def test_validate_discovery_url_rejects_untrusted_origin
    error = assert_raises(DiscoveryError) do
      Discovery.validate_discovery_url("https://untrusted.com/.well-known/openid-configuration", ->(_url) { false })
    end

    assert_equal "discovery_untrusted_origin", error.code
    assert_match(/is not trusted/, error.message)
  end

  def test_validate_discovery_document_accepts_valid_document
    assert Discovery.validate_discovery_document(discovery_document, "https://idp.example.com")
  end

  def test_validate_discovery_document_accepts_only_required_fields
    doc = {
      issuer: "https://idp.example.com",
      authorization_endpoint: "https://idp.example.com/authorize",
      token_endpoint: "https://idp.example.com/token",
      jwks_uri: "https://idp.example.com/jwks"
    }

    assert Discovery.validate_discovery_document(doc, "https://idp.example.com")
  end

  def test_validate_discovery_document_reports_missing_issuer
    error = assert_raises(DiscoveryError) do
      Discovery.validate_discovery_document(discovery_document(issuer: ""), "https://idp.example.com")
    end

    assert_equal "discovery_incomplete", error.code
    assert_includes error.details.fetch(:missingFields), "issuer"
  end

  def test_validate_discovery_document_reports_missing_authorization_endpoint
    error = assert_raises(DiscoveryError) do
      Discovery.validate_discovery_document(discovery_document(authorization_endpoint: ""), "https://idp.example.com")
    end

    assert_equal "discovery_incomplete", error.code
    assert_includes error.details.fetch(:missingFields), "authorization_endpoint"
  end

  def test_validate_discovery_document_reports_missing_token_endpoint
    error = assert_raises(DiscoveryError) do
      Discovery.validate_discovery_document(discovery_document(token_endpoint: ""), "https://idp.example.com")
    end

    assert_equal "discovery_incomplete", error.code
    assert_includes error.details.fetch(:missingFields), "token_endpoint"
  end

  def test_validate_discovery_document_reports_missing_jwks_uri
    error = assert_raises(DiscoveryError) do
      Discovery.validate_discovery_document(discovery_document(jwks_uri: ""), "https://idp.example.com")
    end

    assert_equal "discovery_incomplete", error.code
    assert_includes error.details.fetch(:missingFields), "jwks_uri"
  end

  def test_validate_discovery_document_lists_all_missing_fields
    error = assert_raises(DiscoveryError) do
      Discovery.validate_discovery_document(
        {issuer: "", authorization_endpoint: "", token_endpoint: "", jwks_uri: ""},
        "https://idp.example.com"
      )
    end

    assert_equal "discovery_incomplete", error.code
    assert_equal %w[issuer authorization_endpoint token_endpoint jwks_uri], error.details.fetch(:missingFields)
  end

  def test_validate_discovery_document_rejects_issuer_mismatch
    error = assert_raises(DiscoveryError) do
      Discovery.validate_discovery_document(discovery_document(issuer: "https://evil.example.com"), "https://idp.example.com")
    end

    assert_equal "issuer_mismatch", error.code
    assert_equal "https://evil.example.com", error.details.fetch(:discovered)
    assert_equal "https://idp.example.com", error.details.fetch(:configured)
  end

  def test_validate_discovery_document_normalizes_trailing_slash_in_discovered_issuer
    assert Discovery.validate_discovery_document(discovery_document(issuer: "https://idp.example.com/"), "https://idp.example.com")
  end

  def test_validate_discovery_document_normalizes_trailing_slash_in_configured_issuer
    assert Discovery.validate_discovery_document(discovery_document(issuer: "https://idp.example.com"), "https://idp.example.com/")
  end

  def test_select_token_endpoint_auth_method_returns_existing_config_value
    assert_equal "client_secret_post", Discovery.select_token_endpoint_auth_method(discovery_document, "client_secret_post")
  end

  def test_select_token_endpoint_auth_method_prefers_basic_when_both_supported
    assert_equal "client_secret_basic", Discovery.select_token_endpoint_auth_method(
      discovery_document(token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"])
    )
  end

  def test_select_token_endpoint_auth_method_uses_post_if_only_post_supported
    assert_equal "client_secret_post", Discovery.select_token_endpoint_auth_method(
      discovery_document(token_endpoint_auth_methods_supported: ["client_secret_post"])
    )
  end

  def test_select_token_endpoint_auth_method_defaults_to_basic_for_unsupported_methods
    assert_equal "client_secret_basic", Discovery.select_token_endpoint_auth_method(
      discovery_document(token_endpoint_auth_methods_supported: ["private_key_jwt"])
    )
  end

  def test_select_token_endpoint_auth_method_defaults_to_basic_for_tls_client_auth_only
    assert_equal "client_secret_basic", Discovery.select_token_endpoint_auth_method(
      discovery_document(token_endpoint_auth_methods_supported: ["tls_client_auth", "private_key_jwt"])
    )
  end

  def test_select_token_endpoint_auth_method_defaults_to_basic_if_not_specified
    assert_equal "client_secret_basic", Discovery.select_token_endpoint_auth_method(discovery_document(token_endpoint_auth_methods_supported: nil))
  end

  def test_select_token_endpoint_auth_method_defaults_to_basic_for_empty_array
    assert_equal "client_secret_basic", Discovery.select_token_endpoint_auth_method(discovery_document(token_endpoint_auth_methods_supported: []))
  end

  def test_normalize_discovery_urls_returns_document_unchanged_if_urls_are_absolute
    doc = discovery_document

    assert_equal doc, Discovery.normalize_discovery_urls(doc, "https://idp.example.com", trusted)
  end

  def test_normalize_discovery_urls_resolves_required_urls_relative_to_issuer
    result = Discovery.normalize_discovery_urls(
      discovery_document(
        authorization_endpoint: "/oauth2/authorize",
        token_endpoint: "/oauth2/token",
        jwks_uri: "/.well-known/jwks.json"
      ),
      "https://idp.example.com",
      trusted
    )

    assert_equal "https://idp.example.com/oauth2/authorize", result.fetch(:authorization_endpoint)
    assert_equal "https://idp.example.com/oauth2/token", result.fetch(:token_endpoint)
    assert_equal "https://idp.example.com/.well-known/jwks.json", result.fetch(:jwks_uri)
  end

  def test_normalize_discovery_urls_resolves_optional_urls_relative_to_issuer
    result = Discovery.normalize_discovery_urls(
      discovery_document(
        userinfo_endpoint: "/userinfo",
        revocation_endpoint: "/revoke",
        end_session_endpoint: "/endsession",
        introspection_endpoint: "/introspection"
      ),
      "https://idp.example.com",
      trusted
    )

    assert_equal "https://idp.example.com/userinfo", result.fetch(:userinfo_endpoint)
    assert_equal "https://idp.example.com/revoke", result.fetch(:revocation_endpoint)
    assert_equal "https://idp.example.com/endsession", result.fetch(:end_session_endpoint)
    assert_equal "https://idp.example.com/introspection", result.fetch(:introspection_endpoint)
  end

  def test_normalize_discovery_urls_rejects_invalid_issuer
    error = assert_raises(DiscoveryError) do
      Discovery.normalize_discovery_urls(discovery_document(authorization_endpoint: "/oauth2/authorize"), "not-url", trusted)
    end

    assert_equal "discovery_invalid_url", error.code
    assert_match(/authorization_endpoint.*valid|url.*valid/, error.message)
  end

  def test_normalize_discovery_urls_rejects_untrusted_discovered_url
    error = assert_raises(DiscoveryError) do
      Discovery.normalize_discovery_urls(
        discovery_document(token_endpoint: "/oauth2/token"),
        "https://idp.example.com",
        ->(url) { !url.end_with?("/oauth2/token") }
      )
    end

    assert_equal "discovery_untrusted_origin", error.code
    assert_equal({endpoint: "token_endpoint", url: "https://idp.example.com/oauth2/token"}, error.details)
  end

  def test_normalize_url_returns_absolute_endpoint_unchanged
    endpoint = "https://idp.example.com/oauth2/token"

    assert_equal endpoint, Discovery.normalize_url("url", endpoint, "https://idp.example.com")
  end

  def test_normalize_url_returns_relative_endpoint_as_absolute_url
    assert_equal "https://idp.example.com/oauth2/token", Discovery.normalize_url("url", "/oauth2/token", "https://idp.example.com")
  end

  def test_normalize_url_preserves_issuer_base_path_for_leading_slash_endpoint
    assert_equal "https://idp.example.com/base/oauth2/token", Discovery.normalize_url("url", "/oauth2/token", "https://idp.example.com/base")
  end

  def test_normalize_url_preserves_issuer_base_path_for_endpoint_without_leading_slash
    assert_equal "https://idp.example.com/base/oauth2/token", Discovery.normalize_url("url", "oauth2/token", "https://idp.example.com/base")
  end

  def test_normalize_url_preserves_issuer_base_path_with_trailing_slash
    assert_equal "https://idp.example.com/base/oauth2/token", Discovery.normalize_url("url", "/oauth2/token", "https://idp.example.com/base/")
  end

  def test_normalize_url_handles_multiple_slashes
    assert_equal "https://idp.example.com/base/oauth2/token", Discovery.normalize_url("url", "//oauth2/token", "https://idp.example.com/base//")
  end

  def test_normalize_url_rejects_invalid_endpoint_urls
    error = assert_raises(DiscoveryError) { Discovery.normalize_url("url", "oauth2/token", "not-a-url") }

    assert_equal "discovery_invalid_url", error.code
    assert_match(/must be valid/, error.message)
  end

  def test_normalize_url_rejects_urls_with_unsupported_protocols
    error = assert_raises(DiscoveryError) { Discovery.normalize_url("url", "not-a-url", "ftp://idp.example.com") }

    assert_equal "discovery_invalid_url", error.code
    assert_match(/http or https/, error.message)
  end

  def test_needs_runtime_discovery_returns_true_for_nil_config
    assert Discovery.needs_runtime_discovery?(nil)
  end

  def test_needs_runtime_discovery_returns_true_for_empty_config
    assert Discovery.needs_runtime_discovery?({})
  end

  def test_needs_runtime_discovery_returns_true_if_token_endpoint_missing
    assert Discovery.needs_runtime_discovery?(jwksEndpoint: "https://idp.example.com/.well-known/jwks.json")
  end

  def test_needs_runtime_discovery_returns_true_if_jwks_endpoint_missing
    assert Discovery.needs_runtime_discovery?(tokenEndpoint: "https://idp.example.com/oauth2/token")
  end

  def test_needs_runtime_discovery_returns_false_if_required_runtime_urls_are_present
    refute Discovery.needs_runtime_discovery?(
      tokenEndpoint: "https://idp.example.com/oauth2/token",
      jwksEndpoint: "https://idp.example.com/.well-known/jwks.json",
      authorizationEndpoint: "https://idp.example.com/oauth2/authorize"
    )
  end

  def test_needs_runtime_discovery_returns_true_if_authorization_endpoint_missing
    assert Discovery.needs_runtime_discovery?(
      tokenEndpoint: "https://idp.example.com/oauth2/token",
      jwksEndpoint: "https://idp.example.com/.well-known/jwks.json"
    )
  end

  def test_fetch_discovery_document_fetches_and_parses_valid_document
    calls = []
    expected = discovery_document
    result = Discovery.fetch_discovery_document(
      "https://idp.example.com/.well-known/openid-configuration",
      fetch: ->(url, **_options) {
        calls << url
        {data: expected, error: nil}
      }
    )

    assert_equal expected.fetch(:issuer), result.fetch(:issuer)
    assert_equal expected.fetch(:authorization_endpoint), result.fetch(:authorization_endpoint)
    assert_equal expected.fetch(:token_endpoint), result.fetch(:token_endpoint)
    assert_equal expected.fetch(:jwks_uri), result.fetch(:jwks_uri)
    assert_equal ["https://idp.example.com/.well-known/openid-configuration"], calls
  end

  def test_fetch_discovery_document_raises_not_found_for_404_response
    error = assert_raises(DiscoveryError) do
      Discovery.fetch_discovery_document("https://idp.example.com/config", fetch: ->(_url, **_options) { {data: nil, error: {status: 404, message: "Not Found"}} })
    end

    assert_equal "discovery_not_found", error.code
  end

  def test_fetch_discovery_document_raises_timeout_for_abort_error
    abort_error = Class.new(StandardError)
    abort_error.define_singleton_method(:name) { "AbortError" }
    error = assert_raises(DiscoveryError) do
      Discovery.fetch_discovery_document("https://idp.example.com/config", timeout: 100, fetch: ->(_url, **_options) { raise abort_error, "The operation was aborted" })
    end

    assert_equal "discovery_timeout", error.code
  end

  def test_fetch_discovery_document_raises_timeout_for_http_408_response
    error = assert_raises(DiscoveryError) do
      Discovery.fetch_discovery_document("https://idp.example.com/config", fetch: ->(_url, **_options) { {data: nil, error: {status: 408, message: "Request Timeout"}} })
    end

    assert_equal "discovery_timeout", error.code
  end

  def test_fetch_discovery_document_raises_unexpected_error_for_server_errors
    error = assert_raises(DiscoveryError) do
      Discovery.fetch_discovery_document("https://idp.example.com/config", fetch: ->(_url, **_options) { {data: nil, error: {status: 500, message: "Internal Server Error"}} })
    end

    assert_equal "discovery_unexpected_error", error.code
  end

  def test_fetch_discovery_document_raises_invalid_json_for_empty_response
    error = assert_raises(DiscoveryError) do
      Discovery.fetch_discovery_document("https://idp.example.com/config", fetch: ->(_url, **_options) { {data: nil, error: nil} })
    end

    assert_equal "discovery_invalid_json", error.code
  end

  def test_fetch_discovery_document_raises_invalid_json_for_non_json_body
    error = assert_raises(DiscoveryError) do
      Discovery.fetch_discovery_document("https://idp.example.com/config", fetch: ->(_url, **_options) { {data: "<!DOCTYPE html><html>Not JSON</html>", error: nil} })
    end

    assert_equal "discovery_invalid_json", error.code
    assert_equal "<!DOCTYPE html><html>Not JSON</html>", error.details.fetch(:bodyPreview)
  end

  def test_fetch_discovery_document_raises_unexpected_error_for_unknown_errors
    error = assert_raises(DiscoveryError) do
      Discovery.fetch_discovery_document("https://idp.example.com/config", fetch: ->(_url, **_options) { raise "Network failure" })
    end

    assert_equal "discovery_unexpected_error", error.code
  end

  def test_discover_oidc_config_returns_hydrated_config_from_valid_discovery
    issuer = "https://idp.example.com"
    result = Discovery.discover_oidc_config(issuer: issuer, trusted_origin: trusted, fetch: fetch_with(discovery_document(issuer: issuer)))

    assert_equal issuer, result.fetch(:issuer)
    assert_equal "#{issuer}/oauth2/authorize", result.fetch(:authorization_endpoint)
    assert_equal "#{issuer}/oauth2/token", result.fetch(:token_endpoint)
    assert_equal "#{issuer}/.well-known/jwks.json", result.fetch(:jwks_endpoint)
    assert_equal "#{issuer}/userinfo", result.fetch(:user_info_endpoint)
    assert_equal "#{issuer}/.well-known/openid-configuration", result.fetch(:discovery_endpoint)
    assert_equal "client_secret_basic", result.fetch(:token_endpoint_authentication)
  end

  def test_discover_oidc_config_merges_existing_config_with_precedence
    issuer = "https://idp.example.com"
    result = Discovery.discover_oidc_config(
      issuer: issuer,
      existing_config: {
        tokenEndpoint: "https://custom.example.com/token",
        tokenEndpointAuthentication: "client_secret_post"
      },
      trusted_origin: trusted,
      fetch: fetch_with(discovery_document(issuer: issuer))
    )

    assert_equal "https://custom.example.com/token", result.fetch(:token_endpoint)
    assert_equal "client_secret_post", result.fetch(:token_endpoint_authentication)
    assert_equal "#{issuer}/oauth2/authorize", result.fetch(:authorization_endpoint)
    assert_equal "#{issuer}/.well-known/jwks.json", result.fetch(:jwks_endpoint)
  end

  def test_discover_oidc_config_uses_custom_discovery_endpoint
    issuer = "https://idp.example.com"
    custom_endpoint = "#{issuer}/custom/.well-known/openid-configuration"
    calls = []
    result = Discovery.discover_oidc_config(
      issuer: issuer,
      discovery_endpoint: custom_endpoint,
      trusted_origin: trusted,
      fetch: ->(url, **_options) {
        calls << url
        {data: discovery_document(issuer: issuer), error: nil}
      }
    )

    assert_equal custom_endpoint, result.fetch(:discovery_endpoint)
    assert_equal [custom_endpoint], calls
  end

  def test_discover_oidc_config_uses_discovery_endpoint_from_existing_config
    issuer = "https://idp.example.com"
    existing_endpoint = "#{issuer}/tenant/.well-known/openid-configuration"
    calls = []
    result = Discovery.discover_oidc_config(
      issuer: issuer,
      existing_config: {discoveryEndpoint: existing_endpoint},
      trusted_origin: trusted,
      fetch: ->(url, **_options) {
        calls << url
        {data: discovery_document(issuer: issuer), error: nil}
      }
    )

    assert_equal existing_endpoint, result.fetch(:discovery_endpoint)
    assert_equal [existing_endpoint], calls
  end

  def test_discover_oidc_config_raises_on_issuer_mismatch
    error = assert_raises(DiscoveryError) do
      Discovery.discover_oidc_config(
        issuer: "https://idp.example.com",
        trusted_origin: trusted,
        fetch: fetch_with(discovery_document(issuer: "https://evil.example.com"))
      )
    end

    assert_equal "issuer_mismatch", error.code
  end

  def test_discover_oidc_config_raises_on_missing_required_fields
    error = assert_raises(DiscoveryError) do
      Discovery.discover_oidc_config(
        issuer: "https://idp.example.com",
        trusted_origin: trusted,
        fetch: fetch_with({issuer: "https://idp.example.com", authorization_endpoint: "https://idp.example.com/authorize"})
      )
    end

    assert_equal "discovery_incomplete", error.code
  end

  def test_discover_oidc_config_raises_not_found_when_endpoint_does_not_exist
    error = assert_raises(DiscoveryError) do
      Discovery.discover_oidc_config(
        issuer: "https://idp.example.com",
        trusted_origin: trusted,
        fetch: ->(_url, **_options) { {data: nil, error: {status: 404, message: "Not Found"}} }
      )
    end

    assert_equal "discovery_not_found", error.code
  end

  def test_discover_oidc_config_includes_scopes_supported
    issuer = "https://idp.example.com"
    scopes = ["openid", "profile", "email", "offline_access", "custom"]
    result = Discovery.discover_oidc_config(
      issuer: issuer,
      trusted_origin: trusted,
      fetch: fetch_with(discovery_document(issuer: issuer, scopes_supported: scopes))
    )

    assert_equal scopes, result.fetch(:scopes_supported)
  end

  def test_discover_oidc_config_handles_document_without_optional_fields
    issuer = "https://idp.example.com"
    result = Discovery.discover_oidc_config(
      issuer: issuer,
      trusted_origin: trusted,
      fetch: fetch_with({
        issuer: issuer,
        authorization_endpoint: "#{issuer}/authorize",
        token_endpoint: "#{issuer}/token",
        jwks_uri: "#{issuer}/jwks"
      })
    )

    assert_equal issuer, result.fetch(:issuer)
    assert_equal "#{issuer}/authorize", result.fetch(:authorization_endpoint)
    assert_equal "#{issuer}/token", result.fetch(:token_endpoint)
    assert_equal "#{issuer}/jwks", result.fetch(:jwks_endpoint)
    refute result.key?(:user_info_endpoint)
    refute result.key?(:scopes_supported)
    assert_equal "client_secret_basic", result.fetch(:token_endpoint_authentication)
  end

  def test_discover_oidc_config_preserves_existing_fields
    issuer = "https://idp.example.com"
    result = Discovery.discover_oidc_config(
      issuer: issuer,
      existing_config: {
        issuer: issuer,
        discoveryEndpoint: "https://custom.example.com/.well-known/openid-configuration",
        authorizationEndpoint: "https://custom.example.com/auth",
        tokenEndpoint: "https://custom.example.com/token",
        jwksEndpoint: "https://custom.example.com/jwks",
        userInfoEndpoint: "https://custom.example.com/userinfo",
        tokenEndpointAuthentication: "client_secret_post",
        scopesSupported: ["openid", "profile"]
      },
      trusted_origin: trusted,
      fetch: fetch_with(discovery_document(issuer: issuer))
    )

    assert_equal "https://custom.example.com/auth", result.fetch(:authorization_endpoint)
    assert_equal "https://custom.example.com/token", result.fetch(:token_endpoint)
    assert_equal "https://custom.example.com/jwks", result.fetch(:jwks_endpoint)
    assert_equal "https://custom.example.com/userinfo", result.fetch(:user_info_endpoint)
    assert_equal "client_secret_post", result.fetch(:token_endpoint_authentication)
    assert_equal ["openid", "profile"], result.fetch(:scopes_supported)
  end

  def test_discover_oidc_config_defaults_auth_method_for_unsupported_methods
    issuer = "https://idp.example.com"
    result = Discovery.discover_oidc_config(
      issuer: issuer,
      trusted_origin: trusted,
      fetch: fetch_with(discovery_document(issuer: issuer, token_endpoint_auth_methods_supported: ["private_key_jwt"]))
    )

    assert_equal "client_secret_basic", result.fetch(:token_endpoint_authentication)
  end

  def test_discover_oidc_config_fills_missing_fields_from_discovery
    issuer = "https://idp.example.com"
    result = Discovery.discover_oidc_config(
      issuer: issuer,
      existing_config: {jwksEndpoint: "https://custom.example.com/jwks"},
      trusted_origin: trusted,
      fetch: fetch_with(discovery_document(issuer: issuer))
    )

    assert_equal "https://custom.example.com/jwks", result.fetch(:jwks_endpoint)
    assert_equal "#{issuer}/oauth2/authorize", result.fetch(:authorization_endpoint)
    assert_equal "#{issuer}/oauth2/token", result.fetch(:token_endpoint)
    assert_equal "#{issuer}/userinfo", result.fetch(:user_info_endpoint)
  end

  def test_discover_oidc_config_ignores_unknown_fields_and_missing_optional_fields
    issuer = "https://idp.example.com"
    result = Discovery.discover_oidc_config(
      issuer: issuer,
      trusted_origin: trusted,
      fetch: fetch_with({
        issuer: issuer,
        authorization_endpoint: "#{issuer}/authorize",
        token_endpoint: "#{issuer}/token",
        jwks_uri: "#{issuer}/jwks",
        "x-vendor-feature": true,
        custom_logout_endpoint: "#{issuer}/logout"
      })
    )

    assert_equal "#{issuer}/authorize", result.fetch(:authorization_endpoint)
    assert_equal "#{issuer}/token", result.fetch(:token_endpoint)
    assert_equal "#{issuer}/jwks", result.fetch(:jwks_endpoint)
    refute result.key?(:user_info_endpoint)
  end

  def test_discover_oidc_config_rejects_untrusted_main_discovery_url
    error = assert_raises(DiscoveryError) do
      Discovery.discover_oidc_config(issuer: "https://idp.example.com", trusted_origin: ->(_url) { false }, fetch: fetch_with(discovery_document))
    end

    assert_equal "discovery_untrusted_origin", error.code
    assert_equal({url: "https://idp.example.com/.well-known/openid-configuration"}, error.details)
  end

  def test_discover_oidc_config_rejects_untrusted_discovered_urls
    issuer = "https://idp.example.com"
    error = assert_raises(DiscoveryError) do
      Discovery.discover_oidc_config(
        issuer: issuer,
        trusted_origin: ->(url) { url.end_with?(".well-known/openid-configuration") },
        fetch: fetch_with(discovery_document(issuer: issuer))
      )
    end

    assert_equal "discovery_untrusted_origin", error.code
    assert_equal "token_endpoint", error.details.fetch(:endpoint)
  end

  def test_ensure_runtime_discovery_returns_config_unchanged_when_discovery_is_not_needed
    complete_config = {
      issuer: "https://idp.example.com",
      client_id: "client-id",
      client_secret: "client-secret",
      pkce: true,
      authorization_endpoint: "https://idp.example.com/oauth2/authorize",
      token_endpoint: "https://idp.example.com/oauth2/token",
      jwks_endpoint: "https://idp.example.com/.well-known/jwks.json"
    }
    calls = []

    result = Discovery.ensure_runtime_discovery(complete_config, "https://idp.example.com", trusted, fetch: ->(url, **_options) { calls << url })

    assert_same complete_config, result
    assert_empty calls
  end

  def test_ensure_runtime_discovery_hydrates_missing_endpoints
    issuer = "https://idp.example.com"
    result = Discovery.ensure_runtime_discovery(
      {issuer: issuer, client_id: "client-id", client_secret: "client-secret", pkce: true},
      issuer,
      trusted,
      fetch: fetch_with(discovery_document(issuer: issuer))
    )

    assert_equal "#{issuer}/oauth2/authorize", result.fetch(:authorization_endpoint)
    assert_equal "#{issuer}/oauth2/token", result.fetch(:token_endpoint)
    assert_equal "#{issuer}/.well-known/jwks.json", result.fetch(:jwks_endpoint)
    assert_equal "#{issuer}/userinfo", result.fetch(:user_info_endpoint)
  end

  def test_ensure_runtime_discovery_preserves_existing_config_fields
    issuer = "https://idp.example.com"
    result = Discovery.ensure_runtime_discovery(
      {issuer: issuer, client_id: "client-id", client_secret: "client-secret", pkce: true},
      issuer,
      trusted,
      fetch: fetch_with(discovery_document(issuer: issuer))
    )

    assert_equal "client-id", result.fetch(:client_id)
    assert_equal "client-secret", result.fetch(:client_secret)
    assert_equal true, result.fetch(:pkce)
  end

  def test_ensure_runtime_discovery_raises_when_discovery_fails
    error = assert_raises(DiscoveryError) do
      Discovery.ensure_runtime_discovery(
        {issuer: "https://idp.example.com"},
        "https://idp.example.com",
        trusted,
        fetch: ->(_url, **_options) { {data: nil, error: {message: "Network error"}} }
      )
    end

    assert_equal "discovery_unexpected_error", error.code
  end

  def test_ensure_runtime_discovery_raises_for_untrusted_origin
    error = assert_raises(DiscoveryError) do
      Discovery.ensure_runtime_discovery({issuer: "https://idp.example.com"}, "https://idp.example.com", ->(_url) { false }, fetch: fetch_with(discovery_document))
    end

    assert_equal "discovery_untrusted_origin", error.code
  end

  private

  def trusted
    ->(_url) { true }
  end

  def discovery_document(overrides = {})
    {
      issuer: "https://idp.example.com",
      authorization_endpoint: "https://idp.example.com/oauth2/authorize",
      token_endpoint: "https://idp.example.com/oauth2/token",
      jwks_uri: "https://idp.example.com/.well-known/jwks.json",
      userinfo_endpoint: "https://idp.example.com/userinfo",
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      scopes_supported: ["openid", "profile", "email", "offline_access"],
      response_types_supported: ["code", "token", "id_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      claims_supported: ["sub", "name", "email", "email_verified"]
    }.merge(overrides)
  end

  def fetch_with(document)
    ->(_url, **_options) { {data: document, error: nil} }
  end
end

# frozen_string_literal: true

require "better_auth/sso"
require "json"
require "rack/mock"
require_relative "../../test_helper"

class BetterAuthSSOOIDCMirrorTest < Minitest::Test
  SECRET = "oidc-mirror-secret-with-enough-entropy-123"

  def test_registers_oidc_provider_and_stores_full_config
    auth = build_auth
    cookie = sign_up_cookie(auth)

    response = register_oidc_provider(auth, cookie, provider_id: "test", domain: "localhost.com")
    stored = auth.context.adapter.find_one(model: "ssoProvider", where: [{field: "providerId", value: "test"}])

    assert_equal "test", response.fetch("providerId")
    assert_equal "oidc", response.fetch("type")
    assert_equal "****", response.fetch("oidcConfig").fetch("clientIdLastFour")
    assert_equal "sub", response.fetch("oidcConfig").fetch("mapping").fetch("id")
    assert_equal "email", response.fetch("oidcConfig").fetch("mapping").fetch("email")
    refute JSON.generate(response).include?("clientSecret")
    stored_config = stored.fetch("oidcConfig")
    assert_equal "test", stored_config.fetch(:client_id)
    assert_equal "test-secret", stored_config.fetch(:client_secret)
    assert_equal({"id" => "sub", "email" => "email", "email_verified" => "email_verified", "name" => "name", "image" => "picture"}, stringify_keys(stored_config.fetch(:mapping)))
  end

  def test_rejects_invalid_issuer_and_duplicate_provider_id
    auth = build_auth
    cookie = sign_up_cookie(auth)

    invalid = assert_raises(BetterAuth::APIError) do
      register_oidc_provider(auth, cookie, provider_id: "invalid", issuer: "invalid")
    end
    assert_equal 400, invalid.status_code
    assert_equal "Invalid issuer. Must be a valid URL", invalid.message

    register_oidc_provider(auth, cookie, provider_id: "duplicate", domain: "duplicate.com")
    duplicate = assert_raises(BetterAuth::APIError) do
      register_oidc_provider(auth, cookie, provider_id: "duplicate", domain: "another-duplicate.com")
    end
    assert_equal 422, duplicate.status_code
    assert_equal "SSO provider with this providerId already exists", duplicate.message
  end

  def test_sign_in_selects_oidc_provider_by_email_domain_and_provider_id
    auth = build_auth
    cookie = sign_up_cookie(auth)
    register_oidc_provider(auth, cookie, provider_id: "test", domain: "localhost.com")

    by_email = oidc_sign_in_params(auth, email: "my-email@localhost.com", callbackURL: "/dashboard")
    assert_equal "https://idp.example.com/authorize", by_email.fetch(:url_without_query)
    assert_equal "http://localhost:3000/api/auth/sso/callback/test", by_email.fetch(:params).fetch("redirect_uri")
    assert_equal "my-email@localhost.com", by_email.fetch(:params).fetch("login_hint")

    by_domain = oidc_sign_in_params(auth, email: "my-email@test.com", domain: "localhost.com", callbackURL: "/dashboard")
    assert_equal "test", by_domain.fetch(:params).fetch("client_id")

    by_provider = oidc_sign_in_params(auth, providerId: "test", loginHint: "user@example.com", callbackURL: "/dashboard")
    assert_equal "user@example.com", by_provider.fetch(:params).fetch("login_hint")
  end

  def test_sign_in_selects_oidc_provider_by_organization_slug
    auth = build_auth(plugins: [BetterAuth::Plugins.sso, BetterAuth::Plugins.organization])
    cookie = sign_up_cookie(auth)
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Localhost", slug: "localhost"})
    register_oidc_provider(auth, cookie, provider_id: "org-oidc", domain: "localhost.com", organization_id: organization.fetch("id"))

    sign_in = oidc_sign_in_params(auth, organizationSlug: "localhost", callbackURL: "/dashboard")

    assert_equal "https://idp.example.com/authorize", sign_in.fetch(:url_without_query)
    assert_equal "http://localhost:3000/api/auth/sso/callback/org-oidc", sign_in.fetch(:params).fetch("redirect_uri")
  end

  def test_sign_in_hydrates_missing_authorization_endpoint_with_runtime_discovery
    discovery_calls = []
    auth = build_auth(
      trusted_origins: ["https://idp.example.com"],
      oidc_discovery_fetch: ->(url) {
        discovery_calls << url
        {
          issuer: "https://idp.example.com",
          authorization_endpoint: "authorize",
          token_endpoint: "token",
          jwks_uri: "jwks"
        }
      }
    )
    cookie = sign_up_cookie(auth)
    register_oidc_provider(
      auth,
      cookie,
      provider_id: "no-auth-endpoint",
      domain: "no-auth-endpoint.com",
      oidc_config: {
        clientId: "test",
        clientSecret: "test-secret",
        skipDiscovery: true,
        tokenEndpoint: "https://idp.example.com/token",
        jwksEndpoint: "https://idp.example.com/jwks",
        discoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration"
      }
    )

    sign_in = oidc_sign_in_params(auth, providerId: "no-auth-endpoint", callbackURL: "/dashboard")

    assert_equal ["https://idp.example.com/.well-known/openid-configuration"], discovery_calls
    assert_equal "https://idp.example.com/authorize", sign_in.fetch(:url_without_query)
  end

  def test_callback_normalizes_email_to_lowercase_and_reuses_existing_user
    auth = build_auth
    cookie = sign_up_cookie(auth)
    register_oidc_provider(auth, cookie, provider_id: "email-case", domain: "email-case-test.com", user_info: {id: "oidc-email-case-test-user", email: "OIDCUser@Example.COM", name: "OIDC Test User"})

    first = complete_oidc_callback(auth, provider_id: "email-case", callback_url: "/dashboard")
    first_user = auth.context.internal_adapter.find_user_by_email("oidcuser@example.com").fetch(:user)
    second = complete_oidc_callback(auth, provider_id: "email-case", callback_url: "/dashboard")
    second_user = auth.context.internal_adapter.find_user_by_email("oidcuser@example.com").fetch(:user)

    assert_equal "/dashboard", first.fetch(:location)
    assert_equal "/dashboard", second.fetch(:location)
    assert_equal first_user.fetch("id"), second_user.fetch("id")
    assert_equal "oidcuser@example.com", second_user.fetch("email")
  end

  def test_disable_implicit_signup_blocks_unrequested_user_but_allows_requested_signup
    auth = build_auth(disable_implicit_sign_up: true)
    cookie = sign_up_cookie(auth)
    register_oidc_provider(auth, cookie, provider_id: "test", domain: "localhost.com", user_info: {id: "oauth2", email: "oauth2@test.com", name: "OAuth2 Test"})

    blocked = complete_oidc_callback(auth, provider_id: "test", callback_url: "/dashboard")
    assert_equal "/dashboard?error=signup+disabled", blocked.fetch(:location)
    assert_nil auth.context.internal_adapter.find_user_by_email("oauth2@test.com")

    allowed = complete_oidc_callback(auth, provider_id: "test", callback_url: "/dashboard", requestSignUp: true)
    assert_equal "/dashboard", allowed.fetch(:location)
    assert auth.context.internal_adapter.find_user_by_email("oauth2@test.com")
  end

  def test_provision_user_runs_only_for_new_users_by_default
    provisioned = []
    auth = build_auth(
      provision_user: ->(user:, token:, provider:, **data) {
        provisioned << [user.fetch("email"), data.fetch(:userInfo).fetch(:id), token.fetch(:access_token), provider.fetch("providerId")]
      }
    )
    cookie = sign_up_cookie(auth)
    register_oidc_provider(auth, cookie, provider_id: "test", domain: "localhost.com", user_info: {id: "oauth2", email: "provision@example.com", name: "Provisioned"})

    2.times { complete_oidc_callback(auth, provider_id: "test", callback_url: "/dashboard") }

    assert_equal [["provision@example.com", "oauth2", "access-token", "test"]], provisioned
  end

  def test_provision_user_can_run_on_every_login
    provisioned = []
    auth = build_auth(
      provision_user_on_every_login: true,
      provision_user: ->(user:, **_data) { provisioned << user.fetch("email") }
    )
    cookie = sign_up_cookie(auth)
    register_oidc_provider(auth, cookie, provider_id: "test", domain: "localhost.com", user_info: {id: "oauth2", email: "every-login@example.com", name: "Provisioned"})

    2.times { complete_oidc_callback(auth, provider_id: "test", callback_url: "/dashboard") }

    assert_equal ["every-login@example.com", "every-login@example.com"], provisioned
  end

  def test_shared_redirect_uri_is_used_for_authorization_and_callback
    auth = build_auth(redirect_uri: "/sso/callback")
    cookie = sign_up_cookie(auth)
    provider = register_oidc_provider(auth, cookie, provider_id: "shared", domain: "shared.com", user_info: {id: "shared-sub", email: "shared@example.com", name: "Shared Callback"})

    sign_in = oidc_sign_in_params(auth, providerId: "shared", callbackURL: "/dashboard")
    status, headers, _body = auth.api.callback_sso_shared(query: {code: "good-code", state: sign_in.fetch(:params).fetch("state")}, as_response: true)

    assert_equal "http://localhost:3000/api/auth/sso/callback", provider.fetch(:redirectURI)
    assert_equal "http://localhost:3000/api/auth/sso/callback", sign_in.fetch(:params).fetch("redirect_uri")
    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("shared@example.com")
  end

  def test_default_sso_oidc_selects_provider_by_provider_id_and_email_domain
    auth = build_auth(
      default_sso: [
        {
          domain: "example.com",
          providerId: "default-oidc",
          oidcConfig: {
            issuer: "https://idp.example.com",
            clientId: "client-id",
            clientSecret: "client-secret",
            pkce: false,
            authorizationEndpoint: "https://idp.example.com/authorize",
            tokenEndpoint: "https://idp.example.com/token",
            jwksEndpoint: "https://idp.example.com/jwks",
            getToken: ->(**_data) { {accessToken: "access-token"} },
            getUserInfo: ->(_tokens) { {id: "default-sub", email: "default@example.com", name: "Default OIDC"} }
          }
        }
      ]
    )

    by_provider = oidc_sign_in_params(auth, providerId: "default-oidc", callbackURL: "/dashboard")
    by_email = oidc_sign_in_params(auth, email: "ada@example.com", callbackURL: "/dashboard")

    assert_equal "client-id", by_provider.fetch(:params).fetch("client_id")
    assert_equal "client-id", by_email.fetch(:params).fetch("client_id")
    refute by_email.fetch(:params).key?("code_challenge")
  end

  def test_default_sso_oidc_hydrates_missing_endpoints_with_runtime_discovery
    discovery_calls = []
    auth = build_auth(
      trusted_origins: ["https://idp.example.com"],
      oidc_discovery_fetch: ->(url) {
        discovery_calls << url
        {
          issuer: "https://idp.example.com",
          authorization_endpoint: "https://idp.example.com/authorize",
          token_endpoint: "https://idp.example.com/token",
          jwks_uri: "https://idp.example.com/jwks"
        }
      },
      default_sso: [
        {
          domain: "discovered-default.com",
          providerId: "default-discovered",
          oidcConfig: {
            issuer: "https://idp.example.com",
            clientId: "client-id",
            clientSecret: "client-secret",
            pkce: false
          }
        }
      ]
    )

    sign_in = oidc_sign_in_params(auth, email: "ada@discovered-default.com", callbackURL: "/dashboard")

    assert_equal ["https://idp.example.com/.well-known/openid-configuration"], discovery_calls
    assert_equal "https://idp.example.com/authorize", sign_in.fetch(:url_without_query)
    assert_equal "client-id", sign_in.fetch(:params).fetch("client_id")
  end

  def test_callback_accepts_sub_claim_from_user_info_when_no_id_token_is_returned
    auth = build_auth
    cookie = sign_up_cookie(auth)
    register_oidc_provider(auth, cookie, provider_id: "userinfo-sub", domain: "userinfo-sub.com", user_info: {sub: "userinfo-sub-claim", email: "userinfo-sub@example.com", name: "UserInfo Sub"})

    result = complete_oidc_callback(auth, provider_id: "userinfo-sub", callback_url: "/dashboard")
    user = auth.context.internal_adapter.find_user_by_email("userinfo-sub@example.com").fetch(:user)
    account = auth.context.internal_adapter.find_account_by_provider_id("userinfo-sub-claim", "sso:userinfo-sub")

    assert_equal "/dashboard", result.fetch(:location)
    assert_equal user.fetch("id"), account.fetch("userId")
  end

  def test_pkce_code_verifier_is_not_exposed_in_readable_state
    auth = build_auth
    cookie = sign_up_cookie(auth)
    register_oidc_provider(
      auth,
      cookie,
      provider_id: "pkce-state",
      domain: "pkce-state.com",
      oidc_config: {
        clientId: "test",
        clientSecret: "test-secret",
        skipDiscovery: true,
        pkce: true,
        authorizationEndpoint: "https://idp.example.com/authorize",
        tokenEndpoint: "https://idp.example.com/token",
        jwksEndpoint: "https://idp.example.com/jwks",
        getToken: ->(**_data) { {accessToken: "access-token"} },
        getUserInfo: ->(_tokens) { {id: "pkce-sub", email: "pkce@example.com", name: "PKCE"} }
      }
    )

    sign_in = oidc_sign_in_params(auth, providerId: "pkce-state", callbackURL: "/dashboard")
    payload = JSON.parse(Base64.urlsafe_decode64(sign_in.fetch(:params).fetch("state").split(".")[1]))

    refute payload.key?("codeVerifier")
    assert sign_in.fetch(:params).fetch("code_challenge")
  end

  def test_oidc_existing_email_requires_trusted_or_matching_verified_domain
    auth = build_auth
    victim_cookie = sign_up_cookie(auth, "victim@example.com")
    auth.api.sign_out(headers: {"cookie" => victim_cookie})
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    register_oidc_provider(
      auth,
      owner_cookie,
      provider_id: "unsafe-link",
      domain: "enterprise.test",
      user_info: {id: "foreign-subject", email: "victim@example.com", name: "Victim"}
    )

    result = complete_oidc_callback(auth, provider_id: "unsafe-link", callback_url: "/dashboard")

    assert_equal "/dashboard?error=account_not_linked", result.fetch(:location)
    assert_nil auth.context.internal_adapter.find_account_by_provider_id("foreign-subject", "sso:unsafe-link")
  end

  def test_register_oidc_rejects_manual_endpoints_outside_trusted_origins
    auth = build_auth(trusted_origins: ["https://idp.example.com"])
    cookie = sign_up_cookie(auth)

    error = assert_raises(BetterAuth::APIError) do
      register_oidc_provider(
        auth,
        cookie,
        provider_id: "untrusted-manual",
        domain: "untrusted-manual.com",
        oidc_config: {
          clientId: "test",
          clientSecret: "test-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://untrusted.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks"
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/trusted/i, error.message)
  end

  def test_plugin_oidc_discovery_passes_timeout_to_fetcher
    calls = []

    BetterAuth::Plugins.sso_discover_oidc_config(
      issuer: "https://idp.example.com",
      timeout: 123,
      trusted_origin: ->(_url) { true },
      fetch: ->(url, timeout: nil) {
        calls << [url, timeout]
        {
          data: {
            issuer: "https://idp.example.com",
            authorization_endpoint: "https://idp.example.com/authorize",
            token_endpoint: "https://idp.example.com/token",
            jwks_uri: "https://idp.example.com/jwks"
          },
          error: nil
        }
      }
    )

    assert_equal [["https://idp.example.com/.well-known/openid-configuration", 123]], calls
  end

  private

  def build_auth(options = nil, plugins: nil, **kwargs)
    options = (options || {}).merge(kwargs)
    trusted_origins = options.delete(:trusted_origins)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      trusted_origins: trusted_origins,
      plugins: plugins || [BetterAuth::Plugins.sso(options)]
    )
  end

  def sign_up_cookie(auth, email = "owner@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: email.split("@").first},
      as_response: true
    )
    headers.fetch("set-cookie").to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def register_oidc_provider(auth, cookie, provider_id:, domain: "localhost.com", issuer: "https://idp.example.com", oidc_config: nil, user_info: nil, organization_id: nil)
    callback_user_info = user_info || {id: "oauth2", email: "oauth2@test.com", name: "OAuth2 Test", picture: "https://test.com/picture.png", email_verified: true}
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        issuer: issuer,
        domain: domain,
        providerId: provider_id,
        organizationId: organization_id,
        oidcConfig: oidc_config || {
          clientId: "test",
          clientSecret: "test-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
          mapping: {
            id: "sub",
            email: "email",
            emailVerified: "email_verified",
            name: "name",
            image: "picture"
          },
          getToken: ->(**_data) { {accessToken: "access-token"} },
          getUserInfo: ->(_tokens) { callback_user_info }
        }
      }
    )
  end

  def oidc_sign_in_params(auth, body = {})
    result = auth.api.sign_in_sso(body: body)
    uri = URI.parse(result.fetch(:url))
    {
      url: result.fetch(:url),
      url_without_query: "#{uri.scheme}://#{uri.host}#{uri.path}",
      params: Rack::Utils.parse_query(uri.query)
    }
  end

  def complete_oidc_callback(auth, provider_id:, callback_url:, **sign_in_body)
    sign_in = oidc_sign_in_params(auth, {providerId: provider_id, callbackURL: callback_url}.merge(sign_in_body))
    status, headers, _body = auth.api.callback_sso(
      params: {providerId: provider_id},
      query: {code: "good-code", state: sign_in.fetch(:params).fetch("state")},
      as_response: true
    )
    {status: status, location: headers.fetch("location"), headers: headers}
  end

  def stringify_keys(value)
    value.each_with_object({}) { |(key, object), result| result[key.to_s] = object }
  end
end

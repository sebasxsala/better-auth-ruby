# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthRoutesAccountTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_list_accounts_returns_current_user_accounts_with_scope_array
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "accounts@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(userId: user_id, providerId: "github", accountId: "gh-1", scope: "repo,user")

    accounts = auth.api.list_accounts(headers: {"cookie" => cookie})

    github = accounts.find { |account| account["providerId"] == "github" }
    assert_equal ["repo", "user"], github["scopes"]
    refute github.key?("accessToken")
  end

  def test_list_user_accounts_alias_matches_upstream_api_name
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "upstream-accounts@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(userId: user_id, providerId: "github", accountId: "gh-upstream", scope: "repo")

    accounts = auth.api.list_user_accounts(headers: {"cookie" => cookie})

    github = accounts.find { |account| account["providerId"] == "github" }
    assert_equal "gh-upstream", github["accountId"]
    assert_equal ["repo"], github["scopes"]
  end

  def test_unlink_account_removes_matching_account_but_not_last_account
    auth = build_auth(account: {account_linking: {allow_unlinking_all: false}})
    cookie = sign_up_cookie(auth, email: "unlink@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(userId: user_id, providerId: "github", accountId: "gh-1")

    assert_equal({status: true}, auth.api.unlink_account(headers: {"cookie" => cookie}, body: {providerId: "github"}))

    error = assert_raises(BetterAuth::APIError) do
      auth.api.unlink_account(headers: {"cookie" => cookie}, body: {providerId: "credential"})
    end
    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["FAILED_TO_UNLINK_LAST_ACCOUNT"], error.message
  end

  def test_unlink_account_cannot_remove_account_owned_by_another_user
    auth = build_auth
    current_cookie = sign_up_cookie(auth, email: "unlink-owner@example.com")
    current_user_id = auth.api.get_session(headers: {"cookie" => current_cookie})[:user]["id"]
    other_cookie = sign_up_cookie(auth, email: "unlink-other@example.com")
    other_user_id = auth.api.get_session(headers: {"cookie" => other_cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(userId: current_user_id, providerId: "github", accountId: "current-gh")
    auth.context.internal_adapter.create_account(userId: other_user_id, providerId: "github", accountId: "other-gh")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.unlink_account(headers: {"cookie" => current_cookie}, body: {providerId: "github", accountId: "other-gh"})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["ACCOUNT_NOT_FOUND"], error.message
    assert auth.context.internal_adapter.find_account_by_provider_id("other-gh", "github")
  end

  def test_unlink_account_rejects_missing_provider_id_before_account_lookup
    auth = build_auth(account: {account_linking: {allow_unlinking_all: true}})
    cookie = sign_up_cookie(auth, email: "unlink-validation@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.unlink_account(headers: {"cookie" => cookie}, body: {})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["VALIDATION_ERROR"], error.message
  end

  def test_get_access_token_and_refresh_token_use_configured_provider
    refreshed_at = Time.now + 3600
    refresh_calls = 0
    provider = {
      id: "github",
      refresh_access_token: ->(_refresh_token) {
        refresh_calls += 1
        {
          accessToken: "new-access",
          refreshToken: "new-refresh",
          accessTokenExpiresAt: refreshed_at,
          refreshTokenExpiresAt: refreshed_at + 3600,
          scopes: ["repo"],
          idToken: "new-id"
        }
      }
    }
    auth = build_auth(social_providers: {github: provider})
    cookie = sign_up_cookie(auth, email: "tokens@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-1",
      accessToken: "old-access",
      refreshToken: "old-refresh",
      accessTokenExpiresAt: Time.now - 60,
      scope: "user"
    )

    token_data = auth.api.get_access_token(headers: {"cookie" => cookie}, body: {providerId: "github", accountId: "gh-1"})
    assert_equal "new-access", token_data[:accessToken]
    assert_equal ["repo"], token_data[:scopes]
    assert_equal "new-id", token_data[:idToken]
    assert_equal 1, refresh_calls

    stored = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["id"] == account["id"] }
    assert_equal "new-id", stored["idToken"]

    refresh_data = auth.api.refresh_token(headers: {"cookie" => cookie}, body: {providerId: "github", accountId: account["id"]})
    assert_equal "new-refresh", refresh_data[:refreshToken]
    assert_equal "github", refresh_data[:providerId]
  end

  def test_get_access_token_wraps_provider_refresh_errors
    provider = {
      id: "github",
      refresh_access_token: ->(_refresh_token) { raise "provider down" }
    }
    auth = build_auth(social_providers: {github: provider})
    cookie = sign_up_cookie(auth, email: "access-error@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-error",
      accessToken: "old-access",
      refreshToken: "old-refresh",
      accessTokenExpiresAt: Time.now - 60
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.get_access_token(headers: {"cookie" => cookie}, body: {providerId: "github", accountId: "gh-error"})
    end

    assert_equal 400, error.status_code
    assert_equal "FAILED_TO_GET_ACCESS_TOKEN", error.code
    assert_equal "Failed to get a valid access token", error.message
  end

  def test_refresh_token_wraps_provider_refresh_errors
    provider = {
      id: "github",
      refresh_access_token: ->(_refresh_token) { raise "provider down" }
    }
    auth = build_auth(social_providers: {github: provider})
    cookie = sign_up_cookie(auth, email: "refresh-error@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-refresh-error",
      refreshToken: "old-refresh"
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.refresh_token(headers: {"cookie" => cookie}, body: {providerId: "github", accountId: "gh-refresh-error"})
    end

    assert_equal 400, error.status_code
    assert_equal "FAILED_TO_REFRESH_ACCESS_TOKEN", error.code
    assert_equal "Failed to refresh access token", error.message
  end

  def test_get_access_token_rejects_missing_provider_id_before_provider_lookup
    auth = build_auth(social_providers: {github: {id: "github"}})
    cookie = sign_up_cookie(auth, email: "access-validation@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.get_access_token(headers: {"cookie" => cookie}, body: {})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["VALIDATION_ERROR"], error.message
  end

  def test_refresh_token_rejects_missing_provider_id_before_provider_lookup
    auth = build_auth(social_providers: {github: {id: "github"}})
    cookie = sign_up_cookie(auth, email: "refresh-validation@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.refresh_token(headers: {"cookie" => cookie}, body: {})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["VALIDATION_ERROR"], error.message
  end

  def test_rack_get_access_token_rejects_user_id_without_session
    auth = build_auth(social_providers: {github: {id: "github"}})
    cookie = sign_up_cookie(auth, email: "rack-access-boundary@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-boundary",
      accessToken: "secret-access",
      scope: "repo"
    )

    status, _headers, body = auth.call(rack_env("POST", "/api/auth/get-access-token", body: {
      providerId: "github",
      userId: user_id,
      accountId: "gh-boundary"
    }))

    assert_equal 401, status
    refute_includes body.join, "secret-access"
  end

  def test_rack_refresh_token_rejects_user_id_without_session
    refresh_calls = 0
    provider = {
      id: "github",
      refresh_access_token: ->(_refresh_token) {
        refresh_calls += 1
        {accessToken: "new-access", refreshToken: "new-refresh"}
      }
    }
    auth = build_auth(social_providers: {github: provider})
    cookie = sign_up_cookie(auth, email: "rack-refresh-boundary@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-refresh-boundary",
      refreshToken: "secret-refresh"
    )

    status, _headers, body = auth.call(rack_env("POST", "/api/auth/refresh-token", body: {
      providerId: "github",
      userId: user_id,
      accountId: "gh-refresh-boundary"
    }))

    assert_equal 401, status
    assert_equal 0, refresh_calls
    refute_includes body.join, "new-refresh"
  end

  def test_direct_get_access_token_allows_server_user_id_without_session
    auth = build_auth(social_providers: {github: {id: "github"}})
    cookie = sign_up_cookie(auth, email: "direct-access-boundary@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-direct",
      accessToken: "direct-access",
      scope: "repo"
    )

    token_data = auth.api.get_access_token(body: {providerId: "github", userId: user_id, accountId: "gh-direct"})

    assert_equal "direct-access", token_data[:accessToken]
  end

  def test_direct_refresh_token_allows_server_user_id_without_session
    provider = {
      id: "github",
      refresh_access_token: ->(_refresh_token) {
        {accessToken: "direct-new-access", refreshToken: "direct-new-refresh"}
      }
    }
    auth = build_auth(social_providers: {github: provider})
    cookie = sign_up_cookie(auth, email: "direct-refresh-boundary@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-direct-refresh",
      refreshToken: "direct-refresh"
    )

    token_data = auth.api.refresh_token(body: {providerId: "github", userId: user_id, accountId: "gh-direct-refresh"})

    assert_equal "direct-new-refresh", token_data[:refreshToken]
  end

  def test_get_access_token_selects_requested_same_provider_account
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          refresh_access_token: ->(_refresh_token) { raise "unexpected refresh" }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "multi-provider@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-first",
      accessToken: "first-access",
      scope: "user"
    )
    second = auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-second",
      accessToken: "second-access",
      scope: "repo"
    )

    by_provider_account_id = auth.api.get_access_token(headers: {"cookie" => cookie}, body: {providerId: "github", accountId: "gh-second"})
    by_internal_id = auth.api.get_access_token(headers: {"cookie" => cookie}, body: {providerId: "github", accountId: second["id"]})

    assert_equal "second-access", by_provider_account_id[:accessToken]
    assert_equal ["repo"], by_provider_account_id[:scopes]
    assert_equal "second-access", by_internal_id[:accessToken]
  end

  def test_oauth_token_storage_passthrough_and_migration_values
    encrypted_auth = build_auth(account: {encrypt_oauth_tokens: true})
    plain_auth = build_auth(account: {encrypt_oauth_tokens: false})
    encrypted_ctx = fake_ctx(encrypted_auth)
    plain_ctx = fake_ctx(plain_auth)

    assert_equal "", BetterAuth::Routes.oauth_token_value(encrypted_ctx, "")
    assert_nil BetterAuth::Routes.oauth_token_for_storage(encrypted_ctx, nil)
    assert_equal "plain-token", BetterAuth::Routes.oauth_token_for_storage(plain_ctx, "plain-token")
    assert_equal "plain-token", BetterAuth::Routes.oauth_token_value(plain_ctx, "plain-token")

    encrypted = BetterAuth::Routes.oauth_token_for_storage(encrypted_ctx, "secret-token")
    refute_equal "secret-token", encrypted
    assert_equal "secret-token", BetterAuth::Routes.oauth_token_value(encrypted_ctx, encrypted)

    assert_equal "ya29.a0ARW5m7hQ_some_oauth_token", BetterAuth::Routes.oauth_token_value(encrypted_ctx, "ya29.a0ARW5m7hQ_some_oauth_token")
    jwt_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
    assert_equal jwt_token, BetterAuth::Routes.oauth_token_value(encrypted_ctx, jwt_token)
    assert_equal "abc", BetterAuth::Routes.oauth_token_value(encrypted_ctx, "abc")
    assert_equal "not-valid-encrypted-data", BetterAuth::Routes.oauth_token_value(encrypted_ctx, "not-valid-encrypted-data")
  end

  def test_encrypted_oauth_token_storage_survives_secret_rotation
    old_auth = build_auth(
      account: {encrypt_oauth_tokens: true},
      secrets: [{version: 1, value: "old-account-token-secret-with-enough-entropy"}]
    )
    encrypted = BetterAuth::Routes.oauth_token_for_storage(fake_ctx(old_auth), "rotated-oauth-token")
    new_auth = build_auth(
      account: {encrypt_oauth_tokens: true},
      secrets: [
        {version: 2, value: "new-account-token-secret-with-enough-entropy"},
        {version: 1, value: "old-account-token-secret-with-enough-entropy"}
      ]
    )

    assert_equal "rotated-oauth-token", BetterAuth::Routes.oauth_token_value(fake_ctx(new_auth), encrypted)
  end

  def test_get_access_token_decrypts_stored_tokens_and_refresh_stores_encrypted_values
    refreshed_at = Time.now + 3600
    auth = build_auth(
      account: {encrypt_oauth_tokens: true},
      social_providers: {
        github: {
          id: "github",
          refresh_access_token: ->(refresh_token) {
            assert_equal "old-refresh", refresh_token
            {
              accessToken: "new-access",
              refreshToken: "new-refresh",
              accessTokenExpiresAt: refreshed_at,
              refreshTokenExpiresAt: refreshed_at + 3600,
              scopes: ["repo", "user"]
            }
          }
        }
      }
    )
    ctx = fake_ctx(auth)
    cookie = sign_up_cookie(auth, email: "encrypted-tokens@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-encrypted",
      accessToken: BetterAuth::Routes.oauth_token_for_storage(ctx, "old-access"),
      refreshToken: BetterAuth::Routes.oauth_token_for_storage(ctx, "old-refresh"),
      accessTokenExpiresAt: Time.now - 60,
      scope: "read"
    )

    data = auth.api.get_access_token(headers: {"cookie" => cookie}, body: {providerId: "github", accountId: "gh-encrypted"})

    assert_equal "new-access", data[:accessToken]
    assert_equal ["repo", "user"], data[:scopes]
    stored = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["id"] == account["id"] }
    refute_equal "new-access", stored["accessToken"]
    refute_equal "new-refresh", stored["refreshToken"]
    assert_equal "new-access", BetterAuth::Routes.oauth_token_value(ctx, stored["accessToken"])
    assert_equal "new-refresh", BetterAuth::Routes.oauth_token_value(ctx, stored["refreshToken"])
  end

  def test_refresh_token_preserves_existing_refresh_token_expiry_and_scope_when_provider_omits_them
    existing_refresh_expires_at = Time.now + 7200
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          refresh_access_token: ->(refresh_token) {
            assert_equal "old-refresh", refresh_token
            {
              accessToken: "new-access",
              accessTokenExpiresAt: Time.now + 3600,
              idToken: "new-id"
            }
          }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "preserve-refresh@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-preserve",
      accessToken: "old-access",
      refreshToken: "old-refresh",
      refreshTokenExpiresAt: existing_refresh_expires_at,
      scope: "repo,user"
    )

    data = auth.api.refresh_token(headers: {"cookie" => cookie}, body: {providerId: "github", accountId: "gh-preserve"})

    assert_equal "new-access", data[:accessToken]
    assert_equal "old-refresh", data[:refreshToken]
    assert_equal existing_refresh_expires_at, data[:refreshTokenExpiresAt]
    assert_equal "repo,user", data[:scope]
    assert_equal "new-id", data[:idToken]
    stored = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["id"] == account["id"] }
    assert_equal "old-refresh", stored["refreshToken"]
    assert_equal existing_refresh_expires_at, stored["refreshTokenExpiresAt"]
  end

  def test_account_info_calls_provider_user_info
    provider = {
      id: "github",
      get_user_info: ->(tokens) {
        {
          user: {id: "gh-1", email: "provider@example.com", name: "Provider User"},
          data: {accessToken: tokens[:accessToken]}
        }
      }
    }
    auth = build_auth(social_providers: {github: provider})
    cookie = sign_up_cookie(auth, email: "info@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-1",
      accessToken: "access-token"
    )

    info = auth.api.account_info(headers: {"cookie" => cookie}, query: {accountId: account["id"]})

    assert_equal "provider@example.com", info[:user][:email]
    assert_equal "access-token", info[:data][:accessToken]
  end

  def test_account_info_refreshes_expired_access_token_before_calling_provider
    refreshed_at = Time.now + 3600
    provider = {
      id: "github",
      refresh_access_token: ->(refresh_token) {
        assert_equal "old-refresh", refresh_token
        {
          accessToken: "fresh-access",
          refreshToken: "fresh-refresh",
          accessTokenExpiresAt: refreshed_at,
          scopes: ["repo"]
        }
      },
      get_user_info: ->(tokens) {
        {
          user: {id: "gh-fresh", email: "fresh-info@example.com"},
          data: {accessToken: tokens[:accessToken], scopes: tokens[:scopes]}
        }
      }
    }
    auth = build_auth(social_providers: {github: provider})
    cookie = sign_up_cookie(auth, email: "fresh-info-user@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-fresh",
      accessToken: "old-access",
      refreshToken: "old-refresh",
      accessTokenExpiresAt: Time.now - 60,
      scope: "user"
    )

    info = auth.api.account_info(headers: {"cookie" => cookie}, query: {accountId: account["id"]})

    assert_equal "fresh-info@example.com", info[:user][:email]
    assert_equal "fresh-access", info[:data][:accessToken]
    assert_equal ["repo"], info[:data][:scopes]
  end

  def test_account_info_accepts_provider_account_id_from_list_accounts
    provider = {
      id: "github",
      get_user_info: ->(_tokens) {
        {
          user: {id: "provider-account-id", email: "provider-id@example.com"},
          data: {ok: true}
        }
      }
    }
    auth = build_auth(social_providers: {github: provider})
    cookie = sign_up_cookie(auth, email: "provider-id-info@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "provider-account-id",
      accessToken: "access-token"
    )
    refute_equal account["id"], account["accountId"]

    listed = auth.api.list_accounts(headers: {"cookie" => cookie}).find { |entry| entry["providerId"] == "github" }
    info = auth.api.account_info(headers: {"cookie" => cookie}, query: {accountId: listed["accountId"]})

    assert_equal "provider-id@example.com", info[:user][:email]
    assert_equal({ok: true}, info[:data])
  end

  def test_account_info_uses_account_cookie_when_account_id_is_omitted
    provider = {
      id: "github",
      get_user_info: ->(tokens) {
        {
          user: {id: "cookie-account-id", email: "cookie-info@example.com"},
          data: {accessToken: tokens[:accessToken]}
        }
      }
    }
    auth = build_auth(account: {store_account_cookie: true}, social_providers: {github: provider})
    session_cookie = sign_up_cookie(auth, email: "cookie-info-user@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => session_cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "cookie-account-id",
      accessToken: "cookie-access-token"
    )
    cookie_ctx = BetterAuth::Endpoint::Context.new(
      path: "/account-info",
      method: "GET",
      query: {},
      body: {},
      params: {},
      headers: {},
      context: auth.context
    )
    BetterAuth::Cookies.set_account_cookie(cookie_ctx, account)
    account_cookie = cookie_ctx.response_headers.fetch("set-cookie").split(";").first

    info = auth.api.account_info(headers: {"cookie" => "#{session_cookie}; #{account_cookie}"})

    assert_equal "cookie-info@example.com", info[:user][:email]
    assert_equal "cookie-access-token", info[:data][:accessToken]
  end

  def test_account_info_refreshes_expired_access_token_through_get_access_token_path
    refreshed_at = Time.now + 3600
    provider = {
      id: "github",
      refresh_access_token: ->(_refresh_token) {
        {
          accessToken: "refreshed-access",
          refreshToken: "refreshed-refresh",
          accessTokenExpiresAt: refreshed_at,
          scopes: ["repo", "user"]
        }
      },
      get_user_info: ->(tokens) {
        {
          user: {id: "refresh-info-id", email: "refresh-info@example.com"},
          data: {accessToken: tokens[:accessToken], scopes: tokens[:scopes]}
        }
      }
    }
    auth = build_auth(social_providers: {github: provider})
    cookie = sign_up_cookie(auth, email: "refresh-info-user@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "refresh-info-account",
      accessToken: "expired-access",
      refreshToken: "refresh-token",
      accessTokenExpiresAt: Time.now - 60,
      scope: "read"
    )

    info = auth.api.account_info(headers: {"cookie" => cookie}, query: {accountId: account["accountId"]})
    stored = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["id"] == account["id"] }

    assert_equal "refreshed-access", info[:data][:accessToken]
    assert_equal ["repo", "user"], info[:data][:scopes]
    assert_equal "refreshed-access", stored["accessToken"]
    assert_equal "refreshed-refresh", stored["refreshToken"]
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Account User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def fake_ctx(auth)
    Struct.new(:context).new(auth.context)
  end

  def rack_env(method, path, body: nil)
    payload = body ? JSON.generate(body) : ""
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(payload),
      "CONTENT_TYPE" => body ? "application/json" : nil,
      "CONTENT_LENGTH" => payload.bytesize.to_s
    }.compact
  end
end

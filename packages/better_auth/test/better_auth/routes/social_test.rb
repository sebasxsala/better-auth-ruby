# frozen_string_literal: true

require "json"
require "uri"
require_relative "../../test_helper"

class BetterAuthRoutesSocialTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_callback_oauth_endpoint_uses_upstream_id_param
    auth = build_auth

    assert_equal "/callback/:id", auth.api.endpoints.fetch(:callback_oauth).path
  end

  def test_sign_in_social_with_id_token_creates_user_account_and_session
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-1",
                email: "social@example.com",
                name: "Social User",
                image: "https://example.com/avatar.png",
                emailVerified: true
              }
            }
          }
        }
      }
    )

    status, headers, body = auth.api.sign_in_social(
      body: {provider: "github", idToken: {token: "id-token", accessToken: "access-token"}},
      as_response: true
    )
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_equal false, data.fetch("redirect")
    assert_equal "social@example.com", data.fetch("user").fetch("email")
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("token"))
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    account = auth.context.internal_adapter.find_accounts(data.fetch("user").fetch("id")).find { |entry| entry["providerId"] == "github" }
    assert_equal "gh-1", account["accountId"]
    assert_equal "access-token", account["accessToken"]
  end

  def test_apple_id_token_sign_in_uses_user_name_from_id_token_body
    token = fake_jwt(
      "sub" => "apple-sub",
      "email" => "apple@example.com",
      "email_verified" => true
    )
    auth = build_auth(
      social_providers: {
        apple: BetterAuth::SocialProviders.apple(
          client_id: "apple-id",
          client_secret: "apple-secret",
          verify_id_token: ->(_token, _nonce = nil) { true }
        )
      }
    )

    result = auth.api.sign_in_social(
      body: {
        provider: "apple",
        idToken: {
          token: token,
          user: {
            name: {
              firstName: "First",
              lastName: "Last"
            },
            email: "apple@example.com"
          }
        }
      }
    )

    assert_equal false, result.fetch(:redirect)
    assert_equal "First Last", result.fetch(:user).fetch("name")
  end

  def test_apple_id_token_sign_in_uses_empty_name_without_user_body
    token = fake_jwt(
      "sub" => "apple-no-name-sub",
      "email" => "apple-no-name@example.com",
      "email_verified" => true
    )
    auth = build_auth(
      social_providers: {
        apple: BetterAuth::SocialProviders.apple(
          client_id: "apple-id",
          client_secret: "apple-secret",
          verify_id_token: ->(_token, _nonce = nil) { true }
        )
      }
    )

    result = auth.api.sign_in_social(
      body: {
        provider: "apple",
        idToken: {
          token: token
        }
      }
    )

    assert_equal false, result.fetch(:redirect)
    assert_equal "apple-no-name@example.com", result.fetch(:user).fetch("email")
    assert_equal "", result.fetch(:user).fetch("name")
  end

  def test_sign_in_social_returns_authorization_url_and_callback_completes_session
    issued_code_verifier = nil
    callback_code_verifier = nil
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: lambda do |data|
            issued_code_verifier = data[:codeVerifier]
            "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}&redirect_uri=#{URI.encode_www_form_component(data[:redirectURI])}"
          end,
          validate_authorization_code: lambda do |data|
            callback_code_verifier = data[:codeVerifier]
            {accessToken: "oauth-access", refreshToken: "oauth-refresh", scopes: ["user"]}
          end,
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-2",
                email: "callback@example.com",
                name: "Callback User",
                emailVerified: true
              }
            }
          }
        }
      }
    )

    response = auth.api.sign_in_social(body: {provider: "github", callbackURL: "/app", disableRedirect: true})
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/app", headers["location"]
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    user = auth.context.internal_adapter.find_user_by_email("callback@example.com")[:user]
    account = auth.context.internal_adapter.find_accounts(user["id"]).find { |entry| entry["providerId"] == "github" }
    assert_equal "oauth-refresh", account["refreshToken"]
    assert_equal "user", account["scope"]
    assert_match(/\A[0-9a-f]{32}\z/, issued_code_verifier)
    assert_equal issued_code_verifier, callback_code_verifier
  end

  def test_callback_post_redirects_to_get_with_merged_body_and_query
    called = false
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { called = true },
          get_user_info: ->(_tokens) { raise "unexpected user info call" }
        }
      }
    )
    response = auth.api.sign_in_social(body: {provider: "github", callbackURL: "/app", disableRedirect: true})
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {state: "query-state"},
      body: {code: "code", state: state},
      method: "POST",
      as_response: true
    )

    assert_equal 302, status
    location = headers.fetch("location")
    assert_match(%r{\Ahttp://localhost:3000/api/auth/callback/github\?}, location)
    params = Rack::Utils.parse_query(URI.parse(location).query)
    assert_equal "code", params.fetch("code")
    assert_equal state, params.fetch("state")
    refute called
  end

  def test_sign_in_social_rejects_untrusted_callback_urls
    auth = build_auth(
      trusted_origins: ["http://localhost:3000"],
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(_data) { "https://github.example/oauth" }
        }
      }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_social(
        body: {
          provider: "github",
          callbackURL: "https://evil.example/app",
          errorCallbackURL: "/error",
          newUserCallbackURL: "/welcome"
        }
      )
    end

    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_CALLBACK_URL"], error.message
  end

  def test_sign_in_social_uses_specific_callback_url_error_messages
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(_data) { "https://github.example/oauth" }
        }
      }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_social(body: {provider: "github", callbackURL: "/app", errorCallbackURL: "https://evil.example/error"})
    end
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_ERROR_CALLBACK_URL"], error.message

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_social(body: {provider: "github", callbackURL: "/app", newUserCallbackURL: "https://evil.example/new"})
    end
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_NEW_USER_CALLBACK_URL"], error.message
  end

  def test_sign_in_social_rejects_disabled_provider
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          enabled: false,
          create_authorization_url: ->(_data) { "https://github.example/oauth" }
        }
      }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_social(body: {provider: "github"})
    end

    assert_equal 404, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["PROVIDER_NOT_FOUND"], error.message
  end

  def test_microsoft_id_token_sign_in_uses_custom_verifier
    token = fake_jwt(
      "sub" => "ms-sub",
      "aud" => "microsoft-id",
      "email" => "microsoft@example.com",
      "name" => "Microsoft User",
      "email_verified" => true
    )
    auth = build_auth(
      social_providers: {
        microsoft: BetterAuth::SocialProviders.microsoft(
          client_id: "microsoft-id",
          verify_id_token: ->(_token, _nonce = nil) { true }
        )
      }
    )

    result = auth.api.sign_in_social(
      body: {
        provider: "microsoft",
        idToken: {
          token: token,
          accessToken: "microsoft-access"
        }
      }
    )

    assert_equal false, result.fetch(:redirect)
    assert_equal "microsoft@example.com", result.fetch(:user).fetch("email")
  end

  def test_link_social_rejects_untrusted_callback_urls
    auth = build_auth(
      trusted_origins: ["http://localhost:3000"],
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(_data) { "https://github.example/oauth" }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "link-url@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.link_social(
        headers: {"cookie" => cookie},
        body: {
          provider: "github",
          callbackURL: "https://evil.example/app",
          errorCallbackURL: "/error"
        }
      )
    end

    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_CALLBACK_URL"], error.message
  end

  def test_link_social_account_alias_matches_upstream_api_name
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(_data) { "https://github.example/oauth" }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "link-upstream@example.com")

    result = auth.api.link_social_account(
      headers: {"cookie" => cookie},
      body: {
        provider: "github",
        callbackURL: "/dashboard",
        disableRedirect: true
      }
    )

    assert_equal "https://github.example/oauth", result[:url]
    assert_equal false, result[:redirect]
  end

  def test_sign_in_social_preserves_safe_additional_state_and_reserved_fields
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" }
        }
      }
    )

    response = auth.api.sign_in_social(
      body: {
        provider: "github",
        callbackURL: "/app",
        additionalData: {
          invitedBy: "user-123",
          callbackURL: "/evil",
          errorURL: "/evil-error",
          newUserURL: "/evil-new-user",
          codeVerifier: "evil-verifier",
          requestSignUp: true
        }
      }
    )
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last
    data = BetterAuth::Crypto.verify_jwt(state, SECRET)

    assert_equal "/app", data.fetch("callbackURL")
    assert_equal "user-123", data.fetch("invitedBy")
    refute_equal "evil-verifier", data.fetch("codeVerifier")
    refute data.key?("errorURL")
    refute data.key?("newUserURL")
    refute data["requestSignUp"]
  end

  def test_sign_in_social_rejects_implicit_signup_when_provider_disables_it
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          disableImplicitSignUp: true,
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { {accessToken: "oauth-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-disabled-signup",
                email: "disabled-signup@example.com",
                name: "Disabled Signup",
                emailVerified: true
              }
            }
          }
        }
      }
    )
    response = auth.api.sign_in_social(body: {provider: "github", callbackURL: "/app", disableRedirect: true})
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_includes headers.fetch("location"), "error=signup_disabled"
    assert_nil auth.context.internal_adapter.find_user_by_email("disabled-signup@example.com")
  end

  def test_sign_in_social_allows_requested_signup_when_implicit_signup_is_disabled
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          disableImplicitSignUp: true,
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { {accessToken: "oauth-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-requested-signup",
                email: "requested-signup@example.com",
                name: "Requested Signup",
                emailVerified: true
              }
            }
          }
        }
      }
    )
    response = auth.api.sign_in_social(body: {provider: "github", callbackURL: "/app", requestSignUp: true, disableRedirect: true})
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/app", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("requested-signup@example.com")
  end

  def test_callback_rejects_invalid_signed_state
    called = false
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          validate_authorization_code: ->(_data) { called = true },
          get_user_info: ->(_tokens) { raise "unexpected user info call" }
        }
      }
    )

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: "not-a-valid-state"},
      as_response: true
    )

    assert_equal 302, status
    assert_includes headers.fetch("location"), "error=state_not_found"
    refute called
  end

  def test_rack_callback_rejects_valid_state_without_initiating_state_cookie
    called = false
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) {
            called = true
            {accessToken: "oauth-access"}
          },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-state-cookie",
                email: "state-cookie@example.com",
                name: "State Cookie",
                emailVerified: true
              }
            }
          }
        }
      }
    )
    _status, _headers, body = auth.call(rack_env("POST", "/api/auth/sign-in/social", body: {provider: "github", callbackURL: "/app", disableRedirect: true}))
    state = URI.decode_www_form(URI.parse(JSON.parse(body.join).fetch("url")).query).assoc("state").last

    status, headers, _body = auth.call(rack_env("GET", "/api/auth/callback/github?code=code&state=#{URI.encode_www_form_component(state)}"))

    assert_equal 302, status
    assert_includes headers.fetch("location"), "error=state_mismatch"
    refute headers.fetch("set-cookie", "").include?("better-auth.session_token=")
    refute called
    assert_includes headers.fetch("set-cookie"), "better-auth.state="
  end

  def test_callback_redirects_new_social_user_to_new_user_callback_url
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { {accessToken: "oauth-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-new-user-callback",
                email: "new-user-callback@example.com",
                name: "New User Callback",
                emailVerified: true
              }
            }
          }
        }
      }
    )

    response = auth.api.sign_in_social(
      body: {
        provider: "github",
        callbackURL: "/app",
        newUserCallbackURL: "/welcome",
        disableRedirect: true
      }
    )
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/welcome", headers.fetch("location")
  end

  def test_callback_rejects_provider_user_without_email
    auth = build_auth(
      social_providers: {
        discord: {
          id: "discord",
          create_authorization_url: ->(data) { "https://discord.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { {accessToken: "discord-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "discord-no-email",
                email: nil,
                name: "Phone Only",
                emailVerified: false
              }
            }
          }
        }
      }
    )
    response = auth.api.sign_in_social(body: {provider: "discord", callbackURL: "/app", disableRedirect: true})
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "discord"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_includes headers.fetch("location"), "error=email_not_found"
    assert_nil auth.context.internal_adapter.find_user_by_email("discord-no-email@example.com")
  end

  def test_callback_rejects_signup_when_provider_disables_signup
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          disableSignUp: true,
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { {accessToken: "oauth-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-signup-disabled",
                email: "signup-disabled@example.com",
                name: "Signup Disabled",
                emailVerified: true
              }
            }
          }
        }
      }
    )

    response = auth.api.sign_in_social(body: {provider: "github", callbackURL: "/app", requestSignUp: true, disableRedirect: true})
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_includes headers.fetch("location"), "error=signup_disabled"
    assert_nil auth.context.internal_adapter.find_user_by_email("signup-disabled@example.com")
  end

  def test_vercel_callback_creates_user_and_existing_user_uses_callback_url
    token_exchange = ->(_url, _form, _headers = {}) { {"access_token" => "vercel-access"} }
    provider = BetterAuth::SocialProviders.vercel(
      client_id: "vercel-id",
      client_secret: "vercel-secret",
      get_user_info: ->(_tokens) {
        {
          "sub" => "vercel-sub",
          "preferred_username" => "vercel-user",
          "email" => "vercel-callback@example.com",
          "email_verified" => true
        }
      }
    )
    auth = build_auth(social_providers: {vercel: provider})

    BetterAuth::SocialProviders::Base.stub(:post_form_json, token_exchange) do
      response = auth.api.sign_in_social(body: {provider: "vercel", callbackURL: "/app", newUserCallbackURL: "/welcome", disableRedirect: true})
      state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last
      status, headers, _body = auth.api.callback_oauth(
        params: {providerId: "vercel"},
        query: {code: "code", state: state},
        as_response: true
      )

      assert_equal 302, status
      assert_equal "/welcome", headers.fetch("location")
      assert_equal "vercel-user", auth.context.internal_adapter.find_user_by_email("vercel-callback@example.com")[:user]["name"]

      second_response = auth.api.sign_in_social(body: {provider: "vercel", callbackURL: "/app", newUserCallbackURL: "/welcome", disableRedirect: true})
      second_state = URI.decode_www_form(URI.parse(second_response[:url]).query).assoc("state").last
      status, headers, _body = auth.api.callback_oauth(
        params: {providerId: "vercel"},
        query: {code: "code", state: second_state},
        as_response: true
      )

      assert_equal 302, status
      assert_equal "/app", headers.fetch("location")
    end
  end

  def test_railway_callback_creates_user_with_unverified_email
    token_exchange = ->(_url, _form, _headers = {}) { {"access_token" => "railway-access"} }
    provider = BetterAuth::SocialProviders.railway(
      client_id: "railway-id",
      client_secret: "railway-secret",
      get_user_info: ->(_tokens) {
        {
          "sub" => "railway-sub",
          "name" => "Railway User",
          "email" => "railway-callback@example.com"
        }
      }
    )
    auth = build_auth(social_providers: {railway: provider})

    BetterAuth::SocialProviders::Base.stub(:post_form_json, token_exchange) do
      response = auth.api.sign_in_social(body: {provider: "railway", callbackURL: "/app", disableRedirect: true})
      state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last
      status, headers, _body = auth.api.callback_oauth(
        params: {providerId: "railway"},
        query: {code: "code", state: state},
        as_response: true
      )

      assert_equal 302, status
      assert_equal "/app", headers.fetch("location")
      user = auth.context.internal_adapter.find_user_by_email("railway-callback@example.com")[:user]
      assert_equal "Railway User", user["name"]
      assert_equal false, user["emailVerified"]
    end
  end

  def test_sign_in_social_rejects_unverified_implicit_linking_from_untrusted_provider
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-unverified-link",
                email: "unverified-link@example.com",
                name: "Unverified Link",
                emailVerified: false
              }
            }
          }
        }
      }
    )
    sign_up_cookie(auth, email: "unverified-link@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_social(body: {provider: "github", idToken: {token: "id-token"}})
    end

    assert_equal "account not linked", error.message
    user = auth.context.internal_adapter.find_user_by_email("unverified-link@example.com")[:user]
    assert_empty auth.context.internal_adapter.find_accounts(user["id"]).reject { |account| account["providerId"] == "credential" }
  end

  def test_link_social_with_id_token_links_account_to_current_user
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-linked",
                email: "link@example.com",
                name: "Linked",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "link@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    result = auth.api.link_social(
      headers: {"cookie" => cookie},
      body: {provider: "github", idToken: {token: "id-token", accessToken: "access-token"}}
    )

    assert_equal({url: "", status: true, redirect: false}, result)
    account = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "github" }
    assert_equal "gh-linked", account["accountId"]
  end

  def test_link_social_with_verified_matching_email_marks_user_email_verified
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-verified-link",
                email: "verified-link@example.com",
                name: "Verified Link",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "verified-link@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    auth.api.link_social(
      headers: {"cookie" => cookie},
      body: {provider: "github", idToken: {token: "id-token"}}
    )

    user = auth.context.internal_adapter.find_user_by_id(user_id)
    assert_equal true, user["emailVerified"]
  end

  def test_link_social_with_unverified_matching_email_leaves_user_unverified
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-unverified-link",
                email: "unverified-link@example.com",
                name: "Unverified Link",
                emailVerified: false
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "unverified-link@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    auth.api.link_social(
      headers: {"cookie" => cookie},
      body: {provider: "github", idToken: {token: "id-token"}}
    )

    user = auth.context.internal_adapter.find_user_by_id(user_id)
    assert_equal false, user["emailVerified"]
  end

  def test_link_social_with_verified_different_email_does_not_mark_user_verified
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-different-email",
                email: "provider-different@example.com",
                name: "Different Email",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: ["github"], allow_different_emails: true}}
    )
    cookie = sign_up_cookie(auth, email: "different-email@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    auth.api.link_social(
      headers: {"cookie" => cookie},
      body: {provider: "github", idToken: {token: "id-token"}}
    )

    user = auth.context.internal_adapter.find_user_by_id(user_id)
    assert_equal false, user["emailVerified"]
  end

  def test_link_social_with_already_verified_user_remains_verified
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-already-verified",
                email: "already-verified@example.com",
                name: "Already Verified",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "already-verified@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.update_user(user_id, "emailVerified" => true)

    auth.api.link_social(
      headers: {"cookie" => cookie},
      body: {provider: "github", idToken: {token: "id-token"}}
    )

    user = auth.context.internal_adapter.find_user_by_id(user_id)
    assert_equal true, user["emailVerified"]
  end

  def test_link_social_redirect_flow_links_account_on_callback
    issued_code_verifier = nil
    callback_code_verifier = nil
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: lambda do |data|
            issued_code_verifier = data[:codeVerifier]
            "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}"
          end,
          validate_authorization_code: lambda do |data|
            callback_code_verifier = data[:codeVerifier]
            {accessToken: "linked-access", refreshToken: "linked-refresh"}
          end,
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-redirect-linked",
                email: "redirect-link@example.com",
                name: "Redirect Link",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "redirect-link@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    response = auth.api.link_social(
      headers: {"cookie" => cookie},
      body: {provider: "github", callbackURL: "/linked", disableRedirect: true}
    )
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/linked", headers.fetch("location")
    refute_includes headers.fetch("set-cookie", ""), "better-auth.session_token="
    account = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "github" }
    assert_equal "gh-redirect-linked", account["accountId"]
    assert_equal "linked-refresh", account["refreshToken"]
    assert_match(/\A[0-9a-f]{32}\z/, issued_code_verifier)
    assert_equal issued_code_verifier, callback_code_verifier
  end

  def test_link_social_redirect_flow_passes_custom_scopes_to_provider
    captured_scopes = nil
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: lambda do |data|
            captured_scopes = data[:scopes]
            "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}"
          end,
          validate_authorization_code: ->(_data) { raise "unexpected callback" },
          get_user_info: ->(_tokens) { raise "unexpected user info" }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "link-scopes@example.com")

    result = auth.api.link_social(
      headers: {"cookie" => cookie},
      body: {
        provider: "github",
        callbackURL: "/linked",
        disableRedirect: true,
        scopes: ["repo", "user:email"]
      }
    )

    assert_equal ["repo", "user:email"], captured_scopes
    assert_equal false, result[:redirect]
    assert_includes result[:url], "github.example/oauth"
  end

  def test_link_social_redirect_flow_links_account_when_email_casing_differs
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { {accessToken: "linked-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-casing",
                email: "Casing-Link@Example.com",
                name: "Casing Link",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "casing-link@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    response = auth.api.link_social(
      headers: {"cookie" => cookie},
      body: {provider: "github", callbackURL: "/linked", disableRedirect: true}
    )
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/linked", headers.fetch("location")
    account = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "github" }
    assert_equal "gh-casing", account["accountId"]
    assert_equal true, auth.context.internal_adapter.find_user_by_id(user_id)["emailVerified"]
  end

  def test_sign_in_social_verified_provider_implicitly_links_without_trusted_provider
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-verified-implicit",
                email: "verified-implicit@example.com",
                name: "Verified Implicit",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: []}}
    )
    sign_up_cookie(auth, email: "verified-implicit@example.com")

    result = auth.api.sign_in_social(body: {provider: "github", idToken: {token: "id-token"}})

    assert_equal false, result.fetch(:redirect)
    user = auth.context.internal_adapter.find_user_by_email("verified-implicit@example.com")[:user]
    assert_equal true, user["emailVerified"]
    account = auth.context.internal_adapter.find_accounts(user["id"]).find { |entry| entry["providerId"] == "github" }
    assert_equal "gh-verified-implicit", account["accountId"]
  end

  def test_sign_in_social_disable_implicit_linking_blocks_existing_user_but_allows_new_user
    provider_user = {
      id: "gh-existing-implicit",
      email: "implicit-block-account@example.com",
      name: "Implicit Block",
      emailVerified: true
    }
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) { {user: provider_user} }
        }
      },
      account: {account_linking: {disable_implicit_linking: true, trusted_providers: ["github"]}}
    )
    sign_up_cookie(auth, email: "implicit-block-account@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_social(body: {provider: "github", idToken: {token: "id-token"}})
    end
    assert_equal "account not linked", error.message

    provider_user = {
      id: "gh-new-implicit",
      email: "new-implicit-user@example.com",
      name: "New Implicit",
      emailVerified: true
    }
    result = auth.api.sign_in_social(body: {provider: "github", idToken: {token: "id-token"}})
    assert_equal "new-implicit-user@example.com", result.fetch(:user).fetch("email")
  end

  def test_sign_in_social_override_user_info_updates_existing_user
    provider_user = {
      id: "gh-override",
      email: "override-social@example.com",
      name: "Updated Social Name",
      image: "https://example.com/updated.png",
      emailVerified: true
    }
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          overrideUserInfoOnSignIn: true,
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) { {user: provider_user} }
        }
      },
      account: {account_linking: {trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "override-social@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.update_user(user_id, "name" => "Initial Name", "emailVerified" => false)

    auth.api.sign_in_social(body: {provider: "github", idToken: {token: "id-token", accessToken: "access-token"}})

    user = auth.context.internal_adapter.find_user_by_id(user_id)
    assert_equal "Updated Social Name", user["name"]
    assert_equal "https://example.com/updated.png", user["image"]
    assert_equal true, user["emailVerified"]
  end

  def test_sign_in_social_does_not_update_linked_account_tokens_when_disabled
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-no-update",
                email: "no-update-account@example.com",
                name: "No Update",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {update_account_on_sign_in: false, account_linking: {trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "no-update-account@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      "providerId" => "github",
      "accountId" => "gh-no-update",
      "userId" => user_id,
      "accessToken" => "preserved-access"
    )

    auth.api.sign_in_social(body: {provider: "github", idToken: {token: "new-id-token", accessToken: "new-access"}})

    stored = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["id"] == account["id"] }
    assert_equal "preserved-access", stored["accessToken"]
    assert_nil stored["idToken"]
  end

  def test_sign_in_social_updates_linked_account_tokens_by_default
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-update",
                email: "update-account@example.com",
                name: "Update Account",
                emailVerified: true
              }
            }
          }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "update-account@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      "providerId" => "github",
      "accountId" => "gh-update",
      "userId" => user_id,
      "accessToken" => "old-access"
    )

    auth.api.sign_in_social(body: {provider: "github", idToken: {token: "new-id-token", accessToken: "new-access"}})

    stored = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["id"] == account["id"] }
    assert_equal "new-access", stored["accessToken"]
    assert_equal "new-id-token", stored["idToken"]
  end

  def test_link_social_redirect_flow_rejects_account_owned_by_another_user
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { {accessToken: "linked-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-owned",
                email: "owner-one@example.com",
                name: "Owned",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: ["github"], allow_different_emails: true}}
    )
    first_cookie = sign_up_cookie(auth, email: "owner-one@example.com")
    first_user_id = auth.api.get_session(headers: {"cookie" => first_cookie})[:user]["id"]
    auth.context.internal_adapter.create_account({
      "providerId" => "github",
      "accountId" => "gh-owned",
      "userId" => first_user_id
    })
    second_cookie = sign_up_cookie(auth, email: "owner-two@example.com")

    response = auth.api.link_social(
      headers: {"cookie" => second_cookie},
      body: {provider: "github", callbackURL: "/linked", disableRedirect: true}
    )
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_includes headers.fetch("location"), "error=account_already_linked_to_different_user"
  end

  def test_link_social_rejects_when_account_linking_is_disabled
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-disabled-link",
                email: "disabled-link@example.com",
                name: "Disabled Link",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {enabled: false, trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "disabled-link@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.link_social(
        headers: {"cookie" => cookie},
        body: {provider: "github", idToken: {token: "id-token"}}
      )
    end

    assert_equal "Account not linked - untrusted provider", error.message
  end

  def test_generic_provider_without_id_token_verifier_rejects_id_token_sign_in
    provider = BetterAuth::SocialProviders::Base.oauth_provider(
      id: "example",
      name: "Example",
      client_id: "id",
      client_secret: "secret",
      authorization_endpoint: "https://provider.example/authorize",
      token_endpoint: "https://provider.example/token",
      profile_map: ->(profile) {
        {
          id: profile.fetch("sub"),
          email: profile.fetch("email"),
          name: profile.fetch("name"),
          emailVerified: true
        }
      }
    )
    auth = build_auth(social_providers: {example: provider})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_social(
        body: {
          provider: "example",
          idToken: {
            token: fake_jwt("sub" => "example-sub", "email" => "example@example.com", "name" => "Example")
          }
        }
      )
    end

    assert_equal 404, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["ID_TOKEN_NOT_SUPPORTED"], error.message
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Social User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def fake_jwt(payload)
    encoded_header = Base64.urlsafe_encode64(JSON.generate({"alg" => "none"}), padding: false)
    encoded_payload = Base64.urlsafe_encode64(JSON.generate(payload), padding: false)
    "#{encoded_header}.#{encoded_payload}."
  end

  def rack_env(method, path, body: nil, cookie: nil)
    path_info, query_string = path.split("?", 2)
    payload = body ? JSON.generate(body) : ""
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path_info,
      "QUERY_STRING" => query_string || "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(payload),
      "CONTENT_TYPE" => body ? "application/json" : nil,
      "CONTENT_LENGTH" => payload.bytesize.to_s,
      "HTTP_COOKIE" => cookie,
      "HTTP_ORIGIN" => "http://localhost:3000"
    }.compact
  end
end

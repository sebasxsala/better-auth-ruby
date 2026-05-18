# frozen_string_literal: true

require "uri"
require_relative "../../test_helper"

class OAuthProviderPromptTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_prompt_login_redirects_to_login_even_with_existing_session_and_consent
    auth = build_auth(scopes: ["openid", "profile"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["authorization_code"], response_types: ["code"], scope: "openid profile")
    issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile")

    status, headers, = authorize_response(auth, cookie, client, scope: "openid profile", prompt: "login")

    assert_equal 302, status
    location = headers.fetch("location")
    assert_match(%r{\A/login\?}, location)
    params = Rack::Utils.parse_query(URI.parse(location).query)
    assert_equal "login", params["prompt"]
    assert params["sig"]
    assert params["exp"]
  end

  def test_prompt_create_without_session_redirects_to_signup_page
    auth = build_auth(scopes: ["openid"], signup: {page: "/signup"})
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["authorization_code"], response_types: ["code"], scope: "openid")

    status, headers, = authorize_response(auth, nil, client, scope: "openid", prompt: "create")

    assert_equal 302, status
    assert_match(%r{\A/signup\?}, headers.fetch("location"))
  end

  def test_prompt_none_cannot_be_combined_with_select_account
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["authorization_code"], response_types: ["code"], scope: "openid")

    status, headers, = authorize_response(auth, cookie, client, scope: "openid", prompt: "none select_account")
    params = extract_redirect_params(headers)

    assert_equal 302, status
    assert_equal "invalid_request", params["error"]
    assert_match(/prompt/, params["error_description"])
    assert_equal "http://localhost:3000", params["iss"]
  end

  def test_prompt_none_with_post_login_requirement_returns_interaction_required
    auth = build_auth(
      scopes: ["openid"],
      post_login: {
        should_redirect: ->(_info) { true },
        page: "/setup"
      }
    )
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["authorization_code"], response_types: ["code"], scope: "openid")

    status, headers, = authorize_response(auth, cookie, client, scope: "openid", prompt: "none")
    params = extract_redirect_params(headers)

    assert_equal 302, status
    assert_equal "interaction_required", params["error"]
    assert_equal "http://localhost:3000", params["iss"]
  end
end

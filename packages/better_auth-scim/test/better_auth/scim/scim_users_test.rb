# frozen_string_literal: true

require_relative "../scim_test_helper"

class BetterAuthPluginsScimUsersTest < Minitest::Test
  include SCIMTestHelper

  def test_scim_user_crud_filter_patch_and_delete
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)

    created = auth.api.create_scim_user(
      headers: headers,
      body: {
        userName: "scim@example.com",
        externalId: "external-1",
        name: {givenName: "SCIM", familyName: "User"}
      }
    )
    assert_equal "scim@example.com", created.fetch(:userName)
    assert_equal "external-1", created.fetch(:externalId)
    assert_equal true, created.fetch(:active)
    assert created.fetch(:meta).fetch(:created)
    assert created.fetch(:meta).fetch(:lastModified)

    listed = auth.api.list_scim_users(headers: headers, query: {filter: 'userName eq "SCIM@example.com"'})
    assert_equal 1, listed.fetch(:totalResults)

    fetched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "SCIM User", fetched.fetch(:displayName)

    updated = auth.api.update_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {userName: "updated-username", externalId: "external-2", name: {formatted: "Updated User"}, emails: [{value: "updated@example.com"}]}
    )
    assert_equal "updated@example.com", updated.fetch(:userName)
    assert_equal "external-2", updated.fetch(:externalId)
    assert_equal "Updated User", updated.fetch(:displayName)

    patch_status = auth.api.patch_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "replace", path: "userName", value: "patched@example.com"}]},
      return_status: true
    )
    assert_equal 204, patch_status.fetch(:status)
    patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "patched@example.com", patched.fetch(:userName)
    assert_equal true, patched.fetch(:active)

    deleted = auth.api.delete_scim_user(headers: headers, params: {userId: created.fetch(:id)}, return_status: true)
    assert_equal 204, deleted.fetch(:status)
  end

  def test_scim_list_users_returns_upstream_list_response_shape_and_order
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)

    user_a = auth.api.create_scim_user(headers: headers, body: {userName: "user-a@example.com"})
    user_b = auth.api.create_scim_user(headers: headers, body: {userName: "user-b@example.com"})
    users = auth.api.list_scim_users(headers: headers)

    assert_equal ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], users.fetch(:schemas)
    assert_equal 2, users.fetch(:itemsPerPage)
    assert_equal 1, users.fetch(:startIndex)
    assert_equal 2, users.fetch(:totalResults)
    assert_equal [user_a, user_b], users.fetch(:Resources)
  end

  def test_scim_list_users_supports_start_index_and_count_pagination
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "paged"}).fetch(:scimToken)
    headers = bearer(token)

    auth.api.create_scim_user(headers: headers, body: {userName: "charlie@example.com"})
    auth.api.create_scim_user(headers: headers, body: {userName: "alpha@example.com"})
    auth.api.create_scim_user(headers: headers, body: {userName: "bravo@example.com"})

    page = auth.api.list_scim_users(headers: headers, query: {startIndex: "2", count: "1"})
    assert_equal 3, page.fetch(:totalResults)
    assert_equal 2, page.fetch(:startIndex)
    assert_equal 1, page.fetch(:itemsPerPage)
    assert_equal ["bravo@example.com"], page.fetch(:Resources).map { |user| user.fetch(:userName) }

    beyond = auth.api.list_scim_users(headers: headers, query: {startIndex: "10", count: "2"})
    assert_equal 3, beyond.fetch(:totalResults)
    assert_equal 10, beyond.fetch(:startIndex)
    assert_equal 0, beyond.fetch(:itemsPerPage)
    assert_equal [], beyond.fetch(:Resources)
  end

  def test_scim_list_users_paginates_filtered_results
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "filtered-page"}).fetch(:scimToken)
    headers = bearer(token)

    auth.api.create_scim_user(headers: headers, body: {userName: "match@example.com"})
    auth.api.create_scim_user(headers: headers, body: {userName: "other@example.com"})

    page = auth.api.list_scim_users(headers: headers, query: {filter: 'userName eq "MATCH@example.com"', startIndex: 1, count: 1})
    assert_equal 1, page.fetch(:totalResults)
    assert_equal 1, page.fetch(:startIndex)
    assert_equal 1, page.fetch(:itemsPerPage)
    assert_equal ["match@example.com"], page.fetch(:Resources).map { |user| user.fetch(:userName) }
  end

  def test_scim_list_users_orders_by_user_name
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "sort-test"}).fetch(:scimToken)
    headers = bearer(token)

    auth.api.create_scim_user(headers: headers, body: {userName: "zebra@example.com"})
    auth.api.create_scim_user(headers: headers, body: {userName: "alpha@example.com"})

    listed = auth.api.list_scim_users(headers: headers)
    names = listed.fetch(:Resources).map { |user| user.fetch(:userName) }
    assert_equal %w[alpha@example.com zebra@example.com], names
  end

  def test_scim_filters_only_user_name_and_rejects_unsupported_filters
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)
    auth.api.create_scim_user(headers: headers, body: {userName: "a@example.com", externalId: "external-a"})
    auth.api.create_scim_user(headers: headers, body: {userName: "b@example.com", externalId: "external-b"})

    listed = auth.api.list_scim_users(headers: headers, query: {filter: 'userName eq "B@example.com"'})
    assert_equal 1, listed.fetch(:totalResults)
    assert_equal "b@example.com", listed.fetch(:Resources).first.fetch(:userName)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_scim_users(headers: headers, query: {filter: 'userName co "example.com"'})
    end
    assert_equal 400, error.status_code
    assert_equal 'The operator "co" is not supported', error.message

    attribute_error = assert_raises(BetterAuth::APIError) do
      auth.api.list_scim_users(headers: headers, query: {filter: 'externalId eq "external-b"'})
    end
    assert_equal 400, attribute_error.status_code
    assert_equal "The attribute \"externalId\" is not supported", attribute_error.message

    %w[ne co sw ew pr].each do |operator|
      error = assert_raises(BetterAuth::APIError) do
        auth.api.list_scim_users(headers: headers, query: {filter: %(userName #{operator} "b@example.com")})
      end
      assert_equal 400, error.status_code
      assert_equal %(The operator "#{operator}" is not supported), error.message
    end

    missing_value = assert_raises(BetterAuth::APIError) do
      auth.api.list_scim_users(headers: headers, query: {filter: "userName eq"})
    end
    assert_equal 400, missing_value.status_code
    assert_equal "Invalid filter expression", missing_value.message

    malformed = assert_raises(BetterAuth::APIError) do
      auth.api.list_scim_users(headers: headers, query: {filter: "("})
    end
    assert_equal 400, malformed.status_code
    assert_equal "Invalid filter expression", malformed.message
  end

  def test_scim_invalid_filter_returns_error_even_when_provider_has_no_users
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "empty"}).fetch(:scimToken)

    status, _headers, body = auth.api.list_scim_users(as_response: true, headers: bearer(token), query: {filter: 'externalId eq "x"'})
    error = JSON.parse(body.join)

    assert_equal 400, status
    assert_equal ["urn:ietf:params:scim:api:messages:2.0:Error"], error.fetch("schemas")
    assert_equal "400", error.fetch("status")
    assert_equal "The attribute \"externalId\" is not supported", error.fetch("detail")
    assert_equal "invalidFilter", error.fetch("scimType")
  end

  def test_scim_default_provider_and_invalid_tokens
    scim_token = Base64.urlsafe_encode64("the-scim-token:the-scim-provider", padding: false)
    auth = build_auth(default_scim: [{providerId: "the-scim-provider", scimToken: "the-scim-token"}])

    created = auth.api.create_scim_user(headers: bearer(scim_token), body: {userName: "default@example.com"})
    assert_equal created, auth.api.get_scim_user(headers: bearer(scim_token), params: {userId: created.fetch(:id)})
    assert_equal [created.fetch(:id)], auth.api.list_scim_users(headers: bearer(scim_token)).fetch(:Resources).map { |user| user.fetch(:id) }
    updated = auth.api.update_scim_user(headers: bearer(scim_token), params: {userId: created.fetch(:id)}, body: {userName: "updated-default@example.com"})
    assert_equal "updated-default@example.com", updated.fetch(:userName)
    assert_equal 204, auth.api.delete_scim_user(headers: bearer(scim_token), params: {userId: created.fetch(:id)}, return_status: true).fetch(:status)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: bearer("invalid-scim-token"), body: {userName: "bad@example.com"})
    end
    assert_equal 401, error.status_code
    assert_equal "Invalid SCIM token", error.message

    conflicting = build_auth(default_scim: [{providerId: "same-provider", scimToken: "default-token"}])
    cookie = sign_up_cookie(conflicting)
    db_token = conflicting.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "same-provider"}).fetch(:scimToken)
    default_precedence_error = assert_raises(BetterAuth::APIError) do
      conflicting.api.create_scim_user(headers: bearer(db_token), body: {userName: "db-token@example.com"})
    end
    assert_equal 401, default_precedence_error.status_code
  end

  def test_scim_default_provider_rejects_wrong_token_length_safely
    token_ok = Base64.urlsafe_encode64("secret-token:p", padding: false)
    token_bad = Base64.urlsafe_encode64("different-length-xx:p", padding: false)
    auth = build_auth(default_scim: [{providerId: "p", scimToken: "secret-token"}])

    created = auth.api.create_scim_user(headers: bearer(token_ok), body: {userName: "ok@example.com"})
    assert_equal "ok@example.com", created.fetch(:userName)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: bearer(token_bad), body: {userName: "no@example.com"})
    end
    assert_equal 401, error.status_code
    assert_equal "Invalid SCIM token", error.message
  end

  def test_scim_scopes_user_access_by_provider_and_deletes_users
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token_a = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "provider-a"}).fetch(:scimToken)
    token_b = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "provider-b"}).fetch(:scimToken)
    user_a = auth.api.create_scim_user(headers: bearer(token_a), body: {userName: "a@example.com"})
    user_b = auth.api.create_scim_user(headers: bearer(token_b), body: {userName: "b@example.com"})

    listed_a = auth.api.list_scim_users(headers: bearer(token_a))
    assert_equal [user_a.fetch(:id)], listed_a.fetch(:Resources).map { |user| user.fetch(:id) }

    not_found = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_user(headers: bearer(token_a), params: {userId: user_b.fetch(:id)})
    end
    assert_equal 404, not_found.status_code

    auth.api.delete_scim_user(headers: bearer(token_b), params: {userId: user_b.fetch(:id)}, return_status: true)
    deleted = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_user(headers: bearer(token_b), params: {userId: user_b.fetch(:id)})
    end
    assert_equal 404, deleted.status_code
  end

  def test_scim_delete_unlinks_only_current_provider_when_user_has_other_accounts
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token_a = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "provider-a"}).fetch(:scimToken)
    token_b = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "provider-b"}).fetch(:scimToken)

    user_a = auth.api.create_scim_user(headers: bearer(token_a), body: {userName: "shared@example.com", externalId: "external-a"})
    user_b = auth.api.create_scim_user(headers: bearer(token_b), body: {userName: "shared@example.com", externalId: "external-b"})
    assert_equal user_a.fetch(:id), user_b.fetch(:id)

    assert_equal 204, auth.api.delete_scim_user(headers: bearer(token_a), params: {userId: user_a.fetch(:id)}, return_status: true).fetch(:status)

    provider_a_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_user(headers: bearer(token_a), params: {userId: user_a.fetch(:id)})
    end
    assert_equal 404, provider_a_error.status_code

    still_linked = auth.api.get_scim_user(headers: bearer(token_b), params: {userId: user_b.fetch(:id)})
    assert_equal "shared@example.com", still_linked.fetch(:userName)
    assert_equal "external-b", still_linked.fetch(:externalId)
  end

  def test_scim_update_user_display_name_falls_back_to_selected_email
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "put-fallback"}).fetch(:scimToken)
    headers = bearer(token)
    created = auth.api.create_scim_user(headers: headers, body: {userName: "original@example.com"})

    updated = auth.api.update_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {userName: "external-id", emails: [{value: "selected@example.com"}]}
    )

    assert_equal "selected@example.com", updated.fetch(:userName)
    assert_equal "selected@example.com", updated.fetch(:displayName)
    assert_equal({formatted: "selected@example.com"}, updated.fetch(:name))
  end

  def test_scim_org_scoping_empty_lists_and_missing_or_anonymous_access
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    org_a = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Org A", slug: "org-a"})
    org_b = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Org B", slug: "org-b"})
    token_a = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "provider-a", organizationId: org_a.fetch("id")}).fetch(:scimToken)
    token_b = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "provider-b", organizationId: org_b.fetch("id")}).fetch(:scimToken)

    assert_equal 0, auth.api.list_scim_users(headers: bearer(token_a)).fetch(:totalResults)
    user_a = auth.api.create_scim_user(headers: bearer(token_a), body: {userName: "org-a@example.com"})
    assert_equal [], auth.api.list_scim_users(headers: bearer(token_b)).fetch(:Resources)
    assert_equal [user_a.fetch(:id)], auth.api.list_scim_users(headers: bearer(token_a)).fetch(:Resources).map { |user| user.fetch(:id) }

    assert_equal 401, auth.api.list_scim_users(as_response: true).first
    assert_equal 401, auth.api.get_scim_user(as_response: true, params: {userId: user_a.fetch(:id)}).first
    assert_equal 401, auth.api.delete_scim_user(as_response: true, params: {userId: user_a.fetch(:id)}).first

    missing_get = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_user(headers: bearer(token_a), params: {userId: "missing"})
    end
    assert_equal 404, missing_get.status_code

    missing_delete = assert_raises(BetterAuth::APIError) do
      auth.api.delete_scim_user(headers: bearer(token_a), params: {userId: "missing"})
    end
    assert_equal 404, missing_delete.status_code
  end

  def test_scim_org_scoped_get_only_allows_same_provider_and_organization
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    org_a = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Org A", slug: "org-a"})
    org_b = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Org B", slug: "org-b"})
    token_a = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "provider-a", organizationId: org_a.fetch("id")}).fetch(:scimToken)
    token_b = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "provider-b", organizationId: org_b.fetch("id")}).fetch(:scimToken)

    user_a = auth.api.create_scim_user(headers: bearer(token_a), body: {userName: "org-a-user@example.com"})
    user_b = auth.api.create_scim_user(headers: bearer(token_b), body: {userName: "org-b-user@example.com"})

    assert_equal user_a, auth.api.get_scim_user(headers: bearer(token_a), params: {userId: user_a.fetch(:id)})
    assert_equal user_b, auth.api.get_scim_user(headers: bearer(token_b), params: {userId: user_b.fetch(:id)})

    org_b_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_user(headers: bearer(token_b), params: {userId: user_a.fetch(:id)})
    end
    assert_equal 404, org_b_error.status_code
    assert_equal "User not found", org_b_error.message

    org_a_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_user(headers: bearer(token_a), params: {userId: user_b.fetch(:id)})
    end
    assert_equal 404, org_a_error.status_code
    assert_equal "User not found", org_a_error.message
  end
end

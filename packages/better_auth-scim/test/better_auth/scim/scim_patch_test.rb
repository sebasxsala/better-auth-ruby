# frozen_string_literal: true

require_relative "../scim_test_helper"

class BetterAuthPluginsScimPatchTest < Minitest::Test
  include SCIMTestHelper

  def test_scim_patch_matches_upstream_supported_operations
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)
    created = auth.api.create_scim_user(
      headers: headers,
      body: {userName: "patch@example.com", externalId: "external-1", name: {givenName: "Patch", familyName: "User"}}
    )

    auth.api.patch_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [
          {op: "replace", path: "/userName", value: "patched@example.com"},
          {op: "add", path: "/externalId", value: "external-2"},
          {op: "REPLACE", path: "/name/givenName", value: "Patched"},
          {op: "ADD", path: "/name/familyName", value: "Person"}
        ]
      },
      return_status: true
    )
    patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "patched@example.com", patched.fetch(:userName)
    assert_equal "external-2", patched.fetch(:externalId)
    assert_equal "Patched Person", patched.fetch(:displayName)

    auth.api.patch_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [
          {op: "replace", path: "name", value: {givenName: "Nested", familyName: "Name"}},
          {op: "add", path: "name", value: {givenName: "Nested", familyName: "Name"}},
          {value: {userName: "object@example.com", externalId: "external-3"}}
        ]
      },
      return_status: true
    )
    object_patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "object@example.com", object_patched.fetch(:userName)
    assert_equal "external-3", object_patched.fetch(:externalId)
    assert_equal "Nested Name", object_patched.fetch(:displayName)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "remove", path: "/externalId"}]}
      )
    end
    assert_equal 400, error.status_code
    assert_equal "No valid fields to update", error.message

    duplicate_add = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "add", path: "/name/formatted", value: "Nested Name"}]}
      )
    end
    assert_equal 400, duplicate_add.status_code
    assert_equal "No valid fields to update", duplicate_add.message
  end

  def test_scim_patch_supports_upstream_replace_and_add_variants
    %w[replace add].each do |operation|
      auth = build_auth
      cookie = sign_up_cookie(auth)
      token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
      headers = bearer(token)
      created = auth.api.create_scim_user(
        headers: headers,
        body: {
          userName: "#{operation}-variant@example.com",
          name: {formatted: "Juan Perez"},
          emails: [{value: "#{operation}-primary@example.com", primary: true}]
        }
      )

      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [
            {op: operation, path: "/externalId", value: "#{operation}-external"},
            {op: operation, path: "/userName", value: "#{operation}-updated@example.com"},
            {op: operation, path: "/name/givenName", value: operation.capitalize}
          ]
        },
        return_status: true
      )
      patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})

      assert_equal "#{operation}-updated@example.com", patched.fetch(:userName)
      assert_equal "#{operation}-external", patched.fetch(:externalId)
      assert_equal "#{operation.capitalize} Perez", patched.fetch(:displayName)
      assert_equal({formatted: "#{operation.capitalize} Perez"}, patched.fetch(:name))
    end
  end

  def test_scim_patch_given_name_three_word_display_name_matches_upstream_split
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)
    created = auth.api.create_scim_user(
      headers: headers,
      body: {userName: "three@example.com", name: {formatted: "Anne Marie Smith"}}
    )

    auth.api.patch_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{op: "replace", path: "/name/givenName", value: "Pat"}]
      },
      return_status: true
    )
    patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})

    assert_equal "Pat Marie Smith", patched.fetch(:displayName)
  end

  def test_scim_patch_supports_upstream_name_subattributes_and_nested_path_variants
    %w[replace add].each do |operation|
      auth = build_auth
      cookie = sign_up_cookie(auth)
      token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
      headers = bearer(token)
      created = auth.api.create_scim_user(headers: headers, body: {userName: "#{operation}-nested@example.com", name: {formatted: "Original Name"}})

      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [
            {op: operation, path: "/name/givenName", value: "Updated"},
            {op: operation, path: "/name/familyName", value: "Value"}
          ]
        },
        return_status: true
      )
      patched_subattributes = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
      assert_equal "Updated Value", patched_subattributes.fetch(:displayName)

      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [
            {op: operation, path: "name", value: {givenName: "Nested"}},
            {op: operation, path: "name", value: {familyName: "User"}},
            {op: operation, path: "userName", value: "#{operation}-nested-updated@example.com"}
          ]
        },
        return_status: true
      )
      patched_nested = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
      assert_equal "Nested User", patched_nested.fetch(:displayName)
      assert_equal "#{operation}-nested-updated@example.com", patched_nested.fetch(:userName)
    end
  end

  def test_scim_patch_supports_upstream_operations_without_explicit_path
    %w[replace add].each do |operation|
      auth = build_auth
      cookie = sign_up_cookie(auth)
      token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
      headers = bearer(token)
      created = auth.api.create_scim_user(headers: headers, body: {userName: "#{operation}-no-path@example.com"})

      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [
            {
              op: operation,
              value: {
                name: {formatted: "No Path Name"},
                userName: "#{operation}-no-path-updated@example.com"
              }
            }
          ]
        },
        return_status: true
      )
      patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})

      assert_equal "No Path Name", patched.fetch(:displayName)
      assert_equal "#{operation}-no-path-updated@example.com", patched.fetch(:userName)
    end
  end

  def test_scim_patch_supports_dot_name_paths_and_rejects_noop_patch
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)
    created = auth.api.create_scim_user(headers: headers, body: {userName: "patch-name@example.com", name: {formatted: "Patch User"}})

    auth.api.patch_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [
          {op: "replace", path: "name.givenName", value: "Given"},
          {op: "replace", path: "name.familyName", value: "Family"}
        ]
      },
      return_status: true
    )
    patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "Given Family", patched.fetch(:displayName)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "replace", path: "unknown", value: "ignored"}]}
      )
    end
    assert_equal 400, error.status_code
    assert_equal "No valid fields to update", error.message

    invalid_op = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "invalid", path: "userName", value: "ignored@example.com"}]}
      )
    end
    assert_equal 400, invalid_op.status_code
    assert_equal '[body.Operations.0.op] Invalid option: expected one of "replace"|"add"|"remove"', invalid_op.message
    assert_equal ["urn:ietf:params:scim:api:messages:2.0:Error"], invalid_op.body.fetch(:schemas)
    assert_equal "400", invalid_op.body.fetch(:status)
    assert_match(/body\.Operations\.0\.op/, invalid_op.body.fetch(:detail))

    non_string_op = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: 1, path: "userName", value: "ignored@example.com"}]}
      )
    end
    assert_equal 400, non_string_op.status_code
    assert_equal "[body.Operations.0.op] Invalid input: expected string", non_string_op.message
    assert_equal ["urn:ietf:params:scim:api:messages:2.0:Error"], non_string_op.body.fetch(:schemas)
  end

  def test_scim_patch_rejects_add_on_non_existing_path
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)
    created = auth.api.create_scim_user(headers: headers, body: {userName: "add-non-existing-path@example.com", name: {formatted: "Original Name"}})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{op: "add", path: "/nonExistentField", value: "Some Value"}]
        }
      )
    end
    assert_equal 400, error.status_code
    assert_equal "No valid fields to update", error.message
  end

  def test_scim_patch_rejects_excessive_operations
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)
    created = auth.api.create_scim_user(headers: headers, body: {userName: "too-many-ops@example.com"})
    operations = Array.new(101) { {op: "replace", path: "userName", value: "ignored@example.com"} }

    error = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: operations}
      )
    end
    assert_equal 400, error.status_code
    assert_equal "Too many SCIM patch operations", error.message
    assert_equal ["urn:ietf:params:scim:api:messages:2.0:Error"], error.body.fetch(:schemas)
  end

  def test_scim_patch_rejects_excessively_nested_values
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)
    created = auth.api.create_scim_user(headers: headers, body: {userName: "deep@example.com"})
    deep_value = {name: {a: {b: {c: {d: {e: {f: "too-deep"}}}}}}}

    error = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "replace", value: deep_value}]}
      )
    end
    assert_equal 400, error.status_code
    assert_equal "SCIM patch value is too deeply nested", error.message
    assert_equal ["urn:ietf:params:scim:api:messages:2.0:Error"], error.body.fetch(:schemas)
  end
end

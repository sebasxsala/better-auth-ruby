# frozen_string_literal: true

require_relative "../scim_test_helper"

class BetterAuthPluginsScimManagementTest < Minitest::Test
  include SCIMTestHelper

  def test_generates_plain_hashed_and_custom_scim_tokens
    plain = build_auth(store_scim_token: "plain")
    plain_cookie = sign_up_cookie(plain)
    plain_token = plain.api.generate_scim_token(headers: {"cookie" => plain_cookie}, body: {providerId: "plain-provider"})
    assert_kind_of String, plain_token.fetch(:scimToken)
    assert plain.api.create_scim_user(headers: bearer(plain_token.fetch(:scimToken)), body: {userName: "plain@example.com"})

    hashed = build_auth(store_scim_token: "hashed")
    hashed_cookie = sign_up_cookie(hashed)
    hashed_token = hashed.api.generate_scim_token(headers: {"cookie" => hashed_cookie}, body: {providerId: "hashed-provider"})
    stored = hashed.context.adapter.find_one(model: "scimProvider", where: [{field: "providerId", value: "hashed-provider"}])
    refute_equal hashed_token.fetch(:scimToken), stored.fetch("scimToken")
    assert_match(/\A[A-Za-z0-9_-]{43}\z/, stored.fetch("scimToken"))
    assert hashed.api.create_scim_user(headers: bearer(hashed_token.fetch(:scimToken)), body: {userName: "hashed@example.com"})

    custom = build_auth(store_scim_token: {hash: ->(token) { "custom:#{token}" }})
    custom_cookie = sign_up_cookie(custom)
    custom_token = custom.api.generate_scim_token(headers: {"cookie" => custom_cookie}, body: {providerId: "custom-provider"})
    assert custom.api.create_scim_user(headers: bearer(custom_token.fetch(:scimToken)), body: {userName: "custom@example.com"})
  end

  def test_default_scim_token_storage_is_hashed
    auth = build_auth
    cookie = sign_up_cookie(auth)
    response = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "default-hashed-provider"})
    stored = auth.context.adapter.find_one(model: "scimProvider", where: [{field: "providerId", value: "default-hashed-provider"}])

    refute_equal response.fetch(:scimToken), stored.fetch("scimToken")
    assert_match(/\A[A-Za-z0-9_-]{43}\z/, stored.fetch("scimToken"))
    assert_equal auth.api.get_session(headers: {"cookie" => cookie}).fetch(:user).fetch("id"), stored.fetch("userId")
    assert auth.api.create_scim_user(headers: bearer(response.fetch(:scimToken)), body: {userName: "default-hashed@example.com"})
  end

  def test_scim_provider_ownership_is_enabled_by_default_for_personal_providers
    auth = build_auth
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    other_cookie = sign_up_cookie(auth, "other@example.com")

    auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "personal-default"})

    assert_equal ["personal-default"], auth.api.list_scim_provider_connections(headers: {"cookie" => owner_cookie}).fetch(:providers).map { |provider| provider.fetch(:providerId) }
    assert_equal [], auth.api.list_scim_provider_connections(headers: {"cookie" => other_cookie}).fetch(:providers)

    get_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_provider_connection(headers: {"cookie" => other_cookie}, query: {providerId: "personal-default"})
    end
    assert_equal 403, get_error.status_code
    assert_equal "You must be the owner to access this provider", get_error.message

    delete_error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_scim_provider_connection(headers: {"cookie" => other_cookie}, body: {providerId: "personal-default"})
    end
    assert_equal 403, delete_error.status_code

    rotate_error = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => other_cookie}, body: {providerId: "personal-default"})
    end
    assert_equal 403, rotate_error.status_code
  end

  def test_scim_provider_ownership_can_be_disabled_for_legacy_shared_personal_providers
    auth = build_auth(provider_ownership: {enabled: false})
    owner_cookie = sign_up_cookie(auth, "legacy-owner@example.com")
    other_cookie = sign_up_cookie(auth, "legacy-other@example.com")

    auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "legacy-personal"})

    assert_equal ["legacy-personal"], auth.api.list_scim_provider_connections(headers: {"cookie" => other_cookie}).fetch(:providers).map { |provider| provider.fetch(:providerId) }
    assert_equal "legacy-personal", auth.api.get_scim_provider_connection(headers: {"cookie" => other_cookie}, query: {providerId: "legacy-personal"}).fetch(:providerId)
    assert_equal true, auth.api.delete_scim_provider_connection(headers: {"cookie" => other_cookie}, body: {providerId: "legacy-personal"}).fetch(:success)
  end

  def test_scim_tokens_use_upstream_envelope_storage_and_encrypted_modes
    encrypted = build_auth(store_scim_token: "encrypted")
    encrypted_cookie = sign_up_cookie(encrypted)
    encrypted_token = encrypted.api.generate_scim_token(headers: {"cookie" => encrypted_cookie}, body: {providerId: "encrypted-provider"})
    stored = encrypted.context.adapter.find_one(model: "scimProvider", where: [{field: "providerId", value: "encrypted-provider"}])

    refute_includes encrypted_token.fetch(:scimToken), "encrypted-provider"
    refute_equal encrypted_token.fetch(:scimToken), stored.fetch("scimToken")
    assert encrypted.api.create_scim_user(headers: bearer(encrypted_token.fetch(:scimToken)), body: {userName: "encrypted@example.com"})

    custom = build_auth(store_scim_token: {encrypt: ->(token) { "enc:#{token}" }, decrypt: ->(token) { token.delete_prefix("enc:") }})
    custom_cookie = sign_up_cookie(custom)
    custom_token = custom.api.generate_scim_token(headers: {"cookie" => custom_cookie}, body: {providerId: "custom-encrypted-provider"})
    assert custom.api.create_scim_user(headers: bearer(custom_token.fetch(:scimToken)), body: {userName: "custom-encrypted@example.com"})
  end

  def test_scim_rejects_corrupted_stored_encrypted_token_as_invalid_token
    auth = build_auth(store_scim_token: "encrypted")
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "corrupt-provider"}).fetch(:scimToken)
    provider = auth.context.adapter.find_one(model: "scimProvider", where: [{field: "providerId", value: "corrupt-provider"}])
    auth.context.adapter.update(model: "scimProvider", where: [{field: "id", value: provider.fetch("id")}], update: {scimToken: "not-encrypted"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: bearer(token), body: {userName: "corrupt@example.com"})
    end
    assert_equal 401, error.status_code
    assert_equal "Invalid SCIM token", error.message
  end

  def test_scim_after_token_generation_hook_receives_stored_provider_and_usable_token
    hook_payloads = []
    auth = build_auth(
      store_scim_token: "plain",
      after_scim_token_generated: ->(payload) { hook_payloads << payload }
    )
    cookie = sign_up_cookie(auth)

    response = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "hook-provider"})
    assert_kind_of String, response.fetch(:scimToken)
    assert_equal 1, hook_payloads.length

    payload = hook_payloads.first
    provider = payload.fetch(:scim_provider)
    assert_equal "hook-provider", provider.fetch("providerId")
    assert_kind_of String, provider.fetch("scimToken")
    refute_empty provider.fetch("scimToken")
    assert_equal response.fetch(:scimToken), payload.fetch(:scim_token)
    assert auth.api.create_scim_user(headers: bearer(response.fetch(:scimToken)), body: {userName: "hook-user@example.com"})
  end

  def test_scim_requires_org_plugin_and_membership_for_org_tokens
    no_org = build_auth
    no_org_cookie = sign_up_cookie(no_org)
    error = assert_raises(BetterAuth::APIError) do
      no_org.api.generate_scim_token(headers: {"cookie" => no_org_cookie}, body: {providerId: "okta", organizationId: "org-1"})
    end
    assert_equal 400, error.status_code
    assert_equal "Restricting a token to an organization requires the organization plugin", error.message

    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "SCIM Org", slug: "scim-org"})
    second_cookie = sign_up_cookie(auth, "other@example.com")

    forbidden = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => second_cookie}, body: {providerId: "okta", organizationId: org.fetch("id")})
    end
    assert_equal 403, forbidden.status_code
    assert_equal "You are not a member of the organization", forbidden.message

    token = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "okta", organizationId: org.fetch("id")})
    assert_kind_of String, token.fetch(:scimToken)
  end

  def test_scim_rejects_org_scoped_database_tokens_without_org_envelope
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Scoped", slug: "scoped"})
    token = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "scoped-okta", organizationId: org.fetch("id")}).fetch(:scimToken)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_scim_users(headers: bearer(token_without_organization(token)))
    end
    assert_equal 401, error.status_code
    assert_equal "Invalid SCIM token", error.message
  end

  def test_scim_rejects_org_scoped_default_tokens_without_org_envelope
    token = Base64.urlsafe_encode64("default-token:default-provider:org-1", padding: false)
    auth = build_auth(default_scim: [{providerId: "default-provider", scimToken: "default-token", organizationId: "org-1"}])

    assert_equal 0, auth.api.list_scim_users(headers: bearer(token)).fetch(:totalResults)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_scim_users(headers: bearer(token_without_organization(token)))
    end
    assert_equal 401, error.status_code
    assert_equal "Invalid SCIM token", error.message
  end

  def test_scim_generate_token_requires_string_provider_id
    auth = build_auth
    cookie = sign_up_cookie(auth)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: 123})
    end
    assert_equal 400, error.status_code
    assert_equal "Validation Error", error.message

    org_error = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta", organizationId: 123})
    end
    assert_equal 400, org_error.status_code
    assert_equal "Validation Error", org_error.message
  end

  def test_scim_provider_management_roles_ownership_and_hooks
    calls = []
    scim_options = {
      provider_ownership: {enabled: true},
      required_role: ["owner"],
      before_scim_token_generated: ->(payload) { calls << [:before, payload.fetch(:user).fetch("email"), payload.fetch(:scim_token)] },
      after_scim_token_generated: ->(payload) { calls << [:after, payload.fetch(:scim_provider).fetch("providerId"), payload.fetch(:scim_token)] }
    }
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim(scim_options)])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    other_cookie = sign_up_cookie(auth, "other@example.com")
    other_user = auth.api.get_session(headers: {"cookie" => other_cookie}).fetch(:user)

    assert_equal 401, auth.api.generate_scim_token(as_response: true, body: {providerId: "anonymous"}).first
    invalid_provider = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "bad:provider"})
    end
    assert_equal 400, invalid_provider.status_code

    personal_token = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "personal"}).fetch(:scimToken)
    providers = auth.api.list_scim_provider_connections(headers: {"cookie" => owner_cookie}).fetch(:providers)
    assert_equal [{id: providers.first.fetch(:id), providerId: "personal", organizationId: nil}], providers

    forbidden = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_provider_connection(headers: {"cookie" => other_cookie}, query: {providerId: "personal"})
    end
    assert_equal 403, forbidden.status_code
    assert_equal "You must be the owner to access this provider", forbidden.message

    regenerate_forbidden = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => other_cookie}, body: {providerId: "personal"})
    end
    assert_equal 403, regenerate_forbidden.status_code

    org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "SCIM Org", slug: "scim-org"})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org.fetch("id"), userId: other_user.fetch("id"), role: "member"})
    member_forbidden = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => other_cookie}, body: {providerId: "okta", organizationId: org.fetch("id")})
    end
    assert_equal 403, member_forbidden.status_code
    assert_equal "Insufficient role for this operation", member_forbidden.message

    org_token = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "okta", organizationId: org.fetch("id")}).fetch(:scimToken)
    org_provider = auth.api.get_scim_provider_connection(headers: {"cookie" => owner_cookie}, query: {providerId: "okta"})
    assert_equal({providerId: "okta", organizationId: org.fetch("id")}, org_provider.slice(:providerId, :organizationId))
    assert_equal [:before, "owner@example.com"], calls.first[0, 2]
    assert_equal [:after, "personal"], calls[1][0, 2]

    deleted = auth.api.delete_scim_provider_connection(headers: {"cookie" => owner_cookie}, body: {providerId: "personal"})
    assert_equal true, deleted.fetch(:success)
    assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: bearer(personal_token), body: {userName: "invalid@example.com"})
    end
    assert auth.api.create_scim_user(headers: bearer(org_token), body: {userName: "org@example.com"})

    missing_provider = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_provider_connection(headers: {"cookie" => owner_cookie}, query: {providerId: "missing"})
    end
    assert_equal 404, missing_provider.status_code

    missing_delete = assert_raises(BetterAuth::APIError) do
      auth.api.delete_scim_provider_connection(headers: {"cookie" => owner_cookie}, body: {providerId: "missing"})
    end
    assert_equal 404, missing_delete.status_code

    no_org_list = build_auth(provider_ownership: {enabled: true})
    no_org_owner_cookie = sign_up_cookie(no_org_list, "no-org-owner@example.com")
    no_org_list.api.generate_scim_token(headers: {"cookie" => no_org_owner_cookie}, body: {providerId: "standalone"})
    assert_equal ["standalone"], no_org_list.api.list_scim_provider_connections(headers: {"cookie" => no_org_owner_cookie}).fetch(:providers).map { |provider| provider.fetch(:providerId) }

    aborting_auth = build_auth(
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.scim(before_scim_token_generated: ->(_payload) { raise BetterAuth::APIError.new("FORBIDDEN", message: "blocked by hook") })
      ]
    )
    abort_cookie = sign_up_cookie(aborting_auth, "abort@example.com")
    hook_error = assert_raises(BetterAuth::APIError) do
      aborting_auth.api.generate_scim_token(headers: {"cookie" => abort_cookie}, body: {providerId: "blocked"})
    end
    assert_equal 403, hook_error.status_code
    assert_equal "blocked by hook", hook_error.message
  end

  def test_scim_provider_management_respects_admin_custom_roles_and_creator_role
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    admin_cookie = sign_up_cookie(auth, "admin@example.com")
    member_cookie = sign_up_cookie(auth, "member@example.com")
    admin_user = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    member_user = auth.api.get_session(headers: {"cookie" => member_cookie}).fetch(:user)
    org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Roles", slug: "roles"})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org.fetch("id"), userId: admin_user.fetch("id"), role: ["member", "admin"]})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org.fetch("id"), userId: member_user.fetch("id"), role: "member"})

    token = auth.api.generate_scim_token(headers: {"cookie" => admin_cookie}, body: {providerId: "admin-okta", organizationId: org.fetch("id")})
    assert_kind_of String, token.fetch(:scimToken)
    assert_equal ["admin-okta"], auth.api.list_scim_provider_connections(headers: {"cookie" => admin_cookie}).fetch(:providers).map { |provider| provider.fetch(:providerId) }
    assert_equal [], auth.api.list_scim_provider_connections(headers: {"cookie" => member_cookie}).fetch(:providers)

    owner_only = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim(required_role: ["owner"])])
    owner_only_owner_cookie = sign_up_cookie(owner_only, "owner-only@example.com")
    owner_only_admin_cookie = sign_up_cookie(owner_only, "owner-only-admin@example.com")
    owner_only_admin = owner_only.api.get_session(headers: {"cookie" => owner_only_admin_cookie}).fetch(:user)
    owner_only_org = owner_only.api.create_organization(headers: {"cookie" => owner_only_owner_cookie}, body: {name: "Owner Only", slug: "owner-only"})
    owner_only.api.add_member(headers: {"cookie" => owner_only_owner_cookie}, body: {organizationId: owner_only_org.fetch("id"), userId: owner_only_admin.fetch("id"), role: "admin"})
    forbidden = assert_raises(BetterAuth::APIError) do
      owner_only.api.generate_scim_token(headers: {"cookie" => owner_only_admin_cookie}, body: {providerId: "blocked", organizationId: owner_only_org.fetch("id")})
    end
    assert_equal 403, forbidden.status_code

    founder_auth = build_auth(plugins: [BetterAuth::Plugins.organization(creator_role: "founder"), BetterAuth::Plugins.scim])
    founder_cookie = sign_up_cookie(founder_auth, "founder@example.com")
    founder_org = founder_auth.api.create_organization(headers: {"cookie" => founder_cookie}, body: {name: "Founder", slug: "founder"})
    founder_token = founder_auth.api.generate_scim_token(headers: {"cookie" => founder_cookie}, body: {providerId: "founder-okta", organizationId: founder_org.fetch("id")})
    assert_kind_of String, founder_token.fetch(:scimToken)
  end

  def test_scim_blocks_cross_org_provider_regeneration_and_delete_invalidates_org_token
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    other_cookie = sign_up_cookie(auth, "other@example.com")
    owner_org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Owner Org", slug: "owner-org"})
    other_org = auth.api.create_organization(headers: {"cookie" => other_cookie}, body: {name: "Other Org", slug: "other-org"})
    token = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "shared", organizationId: owner_org.fetch("id")}).fetch(:scimToken)

    blocked = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => other_cookie}, body: {providerId: "shared"})
    end
    assert_equal 403, blocked.status_code

    other_token = auth.api.generate_scim_token(headers: {"cookie" => other_cookie}, body: {providerId: "other", organizationId: other_org.fetch("id")}).fetch(:scimToken)
    assert auth.api.create_scim_user(headers: bearer(token), body: {userName: "owner-org@example.com"})
    assert auth.api.create_scim_user(headers: bearer(other_token), body: {userName: "other-org@example.com"})

    assert_equal true, auth.api.delete_scim_provider_connection(headers: {"cookie" => owner_cookie}, body: {providerId: "shared"}).fetch(:success)
    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: bearer(token), body: {userName: "after-delete@example.com"})
    end
    assert_equal 401, invalid.status_code
  end

  def test_scim_blocks_duplicate_org_scoped_provider_ids_before_create
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    other_cookie = sign_up_cookie(auth, "other@example.com")
    owner_org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Owner Org", slug: "owner-org"})
    other_org = auth.api.create_organization(headers: {"cookie" => other_cookie}, body: {name: "Other Org", slug: "other-org"})

    auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "shared-provider", organizationId: owner_org.fetch("id")})

    blocked = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => other_cookie}, body: {providerId: "shared-provider", organizationId: other_org.fetch("id")})
    end
    assert_equal 403, blocked.status_code
    assert_equal "You must be a member of the organization to access this provider", blocked.message

    providers = auth.context.adapter.find_many(model: "scimProvider", where: [{field: "providerId", value: "shared-provider"}])
    assert_equal 1, providers.length
    assert_equal owner_org.fetch("id"), providers.first.fetch("organizationId")
  end

  def test_scim_provider_management_returns_empty_list_without_memberships
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    cookie = sign_up_cookie(auth, "lonely@example.com")

    assert_equal [], auth.api.list_scim_provider_connections(headers: {"cookie" => cookie}).fetch(:providers)
  end

  def test_scim_provider_management_lists_only_accessible_org_scoped_providers
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    other_cookie = sign_up_cookie(auth, "other@example.com")
    org_a = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Org A", slug: "org-a"})
    org_b = auth.api.create_organization(headers: {"cookie" => other_cookie}, body: {name: "Org B", slug: "org-b"})

    auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "provider-1", organizationId: org_a.fetch("id")})
    auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "provider-2", organizationId: org_a.fetch("id")})
    auth.api.generate_scim_token(headers: {"cookie" => other_cookie}, body: {providerId: "provider-3", organizationId: org_b.fetch("id")})

    providers = auth.api.list_scim_provider_connections(headers: {"cookie" => owner_cookie}).fetch(:providers)
    assert_equal ["provider-1", "provider-2"], providers.map { |provider| provider.fetch(:providerId) }.sort

    provider_by_id = providers.to_h { |provider| [provider.fetch(:providerId), provider] }
    assert_kind_of String, provider_by_id.fetch("provider-1").fetch(:id)
    assert_equal org_a.fetch("id"), provider_by_id.fetch("provider-1").fetch(:organizationId)
    assert_kind_of String, provider_by_id.fetch("provider-2").fetch(:id)
    assert_equal org_a.fetch("id"), provider_by_id.fetch("provider-2").fetch(:organizationId)
  end

  def test_scim_provider_management_denies_get_and_delete_for_other_org
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    other_cookie = sign_up_cookie(auth, "other@example.com")
    org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Owner Org", slug: "owner-org"})
    auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "other-org-provider", organizationId: org.fetch("id")})

    get_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_provider_connection(headers: {"cookie" => other_cookie}, query: {providerId: "other-org-provider"})
    end
    assert_equal 403, get_error.status_code
    assert_equal "You must be a member of the organization to access this provider", get_error.message

    delete_error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_scim_provider_connection(headers: {"cookie" => other_cookie}, body: {providerId: "other-org-provider"})
    end
    assert_equal 403, delete_error.status_code
    assert_equal "You must be a member of the organization to access this provider", delete_error.message
  end

  def test_scim_provider_management_requires_string_provider_id
    auth = build_auth
    cookie = sign_up_cookie(auth)

    get_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_provider_connection(headers: {"cookie" => cookie}, query: {providerId: 123})
    end
    assert_equal 400, get_error.status_code
    assert_equal "Validation Error", get_error.message

    delete_error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_scim_provider_connection(headers: {"cookie" => cookie}, body: {providerId: 123})
    end
    assert_equal 400, delete_error.status_code
    assert_equal "Validation Error", delete_error.message
  end

  def test_scim_provider_management_denies_delete_for_non_owner_personal_provider
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim(provider_ownership: {enabled: true})])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    other_cookie = sign_up_cookie(auth, "other@example.com")
    auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "personal"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_scim_provider_connection(headers: {"cookie" => other_cookie}, body: {providerId: "personal"})
    end
    assert_equal 403, error.status_code
    assert_equal "You must be the owner to access this provider", error.message
  end

  def test_scim_regeneration_deletes_existing_provider_before_before_hook_failure
    blocked = false
    auth = build_auth(before_scim_token_generated: ->(_payload) { raise BetterAuth::APIError.new("FORBIDDEN", message: "blocked") if blocked })
    cookie = sign_up_cookie(auth)
    old_token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)

    blocked = true
    error = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"})
    end
    assert_equal 403, error.status_code

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: bearer(old_token), body: {userName: "after-block@example.com"})
    end
    assert_equal 401, invalid.status_code
  end

  def test_scim_provider_management_requires_org_membership_after_creator_removed
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    replacement_cookie = sign_up_cookie(auth, "replacement@example.com")
    replacement_user = auth.api.get_session(headers: {"cookie" => replacement_cookie}).fetch(:user)
    org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Removed", slug: "removed"})
    auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "removed-provider", organizationId: org.fetch("id")})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org.fetch("id"), userId: replacement_user.fetch("id"), role: "owner"})
    owner_member = auth.context.adapter.find_one(model: "member", where: [{field: "organizationId", value: org.fetch("id")}, {field: "userId", value: auth.api.get_session(headers: {"cookie" => owner_cookie}).fetch(:user).fetch("id")}])
    auth.context.adapter.delete(model: "member", where: [{field: "id", value: owner_member.fetch("id")}])

    error = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_provider_connection(headers: {"cookie" => owner_cookie}, query: {providerId: "removed-provider"})
    end
    assert_equal 403, error.status_code
    assert_equal "You must be a member of the organization to access this provider", error.message
    refute auth.api.list_scim_provider_connections(headers: {"cookie" => owner_cookie}).fetch(:providers).any? { |provider| provider.fetch(:providerId) == "removed-provider" }
  end
end

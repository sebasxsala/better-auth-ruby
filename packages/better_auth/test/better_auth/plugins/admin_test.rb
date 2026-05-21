# frozen_string_literal: true

require "json"
require "uri"
require_relative "../../test_helper"

class BetterAuthPluginsAdminTest < Minitest::Test
  SECRET = "phase-ten-admin-secret-with-enough-entropy"

  def test_admin_manages_users_roles_bans_sessions_and_passwords
    auth = build_auth
    admin_cookie = sign_up_cookie(auth, email: "admin@example.com")
    user_cookie = sign_up_cookie(auth, email: "user@example.com")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    user = auth.api.get_session(headers: {"cookie" => user_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")

    users = auth.api.list_users(headers: {"cookie" => admin_cookie}, query: {searchValue: "user", searchField: "email"})
    assert_equal 1, users.fetch(:total)
    assert_equal "user@example.com", users.fetch(:users).first.fetch("email")

    created = auth.api.create_user(
      headers: {"cookie" => admin_cookie},
      body: {email: "created@example.com", password: "password123", name: "Created", role: ["user", "admin"]}
    )
    assert_equal "user,admin", created.fetch(:user).fetch("role")

    role_response = auth.api.set_role(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id"), role: "user"})
    assert_equal user.fetch("id"), role_response.fetch(:user).fetch("id")
    assert_equal "user", auth.context.internal_adapter.find_user_by_id(user.fetch("id")).fetch("role")

    banned = auth.api.ban_user(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id"), banReason: "spam"})
    assert_equal true, banned.fetch(:user).fetch("banned")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_email(body: {email: "user@example.com", password: "password123"})
    end
    assert_equal 403, error.status_code

    unbanned = auth.api.unban_user(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id")})
    assert_equal false, unbanned.fetch(:user).fetch("banned")
    auth.api.set_user_password(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id"), newPassword: "newpassword123"})
    assert auth.api.sign_in_email(body: {email: "user@example.com", password: "newpassword123"}).fetch(:token)

    impersonated_result = auth.api.impersonate_user(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id")}, return_headers: true)
    impersonated = impersonated_result.fetch(:response)
    assert_equal admin.fetch("id"), impersonated.fetch(:session).fetch("impersonatedBy")
    assert_includes impersonated_result.fetch(:headers).fetch("set-cookie"), "better-auth.admin_session"

    stopped = auth.api.stop_impersonating(headers: {"cookie" => cookie_header(impersonated_result.fetch(:headers).fetch("set-cookie"))})
    assert_equal admin.fetch("id"), stopped.fetch(:user).fetch("id")
    assert_equal admin.fetch("id"), stopped.fetch(:session).fetch("userId")
  end

  def test_blocks_non_admin_and_checks_permissions
    auth = build_auth
    admin_cookie = sign_up_cookie(auth, email: "permissions-admin@example.com")
    user_cookie = sign_up_cookie(auth, email: "permissions-user@example.com")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    user = auth.api.get_session(headers: {"cookie" => user_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")

    denied_calls = [
      -> { auth.api.get_user(headers: {"cookie" => user_cookie}, query: {id: admin.fetch("id")}) },
      -> { auth.api.create_user(headers: {"cookie" => user_cookie}, body: {email: "denied-create@example.com", name: "Denied", role: "user"}) },
      -> { auth.api.list_users(headers: {"cookie" => user_cookie}) },
      -> { auth.api.set_role(headers: {"cookie" => user_cookie}, body: {userId: admin.fetch("id"), role: "user"}) },
      -> { auth.api.ban_user(headers: {"cookie" => user_cookie}, body: {userId: admin.fetch("id")}) },
      -> { auth.api.unban_user(headers: {"cookie" => user_cookie}, body: {userId: admin.fetch("id")}) },
      -> { auth.api.list_user_sessions(headers: {"cookie" => user_cookie}, body: {userId: admin.fetch("id")}) },
      -> { auth.api.impersonate_user(headers: {"cookie" => user_cookie}, body: {userId: admin.fetch("id")}) },
      -> { auth.api.revoke_user_session(headers: {"cookie" => user_cookie}, body: {sessionToken: "session-token"}) },
      -> { auth.api.revoke_user_sessions(headers: {"cookie" => user_cookie}, body: {userId: admin.fetch("id")}) },
      -> { auth.api.remove_user(headers: {"cookie" => user_cookie}, body: {userId: admin.fetch("id")}) },
      -> { auth.api.set_user_password(headers: {"cookie" => user_cookie}, body: {userId: admin.fetch("id"), newPassword: "newpassword123"}) },
      -> { auth.api.admin_update_user(headers: {"cookie" => user_cookie}, body: {userId: admin.fetch("id"), data: {name: "Denied"}}) }
    ]

    denied_calls.each do |call|
      denied = assert_raises(BetterAuth::APIError) { call.call }
      assert_equal 403, denied.status_code
    end

    assert_equal true, auth.api.user_has_permission(
      headers: {"cookie" => admin_cookie},
      body: {permissions: {user: ["list"], session: ["revoke"]}}
    ).fetch(:success)
    assert_equal false, auth.api.user_has_permission(
      headers: {"cookie" => user_cookie},
      body: {permissions: {user: ["list"]}}
    ).fetch(:success)
    assert_equal user.fetch("id"), auth.api.get_session(headers: {"cookie" => user_cookie}).fetch(:user).fetch("id")
  end

  def test_admin_list_users_filters_before_pagination_and_reports_total
    auth = build_auth
    admin_cookie = sign_up_cookie(auth, email: "admin-list@example.com", name: "Admin")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")
    alpha_cookie = sign_up_cookie(auth, email: "alpha@example.com", name: "Alpha")
    beta_cookie = sign_up_cookie(auth, email: "beta@example.com", name: "Beta")
    alpha = auth.api.get_session(headers: {"cookie" => alpha_cookie}).fetch(:user)
    beta = auth.api.get_session(headers: {"cookie" => beta_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(alpha.fetch("id"), role: "support")
    auth.context.internal_adapter.update_user(beta.fetch("id"), role: "support", banned: true)

    limited = auth.api.list_users(headers: {"cookie" => admin_cookie}, query: {limit: 1, offset: 0, filterField: "role", filterValue: "support"})
    assert_equal 2, limited.fetch(:total)
    assert_equal 1, limited.fetch(:users).length

    unbanned = auth.api.list_users(headers: {"cookie" => admin_cookie}, query: {filterField: "banned", filterValue: false})
    emails = unbanned.fetch(:users).map { |user| user.fetch("email") }
    assert_includes emails, "alpha@example.com"
    refute_includes emails, "beta@example.com"

    without_alpha = auth.api.list_users(headers: {"cookie" => admin_cookie}, query: {filterField: "_id", filterOperator: "ne", filterValue: alpha.fetch("id")})
    refute_includes without_alpha.fetch(:users).map { |user| user.fetch("id") }, alpha.fetch("id")
  end

  def test_admin_update_user_requires_set_role_permission_for_role_changes
    ac = BetterAuth::Plugins.create_access_control(user: ["update", "set-role"])
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.admin(
          ac: ac,
          roles: {
            admin: ac.new_role(user: ["update", "set-role"]),
            support: ac.new_role(user: ["update"]),
            user: ac.new_role(user: [])
          }
        )
      ]
    )
    admin_cookie = sign_up_cookie(auth, email: "role-admin@example.com", name: "Admin")
    support_cookie = sign_up_cookie(auth, email: "role-support@example.com", name: "Support")
    target_cookie = sign_up_cookie(auth, email: "role-target@example.com", name: "Target")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    support = auth.api.get_session(headers: {"cookie" => support_cookie}).fetch(:user)
    target = auth.api.get_session(headers: {"cookie" => target_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")
    auth.context.internal_adapter.update_user(support.fetch("id"), role: "support")

    result = auth.api.admin_update_user(headers: {"cookie" => support_cookie}, body: {userId: target.fetch("id"), data: {name: "Target Updated"}})
    assert_equal "Target Updated", result.fetch("name")

    denied = assert_raises(BetterAuth::APIError) do
      auth.api.admin_update_user(headers: {"cookie" => support_cookie}, body: {userId: target.fetch("id"), data: {role: "admin"}})
    end
    assert_equal 403, denied.status_code

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.admin_update_user(headers: {"cookie" => admin_cookie}, body: {userId: target.fetch("id"), data: {role: "missing-role"}})
    end
    assert_equal 400, invalid.status_code
  end

  def test_admin_has_permission_requires_user_id_or_role_and_handles_missing_users
    auth = build_auth

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.user_has_permission(body: {permissions: {user: ["list"]}})
    end
    assert_equal 400, missing.status_code
    assert_equal "user id or role is required", missing.message

    empty = assert_raises(BetterAuth::APIError) do
      auth.api.user_has_permission(body: {userId: "", permissions: {user: ["list"]}})
    end
    assert_equal 400, empty.status_code
    assert_equal "user id or role is required", empty.message

    no_permission = assert_raises(BetterAuth::APIError) do
      auth.api.user_has_permission(body: {role: "admin"})
    end
    assert_equal 400, no_permission.status_code
    assert_equal "invalid permission check. no permission(s) were passed.", no_permission.message

    not_found = assert_raises(BetterAuth::APIError) do
      auth.api.user_has_permission(body: {userId: "NaN", permissions: {user: ["list"]}})
    end
    assert_equal 400, not_found.status_code
    assert_equal "user not found", not_found.message

    result = auth.api.user_has_permission(body: {role: "admin", userId: "NaN", permissions: {user: ["list"]}})
    assert_nil result.fetch(:error)
    assert_equal true, result.fetch(:success)
  end

  def test_admin_has_permission_matches_upstream_role_priority_and_banned_user
    ac = BetterAuth::Plugins.create_access_control(
      user: ["create", "read", "update", "delete", "list", "bulk-delete", "set-role", "ban"],
      order: ["create", "read", "update", "delete", "update-many"]
    )
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.admin(
          ac: ac,
          roles: {
            admin: ac.new_role(user: ["create", "read", "update", "delete", "list", "set-role", "ban"], order: ["create", "read", "update", "delete"]),
            user: ac.new_role(user: ["read"], order: ["read"])
          }
        )
      ]
    )
    admin_cookie = sign_up_cookie(auth, email: "access-admin@example.com", name: "Admin")
    user_cookie = sign_up_cookie(auth, email: "access-user@example.com", name: "User")
    banned_cookie = sign_up_cookie(auth, email: "access-banned@example.com", name: "Banned")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    user = auth.api.get_session(headers: {"cookie" => user_cookie}).fetch(:user)
    banned = auth.api.get_session(headers: {"cookie" => banned_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")
    auth.context.internal_adapter.update_user(user.fetch("id"), role: "user")
    auth.context.internal_adapter.update_user(banned.fetch("id"), role: "user")
    auth.api.ban_user(headers: {"cookie" => admin_cookie}, body: {userId: banned.fetch("id"), banReason: "Testing role priority"})

    assert_equal true, auth.api.user_has_permission(
      body: {userId: admin.fetch("id"), permissions: {user: ["create"], order: ["create"]}}
    ).fetch(:success)
    assert_equal false, auth.api.user_has_permission(
      body: {userId: user.fetch("id"), permissions: {order: ["update-many"]}}
    ).fetch(:success)
    assert_equal true, auth.api.user_has_permission(
      body: {userId: user.fetch("id"), role: "admin", permissions: {user: ["create"]}}
    ).fetch(:success)
    assert_equal false, auth.api.user_has_permission(
      body: {userId: admin.fetch("id"), role: "user", permissions: {user: ["create"]}}
    ).fetch(:success)
    assert_equal true, auth.api.user_has_permission(
      body: {userId: banned.fetch("id"), role: "admin", permissions: {user: ["create"]}}
    ).fetch(:success)
    assert_equal false, auth.api.user_has_permission(
      body: {userId: banned.fetch("id"), permissions: {user: ["create"]}}
    ).fetch(:success)
  end

  def test_admin_create_user_matches_upstream_validation_and_server_call
    auth = build_auth
    admin_cookie = sign_up_cookie(auth, email: "create-admin@example.com")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")

    created = auth.api.create_user(body: {email: "server-created@example.com", name: "Server Created", role: "user"})
    assert_equal "server-created@example.com", created.fetch(:user).fetch("email")
    assert_empty auth.context.internal_adapter.find_accounts(created.fetch(:user).fetch("id"))

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.create_user(headers: {"cookie" => admin_cookie}, body: {email: "bad-email", name: "Bad"})
    end
    assert_equal 400, invalid.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES.fetch("INVALID_EMAIL"), invalid.message

    duplicate = assert_raises(BetterAuth::APIError) do
      auth.api.create_user(headers: {"cookie" => admin_cookie}, body: {email: "server-created@example.com", name: "Duplicate"})
    end
    assert_equal 400, duplicate.status_code
    assert_equal BetterAuth::Plugins::ADMIN_ERROR_CODES.fetch("USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"), duplicate.message
  end

  def test_admin_allows_arbitrary_roles_unless_roles_are_configured
    auth = build_auth
    admin_cookie = sign_up_cookie(auth, email: "arbitrary-admin@example.com")
    target_cookie = sign_up_cookie(auth, email: "arbitrary-target@example.com")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    target = auth.api.get_session(headers: {"cookie" => target_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")

    created = auth.api.create_user(headers: {"cookie" => admin_cookie}, body: {email: "arbitrary-created@example.com", name: "Created", role: "support"})
    assert_equal "support", created.fetch(:user).fetch("role")

    set = auth.api.set_role(headers: {"cookie" => admin_cookie}, body: {userId: target.fetch("id"), role: "auditor"})
    assert_equal "auditor", set.fetch(:user).fetch("role")

    updated = auth.api.admin_update_user(headers: {"cookie" => admin_cookie}, body: {userId: target.fetch("id"), data: {role: "operator"}})
    assert_equal "operator", updated.fetch("role")

    restricted = build_auth(admin_options: {
      roles: {
        admin: BetterAuth::Plugins.admin_default_roles.fetch("admin"),
        user: BetterAuth::Plugins.admin_default_roles.fetch("user")
      }
    })
    restricted_admin_cookie = sign_up_cookie(restricted, email: "restricted-admin@example.com")
    restricted_admin = restricted.api.get_session(headers: {"cookie" => restricted_admin_cookie}).fetch(:user)
    restricted.context.internal_adapter.update_user(restricted_admin.fetch("id"), role: "admin")

    invalid = assert_raises(BetterAuth::APIError) do
      restricted.api.create_user(headers: {"cookie" => restricted_admin_cookie}, body: {email: "invalid-role@example.com", name: "Invalid", role: "support"})
    end
    assert_equal 400, invalid.status_code

    restricted_target_cookie = sign_up_cookie(restricted, email: "restricted-target@example.com")
    restricted_target = restricted.api.get_session(headers: {"cookie" => restricted_target_cookie}).fetch(:user)

    invalid_set_role = assert_raises(BetterAuth::APIError) do
      restricted.api.set_role(headers: {"cookie" => restricted_admin_cookie}, body: {userId: restricted_target.fetch("id"), role: "support"})
    end
    assert_equal 400, invalid_set_role.status_code

    invalid_multi_role = assert_raises(BetterAuth::APIError) do
      restricted.api.set_role(headers: {"cookie" => restricted_admin_cookie}, body: {userId: restricted_target.fetch("id"), role: ["user", "support"]})
    end
    assert_equal 400, invalid_multi_role.status_code
  end

  def test_admin_list_users_supports_upstream_search_filter_sort_and_shape
    auth = build_auth
    admin_cookie = sign_up_cookie(auth, email: "root-admin@example.com", name: "Admin")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")
    sign_up_cookie(auth, email: "alpha-list@example.com", name: "Alpha")
    beta_cookie = sign_up_cookie(auth, email: "beta-list@example.com", name: "Beta")
    beta = auth.api.get_session(headers: {"cookie" => beta_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(beta.fetch("id"), role: "admin")

    searched = auth.api.list_users(headers: {"cookie" => admin_cookie}, query: {searchValue: "list@example.com", searchField: "email", searchOperator: "ends_with"})
    assert_equal 2, searched.fetch(:total)
    assert_nil searched.fetch(:limit)
    assert_nil searched.fetch(:offset)

    filtered = auth.api.list_users(headers: {"cookie" => admin_cookie}, query: {filterField: "role", filterOperator: "eq", filterValue: "admin", searchValue: "list", searchField: "email"})
    assert_equal ["beta-list@example.com"], filtered.fetch(:users).map { |user| user.fetch("email") }

    sorted = auth.api.list_users(headers: {"cookie" => admin_cookie}, query: {sortBy: "name", sortDirection: "desc", limit: 1, offset: 1})
    assert_equal 1, sorted.fetch(:limit)
    assert_equal 1, sorted.fetch(:offset)
    assert_equal 1, sorted.fetch(:users).length

    non_users = auth.api.list_users(headers: {"cookie" => admin_cookie}, query: {sortBy: "createdAt", sortDirection: "desc", filterField: "role", filterOperator: "ne", filterValue: "user"})
    assert non_users.fetch(:users).length >= 1
    refute_includes non_users.fetch(:users).map { |user| user.fetch("role") }, "user"
  end

  def test_admin_sessions_and_destructive_endpoints_match_upstream_shapes
    auth = build_auth
    admin_cookie = sign_up_cookie(auth, email: "sessions-admin@example.com")
    user_cookie = sign_up_cookie(auth, email: "sessions-user@example.com")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    user = auth.api.get_session(headers: {"cookie" => user_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")

    sessions = auth.api.list_user_sessions(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id")})
    assert_kind_of Array, sessions.fetch(:sessions)

    token = sessions.fetch(:sessions).first.fetch("token")
    assert_equal({success: true}, auth.api.revoke_user_session(headers: {"cookie" => admin_cookie}, body: {sessionToken: token}))

    fresh_cookie = sign_up_cookie(auth, email: "sessions-delete@example.com")
    fresh = auth.api.get_session(headers: {"cookie" => fresh_cookie}).fetch(:user)
    assert_equal({success: true}, auth.api.revoke_user_sessions(headers: {"cookie" => admin_cookie}, body: {userId: fresh.fetch("id")}))
    assert_equal({success: true}, auth.api.remove_user(headers: {"cookie" => admin_cookie}, body: {userId: fresh.fetch("id")}))

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.remove_user(headers: {"cookie" => admin_cookie}, body: {userId: "missing"})
    end
    assert_equal 404, missing.status_code
  end

  def test_admin_get_update_and_ban_shapes_match_upstream
    auth = build_auth(admin_options: {default_ban_reason: "No reason"})
    admin_cookie = sign_up_cookie(auth, email: "shape-admin@example.com", name: "Admin")
    user_cookie = sign_up_cookie(auth, email: "shape-user@example.com", name: "Shape User")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    user = auth.api.get_session(headers: {"cookie" => user_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")

    fetched = auth.api.get_user(headers: {"cookie" => admin_cookie}, query: {id: user.fetch("id")})
    assert_equal user.fetch("id"), fetched.fetch("id")

    updated = auth.api.admin_update_user(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id"), data: {name: "Shape Updated"}})
    assert_equal "Shape Updated", updated.fetch("name")

    banned = auth.api.ban_user(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id")})
    assert_equal "No reason", banned.fetch(:user).fetch("banReason")

    self_ban = assert_raises(BetterAuth::APIError) do
      auth.api.ban_user(headers: {"cookie" => admin_cookie}, body: {userId: admin.fetch("id")})
    end
    assert_equal 400, self_ban.status_code
  end

  def test_admin_ban_hooks_cover_custom_message_expiry_and_social_callback
    auth = build_auth(
      admin_options: {banned_user_message: "Custom banned user message"},
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: lambda do |data|
            "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}"
          end,
          validate_authorization_code: ->(_data) { {accessToken: "oauth-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-banned",
                email: "social-banned@example.com",
                name: "Social Banned",
                emailVerified: true
              }
            }
          }
        }
      }
    )
    admin_cookie = sign_up_cookie(auth, email: "ban-admin@example.com")
    banned_cookie = sign_up_cookie(auth, email: "social-banned@example.com")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    banned = auth.api.get_session(headers: {"cookie" => banned_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")

    auth.api.ban_user(headers: {"cookie" => admin_cookie}, body: {userId: banned.fetch("id")})
    sign_in_error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_email(body: {email: "social-banned@example.com", password: "password123"})
    end
    assert_equal 403, sign_in_error.status_code
    assert_equal "Custom banned user message", sign_in_error.message

    response = auth.api.sign_in_social(body: {provider: "github", disableRedirect: true})
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last
    status, headers, = auth.api.callback_oauth(params: {providerId: "github"}, query: {code: "code", state: state}, as_response: true)
    assert_equal 302, status
    assert_includes headers.fetch("location"), "error=banned"

    auth.context.internal_adapter.update_user(banned.fetch("id"), banExpires: Time.now - 60)
    signed_in = auth.api.sign_in_email(body: {email: "social-banned@example.com", password: "password123"})
    assert_equal banned.fetch("id"), signed_in.fetch(:user).fetch("id")
    assert_equal false, auth.context.internal_adapter.find_user_by_id(banned.fetch("id")).fetch("banned")
  end

  def test_admin_impersonation_blocks_admins_and_hides_impersonated_sessions
    auth = build_auth
    admin_cookie = sign_up_cookie(auth, email: "impersonation-admin@example.com")
    target_cookie = sign_up_cookie(auth, email: "impersonation-target@example.com")
    other_admin_cookie = sign_up_cookie(auth, email: "impersonation-other-admin@example.com")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    target = auth.api.get_session(headers: {"cookie" => target_cookie}).fetch(:user)
    other_admin = auth.api.get_session(headers: {"cookie" => other_admin_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")
    auth.context.internal_adapter.update_user(other_admin.fetch("id"), role: "admin")

    denied = assert_raises(BetterAuth::APIError) do
      auth.api.impersonate_user(headers: {"cookie" => admin_cookie}, body: {userId: other_admin.fetch("id")})
    end
    assert_equal 403, denied.status_code

    auth.api.impersonate_user(headers: {"cookie" => admin_cookie}, body: {userId: target.fetch("id")})
    raw_sessions = auth.context.internal_adapter.list_sessions(target.fetch("id"))
    assert raw_sessions.any? { |session| session["impersonatedBy"] == admin.fetch("id") }

    visible_sessions = auth.api.list_sessions(headers: {"cookie" => target_cookie})
    assert visible_sessions.all? { |session| !session.key?("impersonatedBy") }
  end

  def test_admin_list_sessions_hook_preserves_missing_session_error
    auth = build_auth

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_sessions
    end

    assert_equal 401, error.status_code
  end

  def test_admin_impersonation_allows_admins_with_impersonate_admins_permission
    ac = BetterAuth::Plugins.create_access_control(user: ["impersonate", "impersonate-admins"], session: [])
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.admin(
          ac: ac,
          roles: {
            super_admin: ac.new_role(user: ["impersonate", "impersonate-admins"]),
            admin: ac.new_role(user: ["impersonate"]),
            user: ac.new_role(user: [])
          },
          admin_roles: ["super_admin", "admin"]
        )
      ]
    )
    super_cookie = sign_up_cookie(auth, email: "super-admin@example.com")
    admin_cookie = sign_up_cookie(auth, email: "plain-admin@example.com")
    target_cookie = sign_up_cookie(auth, email: "target-admin@example.com")
    super_admin = auth.api.get_session(headers: {"cookie" => super_cookie}).fetch(:user)
    plain_admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    target_admin = auth.api.get_session(headers: {"cookie" => target_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(super_admin.fetch("id"), role: "super_admin")
    auth.context.internal_adapter.update_user(plain_admin.fetch("id"), role: "admin")
    auth.context.internal_adapter.update_user(target_admin.fetch("id"), role: "admin")

    denied = assert_raises(BetterAuth::APIError) do
      auth.api.impersonate_user(headers: {"cookie" => admin_cookie}, body: {userId: target_admin.fetch("id")})
    end
    assert_equal 403, denied.status_code

    allowed = auth.api.impersonate_user(headers: {"cookie" => super_cookie}, body: {userId: target_admin.fetch("id")})
    assert_equal super_admin.fetch("id"), allowed.fetch(:session).fetch("impersonatedBy")
  end

  def test_admin_set_password_edges_and_config_role_validation
    config_error = assert_raises(BetterAuth::Error) do
      BetterAuth::Plugins.admin(admin_roles: ["missing"])
    end
    assert_includes config_error.message, "Invalid admin roles"

    auth = build_auth
    admin_cookie = sign_up_cookie(auth, email: "password-admin@example.com")
    user_cookie = sign_up_cookie(auth, email: "password-user@example.com")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    user = auth.api.get_session(headers: {"cookie" => user_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")

    empty_user_id = assert_raises(BetterAuth::APIError) do
      auth.api.set_user_password(headers: {"cookie" => admin_cookie}, body: {userId: "", newPassword: "newpassword123"})
    end
    assert_equal 400, empty_user_id.status_code

    empty_password = assert_raises(BetterAuth::APIError) do
      auth.api.set_user_password(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id"), newPassword: ""})
    end
    assert_equal 400, empty_password.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES.fetch("PASSWORD_TOO_SHORT"), empty_password.message

    long_password = assert_raises(BetterAuth::APIError) do
      auth.api.set_user_password(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id"), newPassword: "a" * 129})
    end
    assert_equal 400, long_password.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES.fetch("PASSWORD_TOO_LONG"), long_password.message
  end

  private

  def build_auth(options = {})
    admin_options = options.delete(:admin_options) || {}
    BetterAuth.auth({
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.admin(admin_options)]
    }.merge(options))
  end

  def sign_up_cookie(auth, email:, name: nil)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: name || email.split("@").first},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end
end

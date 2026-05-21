# frozen_string_literal: true

require "uri"

module BetterAuth
  module Plugins
    ADMIN_ERROR_CODES = {
      "FAILED_TO_CREATE_USER" => "Failed to create user",
      "USER_ALREADY_EXISTS" => "User already exists.",
      "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL" => "User already exists. Use another email.",
      "YOU_CANNOT_BAN_YOURSELF" => "You cannot ban yourself",
      "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE" => "You are not allowed to change users role",
      "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS" => "You are not allowed to create users",
      "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS" => "You are not allowed to list users",
      "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS" => "You are not allowed to list users sessions",
      "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS" => "You are not allowed to ban users",
      "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS" => "You are not allowed to impersonate users",
      "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS" => "You are not allowed to revoke users sessions",
      "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS" => "You are not allowed to delete users",
      "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD" => "You are not allowed to set users password",
      "BANNED_USER" => "You have been banned from this application",
      "YOU_ARE_NOT_ALLOWED_TO_GET_USER" => "You are not allowed to get user",
      "NO_DATA_TO_UPDATE" => "No data to update",
      "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS" => "You are not allowed to update users",
      "YOU_CANNOT_REMOVE_YOURSELF" => "You cannot remove yourself",
      "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE" => "You are not allowed to set a non-existent role value",
      "YOU_CANNOT_IMPERSONATE_ADMINS" => "You cannot impersonate admins",
      "INVALID_ROLE_TYPE" => "Invalid role type"
    }.freeze

    ADMIN_DEFAULT_STATEMENTS = {
      user: ["create", "list", "set-role", "ban", "impersonate", "impersonate-admins", "delete", "set-password", "get", "update"],
      session: ["list", "revoke", "delete"]
    }.freeze
    ADMIN_DEFAULT_ROLE_STATEMENTS = {
      user: ["create", "list", "set-role", "ban", "impersonate", "delete", "set-password", "get", "update"],
      session: ["list", "revoke", "delete"]
    }.freeze

    module_function

    def admin(options = {})
      config = admin_config(options)
      Plugin.new(
        id: "admin",
        init: ->(_context) { {options: {database_hooks: admin_database_hooks(config)}} },
        schema: AdminSchema.build(config[:schema]),
        endpoints: {
          set_role: admin_set_role_endpoint(config),
          get_user: admin_get_user_endpoint(config),
          create_user: admin_create_user_endpoint(config),
          admin_update_user: admin_update_user_endpoint(config),
          list_users: admin_list_users_endpoint(config),
          list_user_sessions: admin_list_user_sessions_endpoint(config),
          unban_user: admin_unban_user_endpoint(config),
          ban_user: admin_ban_user_endpoint(config),
          impersonate_user: admin_impersonate_user_endpoint(config),
          stop_impersonating: admin_stop_impersonating_endpoint,
          revoke_user_session: admin_revoke_user_session_endpoint(config),
          revoke_user_sessions: admin_revoke_user_sessions_endpoint(config),
          remove_user: admin_remove_user_endpoint(config),
          set_user_password: admin_set_user_password_endpoint(config),
          user_has_permission: admin_has_permission_endpoint(config)
        },
        hooks: {
          after: [
            {
              matcher: ->(ctx) { ctx.path == "/list-sessions" },
              handler: lambda do |ctx|
                next unless ctx.returned.is_a?(Array)

                ctx.json(ctx.returned.reject { |session| session["impersonatedBy"] || session[:impersonatedBy] })
              end
            }
          ]
        },
        error_codes: ADMIN_ERROR_CODES,
        options: config
      )
    end

    def admin_config(options)
      config = normalize_hash(options)
      config[:roles_configured] = config.key?(:roles)
      config[:default_role] ||= "user"
      config[:admin_roles] = Array(config[:admin_roles] || ["admin"]).flat_map { |role| role.to_s.split(",") }
      config[:banned_user_message] ||= "You have been banned from this application. Please contact support if you believe this is an error."
      config[:impersonation_session_duration] ||= 60 * 60
      config[:ac] ||= create_access_control(ADMIN_DEFAULT_STATEMENTS)
      config[:roles] ||= admin_default_roles(config)
      valid_roles = config[:roles].keys.map { |role| role.to_s.downcase }
      invalid = config[:admin_roles].reject { |role| valid_roles.include?(role.to_s.downcase) }
      raise Error, "Invalid admin roles: #{invalid.join(", ")}. Admin roles must be defined in the 'roles' configuration." if invalid.any?

      config
    end

    def admin_default_roles(config = {})
      ac = config[:ac] || create_access_control(ADMIN_DEFAULT_STATEMENTS)
      {
        "admin" => ac.new_role(ADMIN_DEFAULT_ROLE_STATEMENTS),
        "user" => ac.new_role(user: [], session: [])
      }
    end

    def admin_database_hooks(config)
      {
        user: {
          create: {
            before: lambda do |user, _ctx|
              {data: {"role" => config[:default_role]}.merge(user)}
            end
          }
        },
        session: {
          create: {
            before: lambda do |session, ctx|
              next unless ctx

              user = ctx.context.internal_adapter.find_user_by_id(session["userId"] || session[:userId])
              next unless user && user["banned"]

              if user["banExpires"] && Time.parse(user["banExpires"].to_s) < Time.now
                ctx.context.internal_adapter.update_user(user["id"], banned: false, banReason: nil, banExpires: nil, updatedAt: Time.now)
                next
              end

              if ctx.path.to_s.start_with?("/callback", "/oauth2/callback")
                error_url = ctx.context.options.on_api_error[:error_url] || "#{ctx.context.base_url}/error"
                url = "#{error_url}?error=banned&error_description=#{URI.encode_www_form_component(config[:banned_user_message])}"
                raise ctx.redirect(url)
              end

              raise APIError.new("FORBIDDEN", message: config[:banned_user_message], code: "BANNED_USER")
            end
          }
        }
      }
    end

    def admin_set_role_endpoint(config)
      Endpoint.new(
        path: "/admin/set-role",
        method: "POST",
        metadata: admin_user_mutation_openapi(
          operation_id: "setUserRole",
          description: "Set the role of a user",
          response_description: "User role updated",
          properties: {
            userId: {type: "string", description: "The user id"},
            role: {type: ["string", "array"], description: "The role or roles to set"}
          },
          required: ["userId", "role"]
        )
      ) do |ctx|
        admin_require_permission!(ctx, config, {user: ["set-role"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"))
        body = normalize_hash(ctx.body)
        user_id = body[:user_id].to_s
        raise APIError.new("BAD_REQUEST", message: "userId is required") if user_id.empty?
        update = {role: admin_validate_roles!(body[:role], config)}
        user = ctx.context.internal_adapter.update_user(user_id, update)
        ctx.json({user: Schema.parse_output(ctx.context.options, "user", user || {})})
      end
    end

    def admin_get_user_endpoint(config)
      Endpoint.new(
        path: "/admin/get-user",
        method: "GET",
        metadata: {
          openapi: {
            operationId: "getUser",
            description: "Get an existing user",
            parameters: [
              {name: "id", in: "query", required: false, schema: {type: "string"}},
              {name: "userId", in: "query", required: false, schema: {type: "string"}},
              {name: "email", in: "query", required: false, schema: {type: "string"}}
            ],
            responses: {
              "200" => OpenAPI.json_response("User", {type: "object", "$ref": "#/components/schemas/User"})
            }
          }
        }
      ) do |ctx|
        admin_require_permission!(ctx, config, {user: ["get"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_GET_USER"))
        query = normalize_hash(ctx.query)
        user = if query[:id] || query[:user_id]
          ctx.context.internal_adapter.find_user_by_id(query[:id] || query[:user_id])
        elsif query[:email]
          ctx.context.internal_adapter.find_user_by_email(query[:email])&.fetch(:user)
        end
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES.fetch("USER_NOT_FOUND")) unless user
        ctx.json(Schema.parse_output(ctx.context.options, "user", user))
      end
    end

    def admin_create_user_endpoint(config)
      Endpoint.new(
        path: "/admin/create-user",
        method: "POST",
        metadata: admin_user_mutation_openapi(
          operation_id: "createUser",
          description: "Create a new user",
          response_description: "User created",
          properties: {
            email: {type: "string", description: "The email of the user"},
            password: {type: ["string", "null"], description: "The password of the user"},
            name: {type: "string", description: "The name of the user"},
            role: {type: ["string", "array", "null"], description: "The role or roles of the user"},
            data: {type: ["object", "null"], description: "Additional user data"}
          },
          required: ["email", "name"]
        )
      ) do |ctx|
        session = Routes.current_session(ctx, allow_nil: true)
        if session
          unless admin_permission?(session[:user], session[:user]["role"], {user: ["create"]}, config)
            raise APIError.new("FORBIDDEN", message: ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS"))
          end
        elsif !ctx.headers.empty?
          raise APIError.new("UNAUTHORIZED")
        end

        body = normalize_hash(ctx.body)
        email = body[:email].to_s.downcase
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES.fetch("INVALID_EMAIL")) unless Routes::EMAIL_PATTERN.match?(email)

        if ctx.context.internal_adapter.find_user_by_email(email)
          raise APIError.new("BAD_REQUEST", message: ADMIN_ERROR_CODES.fetch("USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"))
        end
        data = normalize_hash(body[:data]).each_with_object({}) { |(key, value), result| result[Schema.storage_key(key)] = value }
        user = ctx.context.internal_adapter.create_user(data.merge(
          name: body[:name].to_s,
          email: email,
          role: admin_validate_roles!(body[:role] || config[:default_role], config)
        ).merge(body.key?(:image) ? {image: body[:image]} : {}), context: ctx)
        raise APIError.new("INTERNAL_SERVER_ERROR", message: ADMIN_ERROR_CODES.fetch("FAILED_TO_CREATE_USER")) unless user

        if body[:password].to_s != ""
          ctx.context.internal_adapter.link_account(userId: user["id"], providerId: "credential", accountId: user["id"], password: Routes.hash_password(ctx, body[:password]))
        end
        ctx.json({user: Schema.parse_output(ctx.context.options, "user", user)})
      end
    end

    def admin_update_user_endpoint(config)
      Endpoint.new(
        path: "/admin/update-user",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "adminUpdateUser",
            description: "Update a user's details",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  userId: {type: "string", description: "The user id"},
                  data: {type: "object", description: "The user data to update"}
                },
                required: ["userId", "data"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("User updated", {type: "object", "$ref": "#/components/schemas/User"})
            }
          }
        }
      ) do |ctx|
        admin_require_permission!(ctx, config, {user: ["update"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS"))
        body = normalize_hash(ctx.body)
        data = normalize_hash(body[:data] || body).except(:user_id, :data)
        raise APIError.new("BAD_REQUEST", message: ADMIN_ERROR_CODES.fetch("NO_DATA_TO_UPDATE")) if data.empty?
        if data.key?(:role)
          admin_require_permission!(ctx, config, {user: ["set-role"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"))
          data[:role] = admin_validate_roles!(data[:role], config)
        end
        user = ctx.context.internal_adapter.update_user(body[:user_id], data)
        ctx.json(Schema.parse_output(ctx.context.options, "user", user))
      end
    end

    def admin_list_users_endpoint(config)
      Endpoint.new(
        path: "/admin/list-users",
        method: "GET",
        metadata: {
          openapi: {
            operationId: "listUsers",
            description: "List users",
            parameters: admin_list_users_parameters,
            responses: {
              "200" => OpenAPI.json_response(
                "List of users",
                OpenAPI.object_schema(
                  {
                    users: {type: "array", items: {type: "object", "$ref": "#/components/schemas/User"}},
                    total: {type: "number"},
                    limit: {type: ["number", "null"]},
                    offset: {type: ["number", "null"]}
                  },
                  required: ["users", "total"]
                )
              )
            }
          }
        }
      ) do |ctx|
        admin_require_permission!(ctx, config, {user: ["list"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_LIST_USERS"))
        query = normalize_hash(ctx.query)
        where = admin_user_where(query)
        sort_by = admin_user_sort(query)
        limit = query.key?(:limit) ? query[:limit].to_i : nil
        offset = query.key?(:offset) ? query[:offset].to_i : nil
        users = ctx.context.internal_adapter.list_users(limit: limit, offset: offset, sort_by: sort_by, where: where)
        total = ctx.context.internal_adapter.count_total_users(where: where)
        ctx.json({
          users: users.map { |user| Schema.parse_output(ctx.context.options, "user", user) },
          total: total,
          limit: limit,
          offset: offset
        })
      end
    end

    def admin_list_user_sessions_endpoint(config)
      Endpoint.new(
        path: "/admin/list-user-sessions",
        method: "POST",
        metadata: admin_sessions_openapi(
          operation_id: "adminListUserSessions",
          description: "List user sessions",
          response_description: "List of user sessions"
        )
      ) do |ctx|
        admin_require_permission!(ctx, config, {session: ["list"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS"))
        sessions = ctx.context.internal_adapter.list_sessions(normalize_hash(ctx.body)[:user_id])
        ctx.json({sessions: sessions.map { |session| Schema.parse_output(ctx.context.options, "session", session) }})
      end
    end

    def admin_ban_user_endpoint(config)
      Endpoint.new(
        path: "/admin/ban-user",
        method: "POST",
        metadata: admin_user_mutation_openapi(
          operation_id: "banUser",
          description: "Ban a user",
          response_description: "User banned",
          properties: {
            userId: {type: "string", description: "The user id"},
            banReason: {type: ["string", "null"], description: "The reason for the ban"},
            banExpiresIn: {type: ["number", "null"], description: "The number of seconds until the ban expires"}
          },
          required: ["userId"]
        )
      ) do |ctx|
        session = admin_require_permission!(ctx, config, {user: ["ban"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_BAN_USERS"))
        body = normalize_hash(ctx.body)
        found = ctx.context.internal_adapter.find_user_by_id(body[:user_id])
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES.fetch("USER_NOT_FOUND")) unless found
        raise APIError.new("BAD_REQUEST", message: ADMIN_ERROR_CODES.fetch("YOU_CANNOT_BAN_YOURSELF")) if body[:user_id] == session[:user]["id"]
        expires_in = body[:ban_expires_in] || config[:default_ban_expires_in]
        user = ctx.context.internal_adapter.update_user(body[:user_id], banned: true, banReason: body[:ban_reason] || config[:default_ban_reason] || "No reason", banExpires: expires_in ? Time.now + expires_in.to_i : nil, updatedAt: Time.now)
        ctx.context.internal_adapter.delete_sessions(body[:user_id])
        ctx.json({user: Schema.parse_output(ctx.context.options, "user", user)})
      end
    end

    def admin_unban_user_endpoint(config)
      Endpoint.new(
        path: "/admin/unban-user",
        method: "POST",
        metadata: admin_user_mutation_openapi(
          operation_id: "unbanUser",
          description: "Unban a user",
          response_description: "User unbanned",
          properties: {
            userId: {type: "string", description: "The user id"}
          },
          required: ["userId"]
        )
      ) do |ctx|
        admin_require_permission!(ctx, config, {user: ["ban"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_BAN_USERS"))
        user = ctx.context.internal_adapter.update_user(normalize_hash(ctx.body)[:user_id], banned: false, banReason: nil, banExpires: nil, updatedAt: Time.now)
        ctx.json({user: Schema.parse_output(ctx.context.options, "user", user)})
      end
    end

    def admin_impersonate_user_endpoint(config)
      Endpoint.new(
        path: "/admin/impersonate-user",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "impersonateUser",
            description: "Impersonate a user",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  userId: {type: "string", description: "The user id"}
                },
                required: ["userId"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("Impersonation session created", OpenAPI.session_response_schema_pair)
            }
          }
        }
      ) do |ctx|
        session = admin_require_permission!(ctx, config, {user: ["impersonate"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS"))
        body = normalize_hash(ctx.body)
        target = ctx.context.internal_adapter.find_user_by_id(body[:user_id])
        raise APIError.new("NOT_FOUND", message: "User not found") unless target
        can_impersonate_admins = config[:allow_impersonating_admins] ||
          admin_permission?(session[:user], session[:user]["role"], {user: ["impersonate-admins"]}, config)
        if !can_impersonate_admins && admin_user?(target, config)
          raise APIError.new("FORBIDDEN", message: ADMIN_ERROR_CODES.fetch("YOU_CANNOT_IMPERSONATE_ADMINS"))
        end
        impersonated = ctx.context.internal_adapter.create_session(target["id"], true, {impersonatedBy: session[:user]["id"], expiresAt: Time.now + config[:impersonation_session_duration].to_i}, true, ctx)
        raise APIError.new("INTERNAL_SERVER_ERROR", message: ADMIN_ERROR_CODES.fetch("FAILED_TO_CREATE_USER")) unless impersonated

        dont_remember_cookie = ctx.get_signed_cookie(ctx.context.auth_cookies[:dont_remember].name, ctx.context.secret)
        Cookies.delete_session_cookie(ctx)
        admin_cookie = ctx.context.create_auth_cookie("admin_session")
        ctx.set_signed_cookie(admin_cookie.name, "#{session[:session]["token"]}:#{dont_remember_cookie}", ctx.context.secret, ctx.context.auth_cookies[:session_token].attributes)
        Cookies.set_session_cookie(ctx, {session: impersonated, user: target}, true)
        ctx.json({
          session: Schema.parse_output(ctx.context.options, "session", impersonated),
          user: Schema.parse_output(ctx.context.options, "user", target)
        })
      end
    end

    def admin_stop_impersonating_endpoint
      Endpoint.new(
        path: "/admin/stop-impersonating",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "stopImpersonating",
            description: "Stop impersonating a user",
            requestBody: OpenAPI.empty_request_body,
            responses: {
              "200" => OpenAPI.json_response("Impersonation stopped", OpenAPI.session_response_schema_pair)
            }
          }
        }
      ) do |ctx|
        session = Routes.current_session(ctx, sensitive: true)
        admin_id = session[:session]["impersonatedBy"]
        raise APIError.new("BAD_REQUEST", message: "You are not impersonating anyone") unless admin_id
        admin = ctx.context.internal_adapter.find_user_by_id(admin_id)
        raise APIError.new("INTERNAL_SERVER_ERROR", message: "Failed to find user") unless admin

        admin_cookie = ctx.context.create_auth_cookie("admin_session")
        admin_cookie_value = ctx.get_signed_cookie(admin_cookie.name, ctx.context.secret)
        raise APIError.new("INTERNAL_SERVER_ERROR", message: "Failed to find admin session") unless admin_cookie_value

        admin_session_token, dont_remember_cookie = admin_cookie_value.split(":", 2)
        admin_session = ctx.context.internal_adapter.find_session(admin_session_token)
        if !admin_session || admin_session[:session]["userId"] != admin["id"]
          raise APIError.new("INTERNAL_SERVER_ERROR", message: "Failed to find admin session")
        end

        ctx.context.internal_adapter.delete_session(session[:session]["token"])
        Cookies.set_session_cookie(ctx, admin_session, !dont_remember_cookie.to_s.empty?)
        Cookies.expire_cookie(ctx, admin_cookie)
        ctx.json({
          session: Schema.parse_output(ctx.context.options, "session", admin_session[:session]),
          user: Schema.parse_output(ctx.context.options, "user", admin_session[:user])
        })
      end
    end

    def admin_revoke_user_session_endpoint(config)
      Endpoint.new(
        path: "/admin/revoke-user-session",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "revokeUserSession",
            description: "Revoke a user session",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  sessionToken: {type: "string", description: "The session token"}
                },
                required: ["sessionToken"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("Session revoked", OpenAPI.success_response_schema)
            }
          }
        }
      ) do |ctx|
        admin_require_permission!(ctx, config, {session: ["revoke"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS"))
        ctx.context.internal_adapter.delete_session(normalize_hash(ctx.body)[:session_token])
        ctx.json({success: true})
      end
    end

    def admin_revoke_user_sessions_endpoint(config)
      Endpoint.new(
        path: "/admin/revoke-user-sessions",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "revokeUserSessions",
            description: "Revoke all user sessions",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  userId: {type: "string", description: "The user id"}
                },
                required: ["userId"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("Sessions revoked", OpenAPI.success_response_schema)
            }
          }
        }
      ) do |ctx|
        admin_require_permission!(ctx, config, {session: ["revoke"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS"))
        ctx.context.internal_adapter.delete_sessions(normalize_hash(ctx.body)[:user_id])
        ctx.json({success: true})
      end
    end

    def admin_remove_user_endpoint(config)
      Endpoint.new(
        path: "/admin/remove-user",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "removeUser",
            description: "Remove a user",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  userId: {type: "string", description: "The user id"}
                },
                required: ["userId"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("User removed", OpenAPI.success_response_schema)
            }
          }
        }
      ) do |ctx|
        session = admin_require_permission!(ctx, config, {user: ["delete"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS"))
        user_id = normalize_hash(ctx.body)[:user_id]
        raise APIError.new("BAD_REQUEST", message: ADMIN_ERROR_CODES.fetch("YOU_CANNOT_REMOVE_YOURSELF")) if user_id == session[:user]["id"]
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES.fetch("USER_NOT_FOUND")) unless ctx.context.internal_adapter.find_user_by_id(user_id)
        ctx.context.internal_adapter.delete_user(user_id)
        ctx.json({success: true})
      end
    end

    def admin_set_user_password_endpoint(config)
      Endpoint.new(
        path: "/admin/set-user-password",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "setUserPassword",
            description: "Set a user's password",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  userId: {type: "string", description: "The user id"},
                  newPassword: {type: "string", description: "The new password"}
                },
                required: ["userId", "newPassword"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("Password set", OpenAPI.status_response_schema)
            }
          }
        }
      ) do |ctx|
        admin_require_permission!(ctx, config, {user: ["set-password"]}, ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD"))
        body = normalize_hash(ctx.body)
        user_id = body[:user_id].to_s
        password = body[:new_password].to_s
        raise APIError.new("BAD_REQUEST", message: "userId is required") if user_id.empty?
        min = ctx.context.options.email_and_password[:min_password_length]
        max = ctx.context.options.email_and_password[:max_password_length]
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES.fetch("PASSWORD_TOO_SHORT")) if password.length < min
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES.fetch("PASSWORD_TOO_LONG")) if password.length > max
        ctx.context.internal_adapter.update_password(user_id, Routes.hash_password(ctx, password))
        ctx.json({status: true})
      end
    end

    def admin_has_permission_endpoint(config)
      Endpoint.new(
        path: "/admin/has-permission",
        method: "POST",
        body_schema: ->(body) { body.is_a?(Hash) ? body : false },
        metadata: {
          openapi: {
            operationId: "hasPermission",
            description: "Check if the user has permission",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  permissions: {type: "object", description: "The permissions to check"},
                  userId: {type: ["string", "null"], description: "The user id"},
                  role: {type: ["string", "null"], description: "The role to check"}
                },
                required: ["permissions"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "Success",
                OpenAPI.object_schema(
                  {
                    error: {type: ["string", "null"]},
                    success: {type: "boolean"}
                  },
                  required: ["success"]
                )
              )
            }
          }
        }
      ) do |ctx|
        session = Routes.current_session(ctx, allow_nil: true)
        body = normalize_hash(ctx.body)
        permissions = body[:permissions] || body[:permission]
        unless permissions
          raise APIError.new("BAD_REQUEST", message: "invalid permission check. no permission(s) were passed.")
        end

        if session
          user = session[:user]
          role = user["role"]
        elsif !ctx.headers.empty?
          raise APIError.new("UNAUTHORIZED")
        elsif body.key?(:role)
          role = body[:role]
          user = {"id" => body[:user_id].to_s, "role" => role}
        elsif body.key?(:user_id)
          user_id = body[:user_id].to_s
          raise APIError.new("BAD_REQUEST", message: "user id or role is required") if user_id.empty?

          user = ctx.context.internal_adapter.find_user_by_id(user_id)
          raise APIError.new("BAD_REQUEST", message: "user not found") unless user

          role = user["role"]
        else
          raise APIError.new("BAD_REQUEST", message: "user id or role is required")
        end
        ctx.json({error: nil, success: admin_permission?(user, role, permissions, config)})
      end
    end

    def admin_user_mutation_openapi(operation_id:, description:, response_description:, properties:, required:)
      {
        openapi: {
          operationId: operation_id,
          description: description,
          requestBody: OpenAPI.json_request_body(OpenAPI.object_schema(properties, required: required)),
          responses: {
            "200" => OpenAPI.json_response(
              response_description,
              OpenAPI.object_schema(
                {user: {type: "object", "$ref": "#/components/schemas/User"}},
                required: ["user"]
              )
            )
          }
        }
      }
    end

    def admin_sessions_openapi(operation_id:, description:, response_description:)
      {
        openapi: {
          operationId: operation_id,
          description: description,
          requestBody: OpenAPI.json_request_body(
            OpenAPI.object_schema(
              {userId: {type: "string", description: "The user id"}},
              required: ["userId"]
            )
          ),
          responses: {
            "200" => OpenAPI.json_response(
              response_description,
              OpenAPI.object_schema(
                {sessions: {type: "array", items: {type: "object", "$ref": "#/components/schemas/Session"}}},
                required: ["sessions"]
              )
            )
          }
        }
      }
    end

    def admin_list_users_parameters
      [
        {name: "searchValue", in: "query", required: false, schema: {type: "string"}},
        {name: "searchField", in: "query", required: false, schema: {type: "string"}},
        {name: "searchOperator", in: "query", required: false, schema: {type: "string"}},
        {name: "limit", in: "query", required: false, schema: {type: "number"}},
        {name: "offset", in: "query", required: false, schema: {type: "number"}},
        {name: "sortBy", in: "query", required: false, schema: {type: "string"}},
        {name: "sortDirection", in: "query", required: false, schema: {type: "string"}},
        {name: "filterField", in: "query", required: false, schema: {type: "string"}},
        {name: "filterValue", in: "query", required: false, schema: {type: "string"}},
        {name: "filterOperator", in: "query", required: false, schema: {type: "string"}}
      ]
    end

    def admin_require_permission!(ctx, config, permissions, message)
      session = Routes.current_session(ctx, sensitive: true)
      return session if admin_permission?(session[:user], session[:user]["role"], permissions, config)

      raise APIError.new("FORBIDDEN", message: message)
    end

    def admin_permission?(user, role_string, permissions, config)
      return true if user && Array(config[:admin_user_ids]).map(&:to_s).include?(user["id"].to_s)
      return false unless permissions

      roles = (config[:roles] || admin_default_roles(config)).transform_keys(&:to_s)
      selected_roles = role_string.to_s.empty? ? [config[:default_role].to_s] : role_string.to_s.split(",")
      selected_roles.any? do |role|
        admin_role_for(roles, role)&.authorize(permissions || {})&.fetch(:success, false)
      end
    end

    def admin_user?(user, config)
      return true if Array(config[:admin_user_ids]).map(&:to_s).include?(user["id"].to_s)

      admin_roles = config[:admin_roles].map { |role| role.to_s.downcase }
      user["role"].to_s.split(",").any? { |role| admin_roles.include?(role.to_s.downcase) }
    end

    def admin_parse_roles(roles)
      Array(roles).join(",")
    end

    def admin_validate_roles!(roles, config)
      unless Array(roles).all? { |role| role.is_a?(String) || role.is_a?(Symbol) }
        raise APIError.new("BAD_REQUEST", message: ADMIN_ERROR_CODES.fetch("INVALID_ROLE_TYPE"))
      end

      parsed = admin_parse_roles(roles)
      if config[:roles_configured]
        defined_roles = (config[:roles] || {}).transform_keys(&:to_s)
        invalid = parsed.split(",", -1).reject { |role| admin_role_for(defined_roles, role) }
        if invalid.any?
          raise APIError.new("BAD_REQUEST", message: ADMIN_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE"))
        end
      end

      parsed
    end

    def admin_role_for(roles, role)
      roles[role.to_s] || roles.find { |key, _value| key.to_s.downcase == role.to_s.downcase }&.last
    end

    def admin_user_where(query)
      where = []
      search_value = query[:search_value]
      if search_value && !search_value.to_s.empty?
        where << {
          field: query[:search_field] || "email",
          operator: query[:search_operator] || "contains",
          value: search_value
        }
      end

      filter_value_defined = query.key?(:filter_value) || (query[:filter].is_a?(Hash) && query[:filter].key?(:value))
      if filter_value_defined
        filter_field = query[:filter_field] || query.dig(:filter, :field) || "email"
        where << {
          field: (filter_field.to_s == "_id") ? "id" : filter_field,
          operator: query[:filter_operator] || query.dig(:filter, :operator) || "eq",
          value: query.key?(:filter_value) ? query[:filter_value] : query.dig(:filter, :value)
        }
      end

      where
    end

    def admin_user_sort(query)
      sort_field = query[:sort_by] || query[:sort_field]
      return nil unless sort_field

      {
        field: sort_field,
        direction: query[:sort_direction] || query[:sort_order] || "asc"
      }
    end

    def admin_filter_users(users, query)
      result = users
      search_value = query[:search_value].to_s
      if !search_value.empty?
        field = (query[:search_field] || "email").to_s
        result = result.select { |user| user[field].to_s.downcase.include?(search_value.downcase) }
      end
      filter_field = (query[:filter_field] || query.dig(:filter, :field)).to_s
      if !filter_field.empty?
        filter_value = if query.key?(:filter_value)
          query[:filter_value]
        else
          query.dig(:filter, :value)
        end
        operator = (query[:filter_operator] || query.dig(:filter, :operator) || "eq").to_s
        field = (filter_field == "_id") ? "id" : Schema.storage_key(filter_field)
        result = result.select do |user|
          current = user[field]
          case operator
          when "ne" then current != filter_value
          when "contains" then current.to_s.include?(filter_value.to_s)
          else current == filter_value
          end
        end
      end
      result
    end

    def admin_sort_users(users, query)
      sort_field = query[:sort_by] || query[:sort_field]
      return users unless sort_field

      field = Schema.storage_key(sort_field)
      sorted = users.sort_by { |user| user[field].to_s }
      direction = (query[:sort_direction] || query[:sort_order] || "asc").to_s
      (direction.downcase == "desc") ? sorted.reverse : sorted
    end

    def admin_paginate_users(users, query)
      offset = query[:offset].to_i
      limit = query[:limit]
      result = offset.positive? ? users.drop(offset) : users
      limit ? result.first(limit.to_i) : result
    end
  end
end

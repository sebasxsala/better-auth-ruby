# frozen_string_literal: true

require "securerandom"
require "uri"

module BetterAuth
  module Routes
    def self.update_user
      Endpoint.new(
        path: "/update-user",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "updateUser",
            description: "Update the current user's profile",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  name: {type: ["string", "null"], description: "The user's name"},
                  image: {type: ["string", "null"], description: "The user's profile image URL"}
                }
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("User updated", OpenAPI.status_response_schema)
            }
          }
        }
      ) do |ctx|
        session = current_session(ctx)
        raise APIError.new("BAD_REQUEST", code: "BODY_MUST_BE_AN_OBJECT", message: BASE_ERROR_CODES["BODY_MUST_BE_AN_OBJECT"]) unless ctx.body.is_a?(Hash)

        body = normalize_hash(ctx.body)
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["EMAIL_CAN_NOT_BE_UPDATED"]) if body.key?("email")
        update = parse_declared_input(ctx, "user", body, allowed_base: ["name", "image"])
        raise APIError.new("BAD_REQUEST", message: "No fields to update") if update.empty?

        updated = ctx.context.internal_adapter.update_user(session[:user]["id"], update)
        Cookies.set_session_cookie(ctx, {session: session[:session], user: updated}, Cookies.dont_remember?(ctx))
        ctx.json({status: true})
      end
    end

    def self.change_password
      Endpoint.new(
        path: "/change-password",
        method: "POST",
        metadata: {
          openapi: {
            description: "Change the password of the user",
            operationId: "changePassword",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  newPassword: {type: "string", description: "The new password to set"},
                  currentPassword: {type: "string", description: "The current password is required"},
                  revokeOtherSessions: {type: ["boolean", "null"], description: "Must be a boolean value"}
                },
                required: ["newPassword", "currentPassword"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "Password successfully changed",
                OpenAPI.object_schema(
                  {
                    token: {type: "string", nullable: true, description: "New session token if other sessions were revoked"},
                    user: OpenAPI.user_response_schema
                  },
                  required: ["user"]
                )
              )
            }
          }
        }
      ) do |ctx|
        session = current_session(ctx, sensitive: true)
        body = normalize_hash(ctx.body)
        new_password = body["newPassword"] || body["new_password"]
        current_password = body["currentPassword"] || body["current_password"]
        validate_password_length!(new_password, ctx.context.options.email_and_password)
        account = credential_account(ctx, session[:user]["id"])
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["CREDENTIAL_ACCOUNT_NOT_FOUND"]) unless account && account["password"]

        unless verify_password_value(ctx, current_password.to_s, account["password"])
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_PASSWORD"])
        end

        ctx.context.internal_adapter.update_account(account["id"], password: hash_password(ctx, new_password))
        token = nil
        if body["revokeOtherSessions"] || body["revoke_other_sessions"]
          ctx.context.internal_adapter.delete_sessions(session[:user]["id"])
          new_session = ctx.context.internal_adapter.create_session(session[:user]["id"])
          Cookies.set_session_cookie(ctx, {session: new_session, user: session[:user]})
          token = new_session["token"]
        end
        ctx.json({token: token, user: Schema.parse_output(ctx.context.options, "user", session[:user])})
      end
    end

    def self.set_password
      Endpoint.new(
        path: "/set-password",
        method: "POST",
        metadata: {
          exclude_from_openapi: true,
          openapi: {
            operationId: "setPassword",
            description: "Set a password for the current user",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  newPassword: {type: "string", description: "The password to set"}
                },
                required: ["newPassword"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("Password set", OpenAPI.status_response_schema)
            }
          }
        }
      ) do |ctx|
        session = current_session(ctx, sensitive: true)
        body = normalize_hash(ctx.body)
        new_password = body["newPassword"] || body["new_password"]
        validate_password_length!(new_password, ctx.context.options.email_and_password)
        account = credential_account(ctx, session[:user]["id"])
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["PASSWORD_ALREADY_SET"]) if account && account["password"]

        ctx.context.internal_adapter.link_account(
          userId: session[:user]["id"],
          providerId: "credential",
          accountId: session[:user]["id"],
          password: hash_password(ctx, new_password)
        )
        ctx.json({status: true})
      end
    end

    def self.delete_user
      Endpoint.new(
        path: "/delete-user",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "deleteUser",
            description: "Delete the current user",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  password: {type: ["string", "null"], description: "The user's password"},
                  token: {type: ["string", "null"], description: "Delete account verification token"},
                  callbackURL: {type: ["string", "null"], description: "The URL to redirect to after deletion"}
                }
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "User deleted or verification email sent",
                OpenAPI.object_schema(
                  {
                    success: {type: "boolean"},
                    message: {type: "string"}
                  },
                  required: ["success", "message"]
                )
              )
            }
          }
        }
      ) do |ctx|
        enabled = ctx.context.options.user.dig(:delete_user, :enabled)
        raise APIError.new("NOT_FOUND") unless enabled

        session = current_session(ctx, sensitive: true)
        body = normalize_hash(ctx.body)
        sender = ctx.context.options.user.dig(:delete_user, :send_delete_account_verification)
        if body["password"]
          account = credential_account(ctx, session[:user]["id"])
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["CREDENTIAL_ACCOUNT_NOT_FOUND"]) unless account && account["password"]

          unless verify_password_value(ctx, body["password"], account["password"])
            raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_PASSWORD"])
          end
        end

        if body["token"]
          delete_user_by_token!(ctx, session, body["token"])
        elsif sender
          token = SecureRandom.hex(16)
          expires_in = ctx.context.options.user.dig(:delete_user, :delete_token_expires_in) || 3600
          callback_url = body["callbackURL"] || body["callbackUrl"] || body["callback_url"] || "/"
          url = "#{ctx.context.base_url}/delete-user/callback?token=#{URI.encode_www_form_component(token)}&callbackURL=#{URI.encode_www_form_component(callback_url)}"
          ctx.context.internal_adapter.create_verification_value(
            identifier: "delete-account-#{token}",
            value: session[:user]["id"],
            expiresAt: Time.now + expires_in.to_i
          )
          sender.call({user: session[:user], url: url, token: token}, ctx.request)
          next ctx.json({success: true, message: "Verification email sent"})
        elsif !body["password"]
          require_fresh_session!(ctx, session)
        end

        delete_current_user!(ctx, session)
        ctx.json({success: true, message: "User deleted"})
      end
    end

    def self.delete_user_callback
      Endpoint.new(
        path: "/delete-user/callback",
        method: "GET",
        metadata: {
          openapi: {
            operationId: "deleteUserCallback",
            description: "Delete the current user using a verification token",
            parameters: [
              {
                name: "token",
                in: "query",
                required: true,
                schema: {type: "string"}
              },
              {
                name: "callbackURL",
                in: "query",
                required: false,
                schema: {type: "string"}
              }
            ],
            responses: {
              "200" => OpenAPI.json_response(
                "User deleted",
                OpenAPI.object_schema(
                  {
                    success: {type: "boolean"},
                    message: {type: "string"}
                  },
                  required: ["success", "message"]
                )
              )
            }
          }
        }
      ) do |ctx|
        enabled = ctx.context.options.user.dig(:delete_user, :enabled)
        raise APIError.new("NOT_FOUND") unless enabled
        session = current_session(ctx)
        token = fetch_value(ctx.query, "token")
        callback_url = fetch_value(ctx.query, "callbackURL")
        validate_callback_url!(ctx.context, callback_url)
        delete_user_by_token!(ctx, session, token)
        delete_current_user!(ctx, session)
        raise ctx.redirect(callback_url) if callback_url

        ctx.json({success: true, message: "User deleted"})
      end
    end

    def self.change_email
      Endpoint.new(
        path: "/change-email",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "changeEmail",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  callbackURL: {type: ["string", "null"], description: "The URL to redirect to after email verification"},
                  newEmail: {type: "string", description: "The new email address to set must be a valid email address"}
                },
                required: ["newEmail"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "Email change request processed successfully",
                OpenAPI.object_schema(
                  {
                    message: {
                      type: "string",
                      nullable: true,
                      enum: ["Email updated", "Verification email sent"],
                      description: "Status message of the email change process"
                    },
                    status: {type: "boolean", description: "Indicates if the request was successful"},
                    user: {type: "object", "$ref": "#/components/schemas/User"}
                  },
                  required: ["status"]
                )
              ),
              "422" => OpenAPI.error_response("Unprocessable Entity. Email already exists")
            }
          }
        }
      ) do |ctx|
        enabled = ctx.context.options.user.dig(:change_email, :enabled)
        raise APIError.new("BAD_REQUEST", message: "Change email is disabled") unless enabled
        session = current_session(ctx, sensitive: true)
        body = normalize_hash(ctx.body)
        new_email = (body["newEmail"] || body["new_email"]).to_s.downcase
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_EMAIL"]) unless EMAIL_PATTERN.match?(new_email)
        raise APIError.new("BAD_REQUEST", message: "Email is the same") if new_email == session[:user]["email"]
        sender = ctx.context.options.email_verification[:send_verification_email]
        confirmation_sender = ctx.context.options.user.dig(:change_email, :send_change_email_confirmation)
        can_update_without_verification = !session[:user]["emailVerified"] && ctx.context.options.user.dig(:change_email, :update_email_without_verification)
        can_send_confirmation = session[:user]["emailVerified"] && confirmation_sender.respond_to?(:call)
        can_send_verification = sender.respond_to?(:call)
        unless can_update_without_verification || can_send_confirmation || can_send_verification
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VERIFICATION_EMAIL_NOT_ENABLED"])
        end

        existing_target = ctx.context.internal_adapter.find_user_by_email(new_email)
        next ctx.json({status: true}) if existing_target

        if can_update_without_verification
          updated = ctx.context.internal_adapter.update_user_by_email(session[:user]["email"], email: new_email)
          Cookies.set_session_cookie(ctx, {session: session[:session], user: updated})
          send_verification_email_payload(ctx, updated, body["callbackURL"] || body["callbackUrl"] || body["callback_url"]) if can_send_verification
          next ctx.json({status: true})
        end

        if can_send_confirmation
          callback_url = body["callbackURL"] || body["callbackUrl"] || body["callback_url"]
          token = create_email_verification_token(ctx, session[:user]["email"], update_to: new_email, extra: {"requestType" => "change-email-confirmation"})
          url = email_verification_url(ctx, token, callback_url)
          confirmation_sender.call({user: session[:user], new_email: new_email, url: url, token: token}, ctx.request)
          next ctx.json({status: true})
        end

        send_change_email_verification(ctx, sender, session[:user], session[:user]["email"], new_email, body["callbackURL"] || body["callbackUrl"] || body["callback_url"])
        ctx.json({status: true})
      end
    end

    def self.send_change_email_verification(ctx, sender, user, current_email, new_email, callback_url)
      token = create_email_verification_token(ctx, current_email, update_to: new_email, extra: {"requestType" => "change-email-verification"})
      sender.call({user: user.merge("email" => new_email), url: email_verification_url(ctx, token, callback_url), token: token}, ctx.request)
    end

    def self.email_verification_url(ctx, token, callback_url)
      callback = URI.encode_www_form_component(callback_url || "/")
      "#{ctx.context.base_url}/verify-email?token=#{URI.encode_www_form_component(token)}&callbackURL=#{callback}"
    end

    def self.delete_user_by_token!(ctx, session, token)
      verification = ctx.context.internal_adapter.find_verification_value("delete-account-#{token}")
      unless verification && verification["value"] == session[:user]["id"] && !expired_time?(verification["expiresAt"])
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES["INVALID_TOKEN"])
      end
      ctx.context.internal_adapter.delete_verification_value(verification["id"])
    end

    def self.delete_current_user!(ctx, session)
      config = ctx.context.options.user[:delete_user] || {}
      call_option(config[:before_delete], session[:user], ctx.request)
      deleted = ctx.context.internal_adapter.delete_user(session[:user]["id"])
      raise APIError.new("BAD_REQUEST", message: "User delete aborted") if deleted == false

      ctx.context.internal_adapter.delete_sessions(session[:user]["id"])
      Cookies.delete_session_cookie(ctx)
      call_option(config[:after_delete], session[:user], ctx.request)
    end

    def self.require_fresh_session!(ctx, session)
      fresh_age = ctx.context.session_config[:fresh_age].to_i
      return if fresh_age <= 0

      created_at = Session.normalize_time(session[:session]["createdAt"] || session[:session]["created_at"])
      return if created_at && created_at + fresh_age > Time.now

      raise APIError.new("BAD_REQUEST", code: "SESSION_EXPIRED", message: BASE_ERROR_CODES["SESSION_EXPIRED"])
    end

    def self.parse_declared_input(ctx, model, data, allowed_base: [])
      input = normalize_hash(data || {})
      table = Schema.auth_tables(ctx.context.options)[model.to_s]
      fields = table ? table.fetch(:fields) : {}
      additional = ctx.context.options.public_send(model.to_sym)[:additional_fields] || {}
      fields = fields.merge(additional.each_with_object({}) { |(key, value), result| result[Schema.storage_key(key)] = value }) if model.to_s == "session"
      declared_fields = fields.keys - core_model_fields(model)
      allowed = (Array(allowed_base).map { |field| Schema.storage_key(field) } + declared_fields).uniq

      input.each_with_object({}) do |(field, value), result|
        next unless fields.key?(field)
        next unless allowed.include?(field)

        attributes = fields.fetch(field)
        if attributes[:input] == false
          raise APIError.new("BAD_REQUEST", message: "#{field} is not allowed to be set")
        end

        result[field] = coerce_input_value(value, attributes)
      end
    end

    def self.coerce_input_value(value, attributes)
      return value if value.nil?
      return Time.parse(value) if attributes[:type] == "date" && value.is_a?(String)

      value
    end

    def self.core_model_fields(model)
      case model.to_s
      when "user"
        %w[id name email emailVerified image createdAt updatedAt]
      when "session"
        %w[id expiresAt token ipAddress userAgent userId createdAt updatedAt]
      else
        %w[id createdAt updatedAt]
      end
    end
  end
end

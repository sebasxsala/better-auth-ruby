# frozen_string_literal: true

require "securerandom"

module BetterAuth
  module Plugins
    PHONE_NUMBER_ERROR_CODES = {
      "INVALID_PHONE_NUMBER" => "Invalid phone number",
      "PHONE_NUMBER_EXIST" => "Phone number already exists",
      "PHONE_NUMBER_NOT_EXIST" => "phone number isn't registered",
      "INVALID_PHONE_NUMBER_OR_PASSWORD" => "Invalid phone number or password",
      "UNEXPECTED_ERROR" => "Unexpected error",
      "OTP_NOT_FOUND" => "OTP not found",
      "OTP_EXPIRED" => "OTP expired",
      "INVALID_OTP" => "Invalid OTP",
      "PHONE_NUMBER_NOT_VERIFIED" => "Phone number not verified",
      "PHONE_NUMBER_CANNOT_BE_UPDATED" => "Phone number cannot be updated",
      "SEND_OTP_NOT_IMPLEMENTED" => "sendOTP not implemented",
      "TOO_MANY_ATTEMPTS" => "Too many attempts"
    }.freeze

    module_function

    def phone_number(options = {})
      config = {
        expires_in: 300,
        otp_length: 6,
        allowed_attempts: 3,
        phone_number: "phoneNumber",
        phone_number_verified: "phoneNumberVerified"
      }.merge(normalize_hash(options))

      Plugin.new(
        id: "phone-number",
        hooks: {
          before: [
            {
              matcher: ->(ctx) { ctx.path == "/sign-up/email" && normalize_hash(ctx.body).key?(:phone_number) },
              handler: ->(ctx) { validate_unique_phone_number!(ctx, normalize_hash(ctx.body)[:phone_number]) }
            },
            {
              matcher: ->(ctx) { ctx.path == "/update-user" && normalize_hash(ctx.body).key?(:phone_number) },
              handler: ->(_ctx) { raise APIError.new("BAD_REQUEST", message: PHONE_NUMBER_ERROR_CODES["PHONE_NUMBER_CANNOT_BE_UPDATED"]) }
            }
          ]
        },
        endpoints: {
          sign_in_phone_number: sign_in_phone_number_endpoint(config),
          send_phone_number_otp: send_phone_number_otp_endpoint(config),
          verify_phone_number: verify_phone_number_endpoint(config),
          request_password_reset_phone_number: request_password_reset_phone_number_endpoint(config),
          reset_password_phone_number: reset_password_phone_number_endpoint(config)
        },
        schema: phone_number_schema(config[:schema]),
        rate_limit: [
          {
            path_matcher: ->(path) { path.start_with?("/phone-number") },
            window: 60,
            max: 10
          }
        ],
        error_codes: PHONE_NUMBER_ERROR_CODES,
        options: config
      )
    end

    def sign_in_phone_number_endpoint(config)
      Endpoint.new(
        path: "/sign-in/phone-number",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "signInPhoneNumber",
            description: "Sign in with phone number and password",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  phoneNumber: {type: "string"},
                  password: {type: "string"},
                  rememberMe: {type: ["boolean", "null"]}
                },
                required: ["phoneNumber", "password"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "Signed in",
                OpenAPI.object_schema(
                  {
                    token: {type: "string"},
                    user: {type: "object", "$ref": "#/components/schemas/User"}
                  },
                  required: ["token", "user"]
                )
              )
            }
          }
        }
      ) do |ctx|
        body = normalize_hash(ctx.body)
        phone_number = body[:phone_number].to_s
        password = body[:password].to_s
        validate_phone_number!(config, phone_number)

        found = ctx.context.adapter.find_one(model: "user", where: [{field: "phoneNumber", value: phone_number}])
        unless found
          Routes.hash_password(ctx, password)
          raise APIError.new("UNAUTHORIZED", message: PHONE_NUMBER_ERROR_CODES["INVALID_PHONE_NUMBER_OR_PASSWORD"])
        end

        if config[:require_verification] && !found["phoneNumberVerified"]
          code = phone_number_generate_code(config)
          phone_number_store_code(ctx, config, phone_number, code)
          phone_number_deliver_otp(config, {phone_number: phone_number, code: code}, ctx)
          raise APIError.new("UNAUTHORIZED", message: PHONE_NUMBER_ERROR_CODES["PHONE_NUMBER_NOT_VERIFIED"])
        end

        credential = ctx.context.internal_adapter.find_accounts(found["id"]).find { |entry| entry["providerId"] == "credential" }
        current_password = credential && credential["password"]
        unless current_password && Routes.verify_password_value(ctx, password, current_password)
          Routes.hash_password(ctx, password) unless current_password
          raise APIError.new("UNAUTHORIZED", message: PHONE_NUMBER_ERROR_CODES["INVALID_PHONE_NUMBER_OR_PASSWORD"])
        end

        dont_remember_me = body.key?(:remember_me) && (body[:remember_me] == false || body[:remember_me].to_s == "false")
        session = ctx.context.internal_adapter.create_session(found["id"], dont_remember_me)
        raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["FAILED_TO_CREATE_SESSION"]) unless session

        Cookies.set_session_cookie(ctx, {session: session, user: found}, dont_remember_me)
        ctx.json({token: session["token"], user: Schema.parse_output(ctx.context.options, "user", found)})
      end
    end

    def send_phone_number_otp_endpoint(config)
      Endpoint.new(
        path: "/phone-number/send-otp",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "sendPhoneNumberOTP",
            description: "Send a phone number OTP",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  phoneNumber: {type: "string"}
                },
                required: ["phoneNumber"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "OTP sent",
                OpenAPI.object_schema(
                  {
                    message: {type: "string"}
                  },
                  required: ["message"]
                )
              )
            }
          }
        }
      ) do |ctx|
        sender = config[:send_otp]
        unless sender.respond_to?(:call)
          raise APIError.new("NOT_IMPLEMENTED", message: PHONE_NUMBER_ERROR_CODES["SEND_OTP_NOT_IMPLEMENTED"])
        end

        body = normalize_hash(ctx.body)
        phone_number = body[:phone_number].to_s
        validate_phone_number!(config, phone_number)
        code = phone_number_generate_code(config)
        phone_number_store_code(ctx, config, phone_number, code)
        phone_number_deliver_otp(config, {phone_number: phone_number, code: code}, ctx)
        ctx.json({message: "code sent"})
      end
    end

    def verify_phone_number_endpoint(config)
      Endpoint.new(
        path: "/phone-number/verify",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "verifyPhoneNumber",
            description: "Verify a phone number OTP",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  phoneNumber: {type: "string"},
                  code: {type: "string"},
                  updatePhoneNumber: {type: ["boolean", "null"]},
                  disableSession: {type: ["boolean", "null"]}
                },
                required: ["phoneNumber", "code"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "Phone number verified",
                OpenAPI.object_schema(
                  {
                    status: {type: "boolean"},
                    token: {type: ["string", "null"]},
                    user: {type: "object", "$ref": "#/components/schemas/User"}
                  },
                  required: ["status", "user"]
                )
              )
            }
          }
        }
      ) do |ctx|
        body = normalize_hash(ctx.body)
        phone_number = body[:phone_number].to_s
        code = body[:code].to_s
        phone_number_verify_code!(ctx, config, phone_number, code)

        if truthy?(body[:update_phone_number])
          session = Routes.current_session(ctx)
          existing = ctx.context.adapter.find_many(model: "user", where: [{field: "phoneNumber", value: phone_number}])
          unless existing.empty?
            raise APIError.new("BAD_REQUEST", message: PHONE_NUMBER_ERROR_CODES["PHONE_NUMBER_EXIST"])
          end

          updated = ctx.context.internal_adapter.update_user(
            session[:user]["id"],
            phoneNumber: phone_number,
            phoneNumberVerified: true
          )
          next ctx.json({status: true, token: session[:session]["token"], user: Schema.parse_output(ctx.context.options, "user", updated)})
        end

        user = ctx.context.adapter.find_one(model: "user", where: [{field: "phoneNumber", value: phone_number}])
        user = if user
          ctx.context.internal_adapter.update_user(user["id"], phoneNumberVerified: true)
        elsif config[:sign_up_on_verification]
          phone_number_create_user(ctx, config, body, phone_number)
        end
        raise APIError.new("INTERNAL_SERVER_ERROR", message: BASE_ERROR_CODES["FAILED_TO_UPDATE_USER"]) unless user

        callback = config[:callback_on_verification]
        callback.call({phone_number: phone_number, user: user}, ctx) if callback.respond_to?(:call)

        if truthy?(body[:disable_session])
          next ctx.json({status: true, token: nil, user: Schema.parse_output(ctx.context.options, "user", user)})
        end

        session = ctx.context.internal_adapter.create_session(user["id"])
        raise APIError.new("INTERNAL_SERVER_ERROR", message: BASE_ERROR_CODES["FAILED_TO_CREATE_SESSION"]) unless session

        Cookies.set_session_cookie(ctx, {session: session, user: user})
        ctx.json({status: true, token: session["token"], user: Schema.parse_output(ctx.context.options, "user", user)})
      end
    end

    def request_password_reset_phone_number_endpoint(config)
      Endpoint.new(
        path: "/phone-number/request-password-reset",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "requestPasswordResetPhoneNumber",
            description: "Request a phone number password reset OTP",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  phoneNumber: {type: "string"}
                },
                required: ["phoneNumber"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("Password reset OTP requested", OpenAPI.status_response_schema)
            }
          }
        }
      ) do |ctx|
        body = normalize_hash(ctx.body)
        phone_number = body[:phone_number].to_s
        user = ctx.context.adapter.find_one(model: "user", where: [{field: "phoneNumber", value: phone_number}])
        code = phone_number_generate_code(config)
        phone_number_store_code(ctx, config, "#{phone_number}-request-password-reset", code)

        if user && config[:send_password_reset_otp].respond_to?(:call)
          config[:send_password_reset_otp].call({phone_number: phone_number, code: code}, ctx)
        end

        ctx.json({status: true})
      end
    end

    def reset_password_phone_number_endpoint(config)
      Endpoint.new(
        path: "/phone-number/reset-password",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "resetPasswordPhoneNumber",
            description: "Reset a password with a phone number OTP",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  phoneNumber: {type: "string"},
                  otp: {type: "string"},
                  newPassword: {type: "string"}
                },
                required: ["phoneNumber", "otp", "newPassword"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("Password reset", OpenAPI.status_response_schema)
            }
          }
        }
      ) do |ctx|
        body = normalize_hash(ctx.body)
        phone_number = body[:phone_number].to_s
        otp = body[:otp].to_s
        new_password = body[:new_password]

        verification = phone_number_verify_code!(ctx, config, "#{phone_number}-request-password-reset", otp, consume: false)
        user = ctx.context.adapter.find_one(model: "user", where: [{field: "phoneNumber", value: phone_number}])
        raise APIError.new("BAD_REQUEST", message: PHONE_NUMBER_ERROR_CODES["UNEXPECTED_ERROR"]) unless user

        Routes.validate_password_length!(new_password, ctx.context.options.email_and_password)
        ctx.context.internal_adapter.update_password(user["id"], Routes.hash_password(ctx, new_password))
        ctx.context.internal_adapter.delete_verification_value(verification["id"])
        ctx.context.internal_adapter.delete_sessions(user["id"]) if ctx.context.options.email_and_password[:revoke_sessions_on_password_reset]
        ctx.json({status: true})
      end
    end

    def phone_number_schema(custom_schema)
      base = {
        user: {
          fields: {
            phoneNumber: {type: "string", required: false, unique: true, sortable: true, returned: true},
            phoneNumberVerified: {type: "boolean", required: false, returned: true, input: false}
          }
        }
      }
      deep_merge_hashes(base, normalize_hash(custom_schema || {}))
    end

    def phone_number_create_user(ctx, config, body, phone_number)
      sign_up = config[:sign_up_on_verification]
      email_callback = sign_up[:get_temp_email]
      name_callback = sign_up[:get_temp_name]
      email = email_callback.respond_to?(:call) ? email_callback.call(phone_number) : "temp-#{phone_number}"
      name = name_callback.respond_to?(:call) ? name_callback.call(phone_number) : phone_number
      reserved = %i[phone_number code disable_session update_phone_number]
      additional = body.reject { |key, _value| reserved.include?(key.to_sym) }

      ctx.context.internal_adapter.create_user(
        additional.merge(
          "email" => email,
          "name" => name,
          "phoneNumber" => phone_number,
          "phoneNumberVerified" => true,
          "emailVerified" => false
        ),
        context: ctx
      )
    end

    def phone_number_verify_code!(ctx, config, identifier, code, consume: true)
      verifier = config[:verify_otp]
      if verifier.respond_to?(:call)
        valid = verifier.call({phone_number: identifier.delete_suffix("-request-password-reset"), code: code}, ctx)
        raise APIError.new("BAD_REQUEST", message: PHONE_NUMBER_ERROR_CODES["INVALID_OTP"]) unless valid

        verification = ctx.context.internal_adapter.find_verification_value(identifier)
        ctx.context.internal_adapter.delete_verification_value(verification["id"]) if consume && verification
        return verification || true
      end

      verification = ctx.context.internal_adapter.find_verification_value(identifier)
      raise APIError.new("BAD_REQUEST", message: PHONE_NUMBER_ERROR_CODES["OTP_NOT_FOUND"]) unless verification

      if Routes.expired_time?(verification["expiresAt"])
        raise APIError.new("BAD_REQUEST", message: PHONE_NUMBER_ERROR_CODES["OTP_EXPIRED"])
      end

      stored_code, attempts = phone_number_split_code(verification["value"])
      attempts_count = attempts.to_i
      if attempts_count >= config[:allowed_attempts].to_i
        ctx.context.internal_adapter.delete_verification_value(verification["id"])
        raise APIError.new("FORBIDDEN", message: PHONE_NUMBER_ERROR_CODES["TOO_MANY_ATTEMPTS"])
      end

      unless stored_code == code
        ctx.context.internal_adapter.update_verification_value(verification["id"], value: "#{stored_code}:#{attempts_count + 1}")
        raise APIError.new("BAD_REQUEST", message: PHONE_NUMBER_ERROR_CODES["INVALID_OTP"])
      end

      ctx.context.internal_adapter.delete_verification_value(verification["id"]) if consume
      verification
    end

    def phone_number_store_code(ctx, config, identifier, code)
      ctx.context.internal_adapter.delete_verification_by_identifier(identifier)
      ctx.context.internal_adapter.create_verification_value(
        identifier: identifier,
        value: "#{code}:0",
        expiresAt: Time.now + config[:expires_in].to_i
      )
    end

    def phone_number_deliver_otp(config, data, ctx)
      sender = config[:send_otp]
      sender.call(data, ctx) if sender.respond_to?(:call)
    end

    def validate_unique_phone_number!(ctx, phone_number)
      return if phone_number.to_s.empty?

      existing = ctx.context.adapter.find_one(model: "user", where: [{field: "phoneNumber", value: phone_number.to_s}])
      raise APIError.new("UNPROCESSABLE_ENTITY", message: PHONE_NUMBER_ERROR_CODES["PHONE_NUMBER_EXIST"]) if existing
    end

    def validate_phone_number!(config, phone_number)
      validator = config[:phone_number_validator]
      return unless validator.respond_to?(:call)
      return if validator.call(phone_number)

      raise APIError.new("BAD_REQUEST", message: PHONE_NUMBER_ERROR_CODES["INVALID_PHONE_NUMBER"])
    end

    def phone_number_generate_code(config)
      Array.new(config[:otp_length].to_i) { SecureRandom.random_number(10).to_s }.join
    end

    def phone_number_split_code(value)
      string = value.to_s
      index = string.rindex(":")
      return [string, ""] unless index

      [string[0...index], string[(index + 1)..]]
    end

    def truthy?(value)
      value == true || value.to_s == "true"
    end

    def deep_merge_hashes(base, override)
      base.merge(override) do |_key, old_value, new_value|
        if old_value.is_a?(Hash) && new_value.is_a?(Hash)
          deep_merge_hashes(old_value, new_value)
        else
          new_value
        end
      end
    end
  end
end

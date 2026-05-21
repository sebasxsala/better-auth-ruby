# frozen_string_literal: true

require "base64"
require "webauthn"

module BetterAuth
  module Passkey
    module Routes
      module Authentication
        module_function

        def generate_passkey_authentication_options_endpoint(config)
          Endpoint.new(path: "/passkey/generate-authenticate-options", method: "GET", metadata: Routes.openapi_for(:generate_authentication_options)) do |ctx|
            session = BetterAuth::Routes.current_session(ctx, allow_nil: true)
            relying_party = Utils.relying_party(config, ctx)
            passkeys = if session
              ctx.context.adapter.find_many(model: "passkey", where: [{field: "userId", value: session.fetch(:user).fetch("id")}])
            else
              []
            end
            get_options = {
              extensions: Utils.resolve_extensions(config.dig(:authentication, :extensions), ctx),
              relying_party: relying_party
            }
            get_options[:allow] = passkeys.map { |passkey| Credentials.credential_id(passkey) } if passkeys.any?
            options = WebAuthn::Credential.options_for_get(**get_options)
            Challenges.store_challenge(ctx, config, options.challenge, session ? session.fetch(:user).fetch("id") : "")
            payload = options.as_json.merge(userVerification: "preferred")
            payload.delete(:extensions) if payload[:extensions].nil? || payload[:extensions] == {}
            payload.delete("extensions") if payload["extensions"].nil? || payload["extensions"] == {}
            if passkeys.any?
              payload[:allowCredentials] = passkeys.map { |passkey| Credentials.credential_descriptor(passkey) }
            else
              payload.delete(:allowCredentials)
              payload.delete("allowCredentials")
            end
            ctx.json(payload)
          end
        end

        def verify_passkey_authentication_endpoint(config)
          Endpoint.new(path: "/passkey/verify-authentication", method: "POST", metadata: Routes.openapi_for(:verify_authentication)) do |ctx|
            body = Utils.normalize_hash(ctx.body)
            Utils.require_key!(body, :response)
            origin = Utils.origin(config, ctx)
            raise APIError.new("BAD_REQUEST", message: "origin missing") if origin.to_s.empty?

            verification_token = Challenges.challenge_token(ctx, config)
            raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND")) unless verification_token

            challenge = Challenges.find_challenge(ctx, verification_token)
            raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND")) unless challenge

            begin
              response = Credentials.webauthn_response(body[:response])
              credential_id = response.fetch("id")
              passkey = begin
                ctx.context.adapter.find_one(model: "passkey", where: [{field: "credentialID", value: credential_id}])
              rescue => error
                ctx.context.logger&.error("Failed to find passkey", error)
                raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("AUTHENTICATION_FAILED"))
              end
              raise APIError.new("UNAUTHORIZED", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND")) unless passkey

              relying_party = Utils.relying_party(config, ctx, origin: origin)
              credential = WebAuthn::Credential.from_get(response, relying_party: relying_party)
              credential.verify(
                challenge.fetch("expectedChallenge"),
                public_key: Base64.strict_decode64(passkey.fetch("publicKey")),
                sign_count: passkey.fetch("counter").to_i,
                user_verification: false
              )
              Utils.call_callback(config.dig(:authentication, :after_verification), {
                ctx: ctx,
                verification: credential,
                client_data: response
              })
              updated_passkey = ctx.context.adapter.update(
                model: "passkey",
                where: [{field: "id", value: passkey.fetch("id")}],
                update: {counter: credential.sign_count.to_i}
              )
              unless updated_passkey
                raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("AUTHENTICATION_FAILED"))
              end

              user = ctx.context.internal_adapter.find_user_by_id(passkey.fetch("userId"))
              raise APIError.new("INTERNAL_SERVER_ERROR", message: "User not found") unless user

              session = ctx.context.internal_adapter.create_session(passkey.fetch("userId"))
              raise APIError.new("INTERNAL_SERVER_ERROR", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("UNABLE_TO_CREATE_SESSION")) unless session

              Cookies.set_session_cookie(ctx, {session: session, user: user})
              ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
              ctx.json({session: session, user: user})
            rescue WebAuthn::Error, ArgumentError => error
              ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
              ctx.context.logger&.error("Failed to verify authentication", error)
              raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("AUTHENTICATION_FAILED"))
            rescue APIError
              ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
              raise
            rescue => error
              ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
              ctx.context.logger&.error("Failed to verify authentication", error)
              raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("AUTHENTICATION_FAILED"))
            end
          end
        end
      end
    end
  end
end

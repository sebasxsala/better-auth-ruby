# frozen_string_literal: true

require "base64"
require "webauthn"

module BetterAuth
  module Passkey
    module Routes
      module Registration
        module_function

        def generate_passkey_registration_options_endpoint(config)
          Endpoint.new(path: "/passkey/generate-register-options", method: "GET", metadata: Routes.openapi_for(:generate_registration_options)) do |ctx|
            query = Utils.normalize_hash(ctx.query)
            Utils.validate_authenticator_attachment!(query[:authenticator_attachment])
            user = Utils.resolve_registration_user(config, ctx, query)
            relying_party = Utils.relying_party(config, ctx)
            existing = ctx.context.adapter.find_many(model: "passkey", where: [{field: "userId", value: user.fetch("id")}])
            options = WebAuthn::Credential.options_for_create(
              user: {
                id: Crypto.random_string(32).downcase,
                name: query[:name].to_s.empty? ? (user["email"] || user["name"] || user["id"]) : query[:name].to_s,
                display_name: user["displayName"] || user["display_name"] || user["email"] || user["name"] || user["id"]
              },
              exclude: existing.map { |passkey| Credentials.credential_id(passkey) },
              authenticator_selection: Utils.authenticator_selection(config, query),
              extensions: Utils.resolve_extensions(config.dig(:registration, :extensions), ctx),
              relying_party: relying_party
            )
            Challenges.store_challenge(ctx, config, options.challenge, {
              id: user.fetch("id"),
              name: user["name"] || user["email"] || user["id"],
              displayName: user["displayName"] || user["display_name"]
            }.compact)
            payload = options.as_json.merge(attestation: "none", excludeCredentials: existing.map { |passkey| Credentials.credential_descriptor(passkey, kind: :exclude) })
            payload.delete(:extensions) if payload[:extensions].nil? || payload[:extensions] == {}
            payload.delete("extensions") if payload["extensions"].nil? || payload["extensions"] == {}
            ctx.json(payload)
          end
        end

        def verify_passkey_registration_endpoint(config)
          Endpoint.new(path: "/passkey/verify-registration", method: "POST", metadata: Routes.openapi_for(:verify_registration)) do |ctx|
            body = Utils.normalize_hash(ctx.body)
            Utils.require_key!(body, :response)
            require_session = config.dig(:registration, :require_session) != false
            session = require_session ? BetterAuth::Routes.current_session(ctx, sensitive: true, fresh: true) : BetterAuth::Routes.current_session(ctx, allow_nil: true)
            origin = Utils.origin(config, ctx)
            raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION")) if origin.to_s.empty?

            verification_token = Challenges.challenge_token(ctx, config)
            raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND")) unless verification_token

            challenge = Challenges.find_challenge(ctx, verification_token)
            unless challenge
              raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND"))
            end
            if session && challenge.fetch("userData").fetch("id") != session.fetch(:user).fetch("id")
              ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
              raise APIError.new("UNAUTHORIZED", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"))
            end

            begin
              response = Credentials.webauthn_response(body[:response])
              credential_id = Credentials.response_credential_id(response)
              if credential_id && ctx.context.adapter.find_one(model: "passkey", where: [{field: "credentialID", value: credential_id}])
                ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
                raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("PREVIOUSLY_REGISTERED"))
              end
              relying_party = Utils.relying_party(config, ctx, origin: origin)
              credential = WebAuthn::Credential.from_create(response, relying_party: relying_party)
              credential.verify(challenge.fetch("expectedChallenge"), user_verification: false)
              authenticator_data = Credentials.authenticator_data(credential)
              target_user_id = Utils.after_registration_verification_user_id(config, ctx, credential, challenge, response, session)
            rescue WebAuthn::Error, ArgumentError => error
              ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
              ctx.context.logger&.error("Failed to verify registration", error)
              raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"))
            rescue APIError
              ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
              raise
            end

            existing_passkey = ctx.context.adapter.find_one(model: "passkey", where: [{field: "credentialID", value: credential.id}])
            if existing_passkey
              ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
              raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("PREVIOUSLY_REGISTERED"))
            end

            begin
              data = ctx.context.adapter.create(
                model: "passkey",
                data: {
                  name: body[:name],
                  userId: target_user_id,
                  credentialID: credential.id,
                  publicKey: Base64.strict_encode64(credential.public_key),
                  counter: credential.sign_count.to_i,
                  deviceType: authenticator_data&.credential_backup_eligible? ? "multiDevice" : "singleDevice",
                  backedUp: authenticator_data&.credential_backed_up? || false,
                  transports: Array(Credentials.attestation_response(credential)&.transports).join(","),
                  createdAt: Time.now,
                  aaguid: Credentials.attestation_response(credential)&.aaguid
                }
              )
            rescue => error
              ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
              if Credentials.duplicate_credential_error?(error)
                raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("PREVIOUSLY_REGISTERED"))
              end
              ctx.context.logger&.error("Failed to create passkey", error)
              raise APIError.new("INTERNAL_SERVER_ERROR", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"))
            end
            ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
            ctx.json(Credentials.wire(data))
          rescue APIError
            raise
          rescue => error
            ctx.context.internal_adapter.delete_verification_by_identifier(verification_token) if verification_token
            ctx.context.logger&.error("Failed to verify registration", error)
            raise APIError.new("INTERNAL_SERVER_ERROR", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"))
          end
        end
      end
    end
  end
end

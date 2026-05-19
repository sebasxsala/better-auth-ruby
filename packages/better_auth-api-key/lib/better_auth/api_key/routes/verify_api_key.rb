# frozen_string_literal: true

module BetterAuth
  module APIKey
    module Routes
      module VerifyAPIKey
        UPSTREAM_SOURCE = "upstream/packages/api-key/src/routes/verify-api-key.ts"

        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(
            path: "/api-key/verify",
            method: "POST",
            body_schema: ->(value) { value },
            metadata: Routes.openapi_for(:verify_api_key)
          ) do |ctx|
            body = BetterAuth::Plugins.normalize_hash(ctx.body)
            resolved_config = BetterAuth::Plugins.api_key_resolve_config(ctx.context, config, body[:config_id])
            key = body[:key]
            if key.to_s.empty?
              raise BetterAuth::APIError.new(
                "FORBIDDEN",
                message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"],
                code: "INVALID_API_KEY"
              )
            end

            validation_config = body[:config_id] ? resolved_config : config_for_key(ctx, key, config)
            validation_config ||= resolved_config
            validator = validation_config[:custom_api_key_validator]
            if validator.respond_to?(:call) && !validator.call({ctx: ctx, key: key})
              ctx.json({valid: false, error: {message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"], code: "KEY_NOT_FOUND"}, key: nil})
            else
              record = BetterAuth::Plugins.api_key_validate!(ctx, key, validation_config, permissions: body[:permissions])
              record_config = BetterAuth::Plugins.api_key_resolve_config(ctx.context, config, BetterAuth::Plugins.api_key_record_config_id(record))
              BetterAuth::Plugins.api_key_schedule_cleanup(ctx, record_config)
              ctx.json({valid: true, error: nil, key: BetterAuth::Plugins.api_key_public(record, include_key_field: false)})
            end
          rescue BetterAuth::APIError => error
            ctx.context.logger.error("Failed to validate API key: #{error.message}") if ctx.context.logger.respond_to?(:error)
            ctx.json({valid: false, error: BetterAuth::Plugins.api_key_error_payload(error), key: nil})
          rescue => error
            ctx.context.logger.error("Failed to validate API key: #{error.message}") if ctx.context.logger.respond_to?(:error)
            ctx.json({valid: false, error: {message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"], code: "INVALID_API_KEY"}, key: nil})
          end
        end

        def config_for_key(ctx, key, config)
          config.fetch(:configurations, [config]).each do |entry|
            hashed = BetterAuth::Plugins.api_key_hash(key, entry)
            record = BetterAuth::Plugins.api_key_find_by_hash(ctx, hashed, entry)
            next unless record

            record_config_id = BetterAuth::Plugins.api_key_record_config_id(record)
            return entry if BetterAuth::Plugins.api_key_config_id_matches?(record_config_id, entry[:config_id])

            return BetterAuth::Plugins.api_key_resolve_config(ctx.context, config, record_config_id)
          end
          nil
        end
      end
    end
  end
end

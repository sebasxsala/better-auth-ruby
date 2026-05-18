# frozen_string_literal: true

module BetterAuth
  module APIKey
    module Routes
      module CreateAPIKey
        UPSTREAM_SOURCE = "upstream/packages/api-key/src/routes/create-api-key.ts"

        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/api-key/create", method: "POST") do |ctx|
            body = BetterAuth::Plugins.api_key_normalize_body(ctx.body)
            resolved_config = BetterAuth::Plugins.api_key_resolve_config(ctx.context, config, body[:config_id])
            session = BetterAuth::Routes.current_session(ctx, allow_nil: true)
            if !session && BetterAuth::Plugins.api_key_auth_required?(ctx)
              raise BetterAuth::APIError.new("UNAUTHORIZED", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"])
            end
            reference_id = BetterAuth::Plugins.api_key_create_reference_id!(ctx, body, session, resolved_config)

            BetterAuth::Plugins.api_key_validate_create_update!(body, resolved_config, create: true, client: !ctx.headers.empty?)
            BetterAuth::Plugins.api_key_delete_expired(ctx.context, resolved_config)
            key_prefix = body.key?(:prefix) ? body[:prefix] : resolved_config[:default_prefix]
            key = BetterAuth::Plugins.api_key_generate_key(resolved_config, key_prefix)
            now = Time.now
            hashed = BetterAuth::Plugins.api_key_hash(key, resolved_config)
            data = {
              configId: resolved_config[:config_id] || "default",
              name: body[:name],
              start: resolved_config[:starting_characters_config][:should_store] ? key[0, resolved_config[:starting_characters_config][:characters_length].to_i] : nil,
              prefix: key_prefix,
              key: hashed,
              referenceId: reference_id,
              enabled: true,
              rateLimitEnabled: body.key?(:rate_limit_enabled) ? body[:rate_limit_enabled] : resolved_config[:rate_limit][:enabled],
              rateLimitTimeWindow: body[:rate_limit_time_window] || resolved_config[:rate_limit][:time_window],
              rateLimitMax: body[:rate_limit_max] || resolved_config[:rate_limit][:max_requests],
              requestCount: 0,
              remaining: body.key?(:remaining) ? body[:remaining] : nil,
              refillAmount: body[:refill_amount],
              refillInterval: body[:refill_interval],
              lastRefillAt: nil,
              expiresAt: BetterAuth::Plugins.api_key_expires_at(body, resolved_config),
              createdAt: now,
              updatedAt: now,
              permissions: BetterAuth::Plugins.api_key_encode_json(body[:permissions] || BetterAuth::Plugins.api_key_default_permissions(resolved_config, reference_id, ctx)),
              metadata: body.key?(:metadata) ? BetterAuth::Plugins.api_key_encode_json(body[:metadata]) : nil
            }
            record = BetterAuth::Plugins.api_key_store(ctx, data, resolved_config)
            BetterAuth::Plugins.api_key_public(record, reveal_key: key, include_key_field: true)
          end
        end
      end
    end
  end
end

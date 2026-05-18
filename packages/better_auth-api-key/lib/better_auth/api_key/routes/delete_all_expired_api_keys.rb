# frozen_string_literal: true

module BetterAuth
  module APIKey
    module Routes
      module DeleteAllExpiredAPIKeys
        UPSTREAM_SOURCE = "upstream/packages/api-key/src/routes/delete-all-expired-api-keys.ts"

        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/api-key/delete-all-expired-api-keys", method: "POST") do |ctx|
            BetterAuth::APIKey::Routes.delete_expired(ctx.context, config, bypass_last_check: true, raise_on_error: true)
            ctx.json({success: true, error: nil})
          rescue => error
            ctx.context.logger.error("[API KEY PLUGIN] Failed to delete expired API keys: #{error.message}") if ctx.context.logger.respond_to?(:error)
            ctx.json({success: false, error: {message: error.message.to_s, name: error.class.name}})
          end
        end
      end
    end
  end
end

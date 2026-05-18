# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def scim_auth_middleware(config)
      lambda do |ctx|
        encoded = ctx.headers["authorization"].to_s.sub(/\ABearer\s+/i, "")
        raise scim_error("UNAUTHORIZED", "SCIM token is required") if encoded.empty?

        token, provider_id, organization_id = scim_decode_token(encoded)
        provider = scim_default_provider(config, provider_id, organization_id)
        if provider
          stored = provider.fetch("scimToken").to_s
          provided = token.to_s
          unless scim_token_string_matches?(stored, provided)
            raise scim_error("UNAUTHORIZED", "Invalid SCIM token")
          end
        else
          provider = ctx.context.adapter.find_one(
            model: "scimProvider",
            where: [{field: "providerId", value: provider_id}].tap { |where| where << {field: "organizationId", value: organization_id} if organization_id }
          )
          raise scim_error("UNAUTHORIZED", "Invalid SCIM token") unless provider
          raise scim_error("UNAUTHORIZED", "Invalid SCIM token") unless provider["organizationId"].to_s == organization_id.to_s
          raise scim_error("UNAUTHORIZED", "Invalid SCIM token") unless scim_token_matches?(ctx, config, token, provider.fetch("scimToken"))
        end

        ctx.context.apply_plugin_context!(scim_provider: provider)
        nil
      end
    end
  end
end

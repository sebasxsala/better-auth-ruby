# frozen_string_literal: true

module BetterAuth
  module SSO
    module Routes
      module SAMLPipeline
        module_function

        def process_response(ctx, config = {})
          BetterAuth::Plugins.sso_handle_saml_response(ctx, config)
        end

        def safe_redirect_url(ctx, url, provider_id)
          BetterAuth::Plugins.sso_safe_slo_redirect_url(ctx, url, provider_id)
        end
      end
    end
  end
end

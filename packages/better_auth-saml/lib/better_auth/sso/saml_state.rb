# frozen_string_literal: true

module BetterAuth
  module SSO
    module SAMLState
      module_function

      def generate_relay_state(ctx, link = nil, additional_data = {})
        callback_url = BetterAuth::Plugins.sso_fetch(ctx.body, :callback_url)
        raise BetterAuth::APIError.new("BAD_REQUEST", message: "callbackURL is required") if callback_url.to_s.empty?

        extra = (additional_data == false) ? {} : (additional_data || {})
        BetterAuth::Plugins.sso_generate_saml_relay_state(
          ctx,
          extra.merge(
            callbackURL: callback_url,
            errorURL: BetterAuth::Plugins.sso_fetch(ctx.body, :error_callback_url),
            newUserURL: BetterAuth::Plugins.sso_fetch(ctx.body, :new_user_callback_url),
            requestSignUp: BetterAuth::Plugins.sso_fetch(ctx.body, :request_sign_up),
            link: link
          )
        )
      end

      def parse_relay_state(ctx)
        BetterAuth::Plugins.sso_parse_saml_relay_state(ctx, BetterAuth::Plugins.sso_fetch(ctx.body, :relay_state))
      end
    end
  end
end

# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def paypal(client_id:, client_secret:, scopes: [], **options)
      sandbox = (options[:environment] || "sandbox").to_s == "sandbox"
      auth_host = sandbox ? "https://www.sandbox.paypal.com" : "https://www.paypal.com"
      api_host = sandbox ? "https://api-m.sandbox.paypal.com" : "https://api-m.paypal.com"
      provider = Base.oauth_provider(
        id: "paypal",
        name: "PayPal",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "#{auth_host}/signin/authorize",
        token_endpoint: "#{api_host}/v1/oauth2/token",
        user_info_endpoint: "#{api_host}/v1/identity/oauth2/userinfo?schema=paypalv1.1",
        scopes: scopes,
        pkce: true,
        profile_map: ->(profile) {
          {
            id: profile["user_id"],
            name: profile["name"],
            email: profile["email"],
            image: profile["picture"],
            emailVerified: !!profile["email_verified"]
          }
        },
        **options
      )
      provider.delete(:verify_id_token) unless provider[:verify_id_token]
      provider
    end
  end
end

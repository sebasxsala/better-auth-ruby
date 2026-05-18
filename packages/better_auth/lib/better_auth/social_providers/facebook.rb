# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def facebook(client_id:, client_secret:, scopes: ["email", "public_profile"], **options)
      fields = Array(options[:fields] || %w[id name email picture email_verified]).join(",")
      provider = Base.oauth_provider(
        id: "facebook",
        name: "Facebook",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "https://www.facebook.com/v24.0/dialog/oauth",
        token_endpoint: "https://graph.facebook.com/v24.0/oauth/access_token",
        user_info_endpoint: "https://graph.facebook.com/me?fields=#{URI.encode_www_form_component(fields)}",
        scopes: scopes,
        auth_params: ->(_data, opts) { {config_id: opts[:config_id] || opts[:configId]} },
        profile_map: ->(profile) {
          picture = profile.dig("picture", "data", "url") || profile["picture"]
          {
            id: profile["id"] || profile["sub"],
            name: profile["name"],
            email: profile["email"],
            image: picture,
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

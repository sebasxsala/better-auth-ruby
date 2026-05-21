# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def github(client_id:, client_secret:, scopes: ["read:user", "user:email"], **options)
      normalized = Base.normalize_options(options)
      token_endpoint = normalized[:token_endpoint] || "https://github.com/login/oauth/access_token"
      user_info_endpoint = normalized[:user_info_endpoint] || "https://api.github.com/user"
      emails_endpoint = normalized[:emails_endpoint] || "https://api.github.com/user/emails"
      {
        id: "github",
        name: "GitHub",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: lambda do |data|
          Base.authorization_url(options[:authorization_endpoint] || "https://github.com/login/oauth/authorize", {
            client_id: client_id,
            redirect_uri: data[:redirect_uri] || data[:redirectURI],
            scope: Base.selected_scopes(scopes, normalized, data),
            state: data[:state],
            login_hint: data[:loginHint] || data[:login_hint],
            prompt: options[:prompt]
          })
        end,
        validate_authorization_code: lambda do |data|
          Base.post_form(token_endpoint, {
            client_id: client_id,
            client_secret: client_secret,
            code: data[:code],
            code_verifier: data[:code_verifier] || data[:codeVerifier],
            redirect_uri: data[:redirect_uri] || data[:redirectURI]
          })
        end,
        get_user_info: lambda do |tokens|
          custom = normalized[:get_user_info]
          next custom.call(tokens) if custom

          headers = {
            "Authorization" => "Bearer #{Base.access_token(tokens)}",
            "Accept" => "application/json",
            "User-Agent" => "better-auth"
          }
          profile = Base.get_json(user_info_endpoint, headers)
          next nil unless profile

          emails = Base.get_json(emails_endpoint, headers)
          primary = Array(emails).find { |email| email["email"] == profile["email"] } ||
            Array(emails).find { |email| email["primary"] } ||
            Array(emails).first ||
            {}

          user = Base.apply_profile_mapping(
            {
              id: profile["id"].to_s,
              email: profile["email"] || primary["email"],
              name: profile["name"] || profile["login"],
              image: profile["avatar_url"],
              emailVerified: !!primary["verified"]
            },
            profile,
            normalized
          )
          {
            user: user,
            data: profile
          }
        end,
        refresh_access_token: options[:refresh_access_token] || options[:refreshAccessToken] || lambda do |refresh_token|
          Base.refresh_access_token(token_endpoint, refresh_token, client_id: client_id, client_secret: client_secret)
        end
      }
    end
  end
end

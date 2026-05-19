# frozen_string_literal: true

module BetterAuthExamples
  module SocialProviderCatalog
    PROVIDERS = [
      {factory: :apple, id: "apple", name: "Apple", extras: {app_bundle_identifier: "APP_BUNDLE_IDENTIFIER"}},
      {factory: :atlassian, id: "atlassian", name: "Atlassian"},
      {factory: :cognito, id: "cognito", name: "Cognito", extras: {domain: "DOMAIN", region: "REGION", issuer: "ISSUER"}},
      {factory: :discord, id: "discord", name: "Discord"},
      {factory: :dropbox, id: "dropbox", name: "Dropbox"},
      {factory: :facebook, id: "facebook", name: "Facebook"},
      {factory: :figma, id: "figma", name: "Figma"},
      {factory: :github, id: "github", name: "GitHub"},
      {factory: :gitlab, id: "gitlab", name: "GitLab", extras: {issuer: "ISSUER"}},
      {factory: :google, id: "google", name: "Google"},
      {factory: :huggingface, id: "huggingface", name: "Hugging Face"},
      {factory: :kakao, id: "kakao", name: "Kakao"},
      {factory: :kick, id: "kick", name: "Kick"},
      {factory: :line, id: "line", name: "Line"},
      {factory: :linear, id: "linear", name: "Linear"},
      {factory: :linkedin, id: "linkedin", name: "LinkedIn"},
      {factory: :microsoft, id: "microsoft", name: "Microsoft", extras: {tenant_id: "TENANT_ID"}},
      {factory: :microsoft_entra_id, id: "microsoft-entra-id", name: "Microsoft Entra ID", env: "MICROSOFT_ENTRA_ID", extras: {tenant_id: "TENANT_ID"}},
      {factory: :naver, id: "naver", name: "Naver"},
      {factory: :notion, id: "notion", name: "Notion"},
      {factory: :paybin, id: "paybin", name: "Paybin", extras: {issuer: "ISSUER"}},
      {factory: :paypal, id: "paypal", name: "PayPal", extras: {environment: "ENVIRONMENT"}},
      {factory: :polar, id: "polar", name: "Polar"},
      {factory: :railway, id: "railway", name: "Railway"},
      {factory: :reddit, id: "reddit", name: "Reddit"},
      {factory: :roblox, id: "roblox", name: "Roblox"},
      {factory: :salesforce, id: "salesforce", name: "Salesforce", extras: {environment: "ENVIRONMENT", login_url: "LOGIN_URL"}},
      {factory: :slack, id: "slack", name: "Slack"},
      {factory: :spotify, id: "spotify", name: "Spotify"},
      {factory: :tiktok, id: "tiktok", name: "TikTok", extras: {client_key: "CLIENT_KEY"}},
      {factory: :twitch, id: "twitch", name: "Twitch"},
      {factory: :twitter, id: "twitter", name: "Twitter"},
      {factory: :vercel, id: "vercel", name: "Vercel"},
      {factory: :vk, id: "vk", name: "VK"},
      {factory: :wechat, id: "wechat", name: "WeChat"},
      {factory: :zoom, id: "zoom", name: "Zoom"}
    ].freeze

    module_function

    def all
      PROVIDERS
    end

    def configured
      PROVIDERS.each_with_object({}) do |definition, result|
        provider = build_provider(definition)
        result[definition.fetch(:id).tr("-", "_").to_sym] = provider if provider
      end
    end

    def metadata
      configured_ids = configured.values.map { |provider| provider.fetch(:id) }
      PROVIDERS.map do |definition|
        {
          id: definition.fetch(:id),
          lookup_id: lookup_id(definition),
          name: definition.fetch(:name),
          configured: configured_ids.include?(definition.fetch(:id))
        }
      end
    end

    def build_provider(definition)
      prefix = env_prefix(definition)
      client_id = env_value("#{prefix}_CLIENT_ID")
      client_secret = env_value("#{prefix}_CLIENT_SECRET")
      return nil if client_id.empty? || client_secret.empty?

      options = options_for(definition, prefix)
      scopes = env_value("#{prefix}_SCOPES")
      options[:scopes] = scopes.split(/[,\s]+/).reject(&:empty?) unless scopes.empty?

      BetterAuth::SocialProviders.public_send(
        definition.fetch(:factory),
        client_id: client_id,
        client_secret: client_secret,
        **options
      )
    end

    def options_for(definition, prefix)
      definition.fetch(:extras, {}).each_with_object({}) do |(option, suffix), result|
        value = env_value("#{prefix}_#{suffix}")
        result[option] = value unless value.empty?
      end
    end

    def env_prefix(definition)
      "BETTER_AUTH_#{(definition[:env] || definition.fetch(:id)).tr("-", "_").upcase}"
    end

    def lookup_id(definition)
      definition.fetch(:id).tr("-", "_")
    end

    def env_value(key)
      ENV[key].to_s.strip
    end
  end
end

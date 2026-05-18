# frozen_string_literal: true

require "uri"
require "openssl"
require_relative "../test_helper"

class BetterAuthSocialProvidersTest < Minitest::Test
  def test_google_authorization_url_shape
    provider = BetterAuth::SocialProviders.google(client_id: "google-id", client_secret: "google-secret")

    url = provider.fetch(:create_authorization_url).call(
      state: "state-1",
      code_verifier: "verifier-1",
      redirect_uri: "http://localhost:3000/api/auth/callback/google",
      scopes: ["openid", "email", "profile"],
      loginHint: "ada@example.com"
    )

    assert_equal "google", provider.fetch(:id)
    assert_includes url, "https://accounts.google.com/o/oauth2/v2/auth"
    assert_includes url, "client_id=google-id"
    assert_includes url, "scope=openid+email+profile"
    assert_includes url, "state=state-1"
    assert_includes url, "code_challenge="
    assert_includes url, "code_challenge_method=S256"
    assert_includes url, "login_hint=ada%40example.com"
  end

  def test_google_and_vercel_require_code_verifier_for_authorization_url
    google = BetterAuth::SocialProviders.google(client_id: "google-id", client_secret: "google-secret")
    vercel = BetterAuth::SocialProviders.vercel(client_id: "vercel-id", client_secret: "vercel-secret")

    assert_raises(BetterAuth::Error) do
      google.fetch(:create_authorization_url).call(
        state: "state-1",
        redirect_uri: "http://localhost:3000/api/auth/callback/google"
      )
    end
    assert_raises(BetterAuth::Error) do
      vercel.fetch(:create_authorization_url).call(
        state: "state-1",
        redirect_uri: "http://localhost:3000/api/auth/callback/vercel"
      )
    end
  end

  def test_google_uses_first_configured_client_id_for_authorization_url
    provider = BetterAuth::SocialProviders.google(client_id: ["web-id", "ios-id"], client_secret: "google-secret")

    url = provider.fetch(:create_authorization_url).call(
      state: "state-1",
      code_verifier: "verifier-1",
      redirect_uri: "http://localhost:3000/api/auth/callback/google"
    )

    assert_includes url, "client_id=web-id"
    refute_includes url, "ios-id"
  end

  def test_apple_uses_first_configured_client_id_for_authorization_url
    provider = BetterAuth::SocialProviders.apple(client_id: ["web-id", "ios-id"], client_secret: "apple-secret")

    url = provider.fetch(:create_authorization_url).call(
      state: "state-1",
      redirect_uri: "http://localhost:3000/api/auth/callback/apple"
    )

    assert_includes url, "client_id=web-id"
    refute_includes url, "ios-id"
  end

  def test_widened_multi_client_id_providers_use_first_entry_for_authorization_url
    providers = [
      BetterAuth::SocialProviders.facebook(client_id: ["fb-web", "fb-mobile"], client_secret: "facebook-secret"),
      BetterAuth::SocialProviders.cognito(client_id: ["cog-web", "cog-mobile"], client_secret: "cognito-secret", domain: "https://cognito.example")
    ]

    providers.each do |provider|
      url = provider.fetch(:create_authorization_url).call(
        state: "state-1",
        code_verifier: "verifier-1",
        redirect_uri: "http://localhost:3000/api/auth/callback/#{provider.fetch(:id)}"
      )

      client_id = Rack::Utils.parse_query(URI.parse(url).query).fetch("client_id")
      expected_client_id = (provider.fetch(:id) == "facebook") ? "fb-web" : "cog-web"
      assert_equal expected_client_id, client_id
    end
  end

  def test_empty_client_id_array_is_rejected_for_widened_providers
    [
      -> { BetterAuth::SocialProviders.google(client_id: [], client_secret: "secret") },
      -> { BetterAuth::SocialProviders.apple(client_id: [], client_secret: "secret") },
      -> { BetterAuth::SocialProviders.facebook(client_id: [], client_secret: "secret").fetch(:create_authorization_url).call(state: "state") },
      -> { BetterAuth::SocialProviders.cognito(client_id: [], client_secret: "secret").fetch(:create_authorization_url).call(state: "state") }
    ].each do |factory|
      error = assert_raises(BetterAuth::Error) { factory.call }
      assert_equal "CLIENT_ID_AND_SECRET_REQUIRED", error.message
    end
  end

  def test_google_id_token_verifier_rejects_unconfigured_audience
    key = OpenSSL::PKey::RSA.generate(2048)
    jwks = {"keys" => [rsa_public_jwk(key, "google-kid")]}
    provider = BetterAuth::SocialProviders.google(client_id: ["web-id", "ios-id"], client_secret: "google-secret", jwks: jwks)

    assert provider.fetch(:verify_id_token).call(signed_jwt(key, "google-kid", "iss" => "https://accounts.google.com", "aud" => "ios-id", "sub" => "sub-1"))
    refute provider.fetch(:verify_id_token).call(signed_jwt(key, "google-kid", "iss" => "https://accounts.google.com", "aud" => "android-id", "sub" => "sub-1"))
    refute provider.fetch(:verify_id_token).call(fake_jwt("iss" => "https://accounts.google.com", "aud" => "ios-id", "sub" => "sub-1"))
  end

  def test_id_token_jwks_timeout_returns_invalid_token_result
    provider = BetterAuth::SocialProviders.google(
      client_id: "google-id",
      client_secret: "google-secret",
      jwks_endpoint: "https://issuer.example/jwks"
    )

    Net::HTTP.stub(:start, ->(*_args, **_kwargs) { raise Net::OpenTimeout }) do
      refute provider.fetch(:verify_id_token).call(fake_jwt("iss" => "https://accounts.google.com", "aud" => "google-id", "sub" => "sub-1"))
    end
  end

  def test_apple_id_token_verifier_uses_jwks_and_audience_override
    key = OpenSSL::PKey::RSA.generate(2048)
    provider = BetterAuth::SocialProviders.apple(
      client_id: "web-id",
      client_secret: "apple-secret",
      audience: "bundle-id",
      jwks: {"keys" => [rsa_public_jwk(key, "apple-kid")]}
    )

    assert provider.fetch(:verify_id_token).call(signed_jwt(key, "apple-kid", "iss" => "https://appleid.apple.com", "aud" => "bundle-id", "sub" => "apple-sub"))
    refute provider.fetch(:verify_id_token).call(signed_jwt(key, "apple-kid", "iss" => "https://appleid.apple.com", "aud" => "web-id", "sub" => "apple-sub"))
  end

  def test_microsoft_id_token_verifier_validates_specific_tenant_issuer
    key = OpenSSL::PKey::RSA.generate(2048)
    provider = BetterAuth::SocialProviders.microsoft(
      client_id: "microsoft-id",
      tenant_id: "tenant-1",
      jwks: {"keys" => [rsa_public_jwk(key, "microsoft-kid")]}
    )

    assert provider.fetch(:verify_id_token).call(signed_jwt(key, "microsoft-kid", "iss" => "https://login.microsoftonline.com/tenant-1/v2.0", "aud" => "microsoft-id", "sub" => "ms-sub"))
    refute provider.fetch(:verify_id_token).call(signed_jwt(key, "microsoft-kid", "iss" => "https://login.microsoftonline.com/other/v2.0", "aud" => "microsoft-id", "sub" => "ms-sub"))
  end

  def test_github_authorization_url_shape
    provider = BetterAuth::SocialProviders.github(client_id: "github-id", client_secret: "github-secret")

    url = provider.fetch(:create_authorization_url).call(
      state: "state-1",
      redirect_uri: "http://localhost:3000/api/auth/callback/github",
      scopes: ["user:email"]
    )

    assert_equal "github", provider.fetch(:id)
    assert_includes url, "https://github.com/login/oauth/authorize"
    assert_includes url, "client_id=github-id"
    assert_includes Rack::Utils.parse_query(URI.parse(url).query).fetch("scope").split(" "), "user:email"
  end

  def test_github_uses_endpoint_overrides_for_token_and_user_info
    captured_urls = []
    post_form = lambda do |url, _form, _headers = {}|
      captured_urls << url
      {"access_token" => "github-access"}
    end
    get_json = lambda do |url, _headers = {}|
      captured_urls << url
      if url.include?("/emails")
        [{"email" => "octo@example.com", "primary" => true, "verified" => true}]
      else
        {"id" => 123, "login" => "octo", "name" => "Octo", "email" => nil, "avatar_url" => "https://example.com/octo.png"}
      end
    end

    info = nil
    BetterAuth::SocialProviders::Base.stub(:post_form_json, post_form) do
      BetterAuth::SocialProviders::Base.stub(:get_json, get_json) do
        provider = BetterAuth::SocialProviders.github(
          client_id: "github-id",
          client_secret: "github-secret",
          token_endpoint: "https://github.test/token",
          user_info_endpoint: "https://github.test/user",
          emails_endpoint: "https://github.test/emails"
        )
        provider.fetch(:validate_authorization_code).call(code: "code", redirect_uri: "http://localhost/callback")
        info = provider.fetch(:get_user_info).call(accessToken: "github-access")
      end
    end

    assert_includes captured_urls, "https://github.test/token"
    assert_includes captured_urls, "https://github.test/user"
    assert_includes captured_urls, "https://github.test/emails"
    assert_equal "octo@example.com", info.fetch(:user).fetch(:email)
  end

  def test_factories_exist_for_selected_common_providers
    assert_equal "gitlab", BetterAuth::SocialProviders.gitlab(client_id: "id", client_secret: "secret").fetch(:id)
    assert_equal "discord", BetterAuth::SocialProviders.discord(client_id: "id", client_secret: "secret").fetch(:id)
    assert_equal "apple", BetterAuth::SocialProviders.apple(client_id: "id", client_secret: "secret").fetch(:id)
    assert_equal "microsoft-entra-id",
      BetterAuth::SocialProviders.microsoft_entra_id(client_id: "id", client_secret: "secret", tenant_id: "common").fetch(:id)
  end

  def test_factories_exist_for_all_upstream_social_providers
    expected = {
      apple: "apple",
      atlassian: "atlassian",
      cognito: "cognito",
      discord: "discord",
      dropbox: "dropbox",
      facebook: "facebook",
      figma: "figma",
      github: "github",
      gitlab: "gitlab",
      google: "google",
      huggingface: "huggingface",
      kakao: "kakao",
      kick: "kick",
      line: "line",
      linear: "linear",
      linkedin: "linkedin",
      microsoft: "microsoft",
      microsoft_entra_id: "microsoft-entra-id",
      naver: "naver",
      notion: "notion",
      paybin: "paybin",
      paypal: "paypal",
      polar: "polar",
      railway: "railway",
      reddit: "reddit",
      roblox: "roblox",
      salesforce: "salesforce",
      slack: "slack",
      spotify: "spotify",
      tiktok: "tiktok",
      twitch: "twitch",
      twitter: "twitter",
      vercel: "vercel",
      vk: "vk",
      wechat: "wechat",
      zoom: "zoom"
    }

    expected.each do |factory, id|
      provider = BetterAuth::SocialProviders.public_send(factory, client_id: "id", client_secret: "secret")
      assert_equal id, provider.fetch(:id), "#{factory} should expose upstream provider id"
      assert provider.fetch(:create_authorization_url), "#{factory} should create authorization URLs"
      assert provider.fetch(:validate_authorization_code), "#{factory} should validate authorization codes"
      assert provider.fetch(:get_user_info), "#{factory} should fetch user info"
    end
  end

  def test_base_normalizes_oauth_token_expiration_fields
    now = Time.utc(2026, 4, 29, 12, 0, 0)
    tokens = BetterAuth::SocialProviders::Base.normalize_tokens(
      {
        "access_token" => "access-token",
        "refresh_token" => "refresh-token",
        "id_token" => "id-token",
        "expires_in" => 60,
        "refresh_token_expires_in" => 120,
        "scope" => "openid email",
        "token_type" => "Bearer"
      },
      now: now
    )

    assert_equal "access-token", tokens.fetch("accessToken")
    assert_equal "refresh-token", tokens.fetch("refreshToken")
    assert_equal "id-token", tokens.fetch("idToken")
    assert_equal now + 60, tokens.fetch("accessTokenExpiresAt")
    assert_equal now + 120, tokens.fetch("refreshTokenExpiresAt")
    assert_equal "openid,email", tokens.fetch("scope")
    assert_equal "Bearer", tokens.fetch("tokenType")
  end

  def test_generic_provider_applies_profile_mapping_override
    provider = BetterAuth::SocialProviders::Base.oauth_provider(
      id: "example",
      name: "Example",
      client_id: "id",
      client_secret: "secret",
      authorization_endpoint: "https://provider.example/authorize",
      token_endpoint: "https://provider.example/token",
      user_info_endpoint: "https://provider.example/userinfo",
      profile_map: ->(profile) {
        {
          id: profile.fetch("sub"),
          name: profile.fetch("name"),
          email: profile.fetch("email"),
          image: profile.fetch("picture"),
          emailVerified: profile.fetch("email_verified")
        }
      },
      get_user_info: ->(_tokens) {
        {
          "sub" => "profile-id",
          "name" => "Profile Name",
          "email" => "profile@example.com",
          "picture" => "https://example.com/avatar.png",
          "email_verified" => false
        }
      },
      map_profile_to_user: ->(_profile) { {name: "Mapped Name", emailVerified: true} }
    )

    info = provider.fetch(:get_user_info).call("accessToken" => "token")

    assert_equal "profile-id", info.fetch(:user).fetch(:id)
    assert_equal "Mapped Name", info.fetch(:user).fetch(:name)
    assert_equal true, info.fetch(:user).fetch(:emailVerified)
  end

  def test_existing_providers_append_configured_and_requested_scopes
    provider = BetterAuth::SocialProviders.discord(client_id: "discord-id", client_secret: "discord-secret", scope: ["guilds"])

    url = provider.fetch(:create_authorization_url).call(
      state: "state-1",
      redirect_uri: "http://localhost:3000/api/auth/callback/discord",
      scopes: ["bot"]
    )

    scope = Rack::Utils.parse_query(URI.parse(url).query).fetch("scope")
    assert_equal ["identify", "email", "guilds", "bot"], scope.split(" ")
  end

  def test_apple_applies_profile_mapping_override
    provider = BetterAuth::SocialProviders.apple(
      client_id: "apple-id",
      client_secret: "apple-secret",
      map_profile_to_user: ->(_profile) { {name: "Mapped Apple", emailVerified: false} }
    )

    info = provider.fetch(:get_user_info).call(
      idToken: fake_jwt("sub" => "apple-sub", "email" => "apple@example.com", "email_verified" => true, "name" => "Token Name")
    )

    assert_equal "Mapped Apple", info.fetch(:user).fetch(:name)
    assert_equal false, info.fetch(:user).fetch(:emailVerified)
  end

  def test_apple_does_not_use_email_as_name_fallback
    provider = BetterAuth::SocialProviders.apple(client_id: "apple-id", client_secret: "apple-secret")

    info = provider.fetch(:get_user_info).call(
      idToken: fake_jwt("sub" => "apple-sub", "email" => "relay@example.com", "email_verified" => true)
    )

    assert_equal "", info.fetch(:user).fetch(:name)
  end

  def test_vercel_provider_maps_preferred_username_scopes_pkce_and_overrides
    provider = BetterAuth::SocialProviders.vercel(
      client_id: "vercel-id",
      client_secret: "vercel-secret",
      scope: ["team:read"],
      get_user_info: ->(_tokens) {
        {
          "sub" => "vercel-sub",
          "preferred_username" => "vercel-user",
          "email" => "vercel@example.com",
          "email_verified" => true
        }
      },
      map_profile_to_user: ->(_profile) { {name: "Mapped Vercel"} }
    )

    url = provider.fetch(:create_authorization_url).call(
      state: "state-1",
      code_verifier: "verifier-1",
      redirect_uri: "http://localhost:3000/api/auth/callback/vercel",
      scopes: ["project:read"]
    )
    params = Rack::Utils.parse_query(URI.parse(url).query)

    assert_equal "Vercel", provider.fetch(:name)
    assert_equal "vercel-id", params.fetch("client_id")
    assert_equal ["team:read", "project:read"], params.fetch("scope").split(" ")
    assert_equal BetterAuth::SocialProviders::Base.pkce_challenge("verifier-1"), params.fetch("code_challenge")
    assert_equal "S256", params.fetch("code_challenge_method")

    info = provider.fetch(:get_user_info).call(accessToken: "vercel-access")
    assert_equal "Mapped Vercel", info.fetch(:user).fetch(:name)
  end

  def test_railway_provider_maps_email_unverified_by_default
    provider = BetterAuth::SocialProviders.railway(
      client_id: "railway-id",
      client_secret: "railway-secret",
      get_user_info: ->(_tokens) {
        {
          "sub" => "railway-sub",
          "name" => "Railway User",
          "email" => "railway@example.com"
        }
      }
    )

    info = provider.fetch(:get_user_info).call(accessToken: "railway-access")

    assert_equal "Railway", provider.fetch(:name)
    assert_equal false, info.fetch(:user).fetch(:emailVerified)
  end

  def test_railway_validate_authorization_code_uses_basic_auth_header
    captured_form = nil
    captured_headers = nil
    post_form = lambda do |_url, form, headers = {}|
      captured_form = form
      captured_headers = headers
      {"access_token" => "railway-access"}
    end

    provider = BetterAuth::SocialProviders.railway(client_id: "railway-id", client_secret: "railway-secret")
    BetterAuth::SocialProviders::Base.stub(:post_form_json, post_form) do
      provider.fetch(:validate_authorization_code).call(
        code: "code-1",
        code_verifier: "verifier-1",
        redirect_uri: "http://localhost:3000/api/auth/callback/railway"
      )
    end

    assert_equal "Basic #{Base64.strict_encode64("railway-id:railway-secret")}", captured_headers.fetch("Authorization")
    refute_includes captured_form.keys, :client_id
    refute_includes captured_form.keys, :client_secret
  end

  def test_railway_refresh_access_token_uses_basic_auth_header
    captured_form = nil
    captured_headers = nil
    post_form = lambda do |_url, form, headers = {}|
      captured_form = form
      captured_headers = headers
      {"access_token" => "railway-access"}
    end

    provider = BetterAuth::SocialProviders.railway(client_id: "railway-id", client_secret: "railway-secret")
    BetterAuth::SocialProviders::Base.stub(:post_form_json, post_form) do
      provider.fetch(:refresh_access_token).call("railway-refresh")
    end

    assert_equal "Basic #{Base64.strict_encode64("railway-id:railway-secret")}", captured_headers.fetch("Authorization")
    assert_equal "refresh_token", captured_form.fetch(:grant_type)
    refute_includes captured_form.keys, :client_id
    refute_includes captured_form.keys, :client_secret
  end

  def test_wechat_validate_authorization_code_uses_appid_secret_and_get_endpoint
    captured_url = nil
    get_json = lambda do |url, _headers = {}|
      captured_url = url
      {
        "access_token" => "wechat-access",
        "refresh_token" => "wechat-refresh",
        "expires_in" => 7200,
        "openid" => "openid-1",
        "unionid" => "union-1",
        "scope" => "snsapi_login"
      }
    end
    post_form = lambda do |_url, _form, _headers = {}|
      flunk "WeChat token exchange should use GET with appid and secret"
    end

    provider = BetterAuth::SocialProviders.wechat(client_id: "wx-app", client_secret: "wx-secret")
    tokens = nil
    BetterAuth::SocialProviders::Base.stub(:post_form_json, post_form) do
      BetterAuth::SocialProviders::Base.stub(:get_json, get_json) do
        tokens = provider.fetch(:validate_authorization_code).call(code: "code-1")
      end
    end

    params = Rack::Utils.parse_query(URI.parse(captured_url).query)
    assert_equal "wx-app", params.fetch("appid")
    assert_equal "wx-secret", params.fetch("secret")
    assert_equal "code-1", params.fetch("code")
    assert_equal "authorization_code", params.fetch("grant_type")
    assert_equal "wechat-access", tokens.fetch("accessToken")
    assert_equal "openid-1", tokens.fetch("openid")
    assert_equal "union-1", tokens.fetch("unionid")
  end

  def test_wechat_authorization_url_uses_default_lang
    provider = BetterAuth::SocialProviders.wechat(client_id: "wx-app", client_secret: "wx-secret")

    url = provider.fetch(:create_authorization_url).call(
      state: "state-1",
      redirect_uri: "http://localhost:3000/api/auth/callback/wechat"
    )

    assert_equal "wechat_redirect", URI.parse(url).fragment
    params = Rack::Utils.parse_query(URI.parse(url).query)
    assert_equal "wx-app", params.fetch("appid")
    assert_equal "cn", params.fetch("lang")
  end

  def test_wechat_refresh_access_token_uses_appid_and_get_endpoint
    captured_url = nil
    get_json = lambda do |url, _headers = {}|
      captured_url = url
      {
        "access_token" => "wechat-access",
        "refresh_token" => "wechat-refresh",
        "expires_in" => 7200,
        "openid" => "openid-1",
        "scope" => "snsapi_login"
      }
    end

    provider = BetterAuth::SocialProviders.wechat(client_id: "wx-app", client_secret: "wx-secret")
    tokens = nil
    BetterAuth::SocialProviders::Base.stub(:get_json, get_json) do
      tokens = provider.fetch(:refresh_access_token).call("wechat-refresh")
    end

    params = Rack::Utils.parse_query(URI.parse(captured_url).query)
    assert_equal "wx-app", params.fetch("appid")
    assert_equal "refresh_token", params.fetch("grant_type")
    assert_equal "wechat-refresh", params.fetch("refresh_token")
    refute params.key?("secret")
    assert_equal "openid-1", tokens.fetch("openid")
  end

  def test_wechat_get_user_info_uses_openid_and_maps_unionid_fallback
    captured_url = nil
    get_json = lambda do |url, _headers = {}|
      captured_url = url
      {
        "openid" => "openid-1",
        "unionid" => "union-1",
        "nickname" => "WeChat User",
        "headimgurl" => "https://wechat.example/avatar.png"
      }
    end

    provider = BetterAuth::SocialProviders.wechat(client_id: "wx-app", client_secret: "wx-secret")
    info = nil
    BetterAuth::SocialProviders::Base.stub(:get_json, get_json) do
      info = provider.fetch(:get_user_info).call("accessToken" => "wechat-access", "openid" => "openid-1")
    end

    params = Rack::Utils.parse_query(URI.parse(captured_url).query)
    assert_equal "wechat-access", params.fetch("access_token")
    assert_equal "openid-1", params.fetch("openid")
    assert_equal "zh_CN", params.fetch("lang")
    assert_equal "union-1", info.fetch(:user).fetch(:id)
    assert_equal "WeChat User", info.fetch(:user).fetch(:name)
    assert_nil info.fetch(:user).fetch(:email)
    assert_equal false, info.fetch(:user).fetch(:emailVerified)
  end

  def test_wechat_get_user_info_returns_nil_without_openid
    provider = BetterAuth::SocialProviders.wechat(client_id: "wx-app", client_secret: "wx-secret")

    assert_nil provider.fetch(:get_user_info).call("accessToken" => "wechat-access")
  end

  def test_discord_null_email_can_be_synthesized_with_profile_mapping
    get_json = lambda do |_url, _headers = {}|
      {
        "id" => "discord-id",
        "username" => "phoneonly",
        "global_name" => nil,
        "email" => nil,
        "verified" => false,
        "avatar" => nil,
        "discriminator" => "0"
      }
    end
    provider = BetterAuth::SocialProviders.discord(
      client_id: "discord-id",
      client_secret: "discord-secret",
      map_profile_to_user: ->(profile) { {email: "#{profile.fetch("id")}@discord.local", emailVerified: true} }
    )

    info = nil
    BetterAuth::SocialProviders::Base.stub(:get_json, get_json) do
      info = provider.fetch(:get_user_info).call(accessToken: "discord-access")
    end

    assert_equal "discord-id@discord.local", info.fetch(:user).fetch(:email)
    assert_equal true, info.fetch(:user).fetch(:emailVerified)
  end

  def test_discord_default_avatar_uses_snowflake_for_modern_accounts
    assert_equal "https://cdn.discordapp.com/embed/avatars/2.png",
      BetterAuth::SocialProviders.discord_avatar_url({"id" => "175928847299117063", "discriminator" => "0", "avatar" => nil})
  end

  def test_microsoft_refresh_access_token_includes_scope_param
    captured_form = nil
    post_form = lambda do |_url, form, _headers = {}|
      captured_form = form
      {"access_token" => "new-access"}
    end

    provider = BetterAuth::SocialProviders.microsoft(client_id: "microsoft-id", client_secret: "secret", scope: ["Calendars.Read"])
    BetterAuth::SocialProviders::Base.stub(:post_form_json, post_form) do
      provider.fetch(:refresh_access_token).call("refresh-token")
    end

    assert_equal "openid profile email User.Read offline_access Calendars.Read", captured_form.fetch(:scope)
  end

  def test_microsoft_get_user_info_fetches_profile_photo_data_uri
    captured_url = nil
    captured_headers = nil
    get_bytes = lambda do |url, headers = {}|
      captured_url = url
      captured_headers = headers
      "jpeg-bytes"
    end

    provider = BetterAuth::SocialProviders.microsoft(client_id: "microsoft-id", profile_photo_size: 64)
    info = nil
    BetterAuth::SocialProviders::Base.stub(:get_bytes, get_bytes) do
      info = provider.fetch(:get_user_info).call(
        idToken: fake_jwt("sub" => "ms-sub", "email" => "microsoft@example.com", "name" => "Microsoft User", "email_verified" => true),
        accessToken: "access-token"
      )
    end

    assert_equal "https://graph.microsoft.com/v1.0/me/photos/64x64/$value", captured_url
    assert_equal "Bearer access-token", captured_headers.fetch("Authorization")
    assert_equal "data:image/jpeg;base64, anBlZy1ieXRlcw==", info.fetch(:user).fetch(:image)
  end

  private

  def signed_jwt(private_key, kid, payload)
    claims = {
      "iat" => Time.now.to_i,
      "exp" => Time.now.to_i + 3600
    }.merge(payload)
    JWT.encode(claims, private_key, "RS256", kid: kid)
  end

  def rsa_public_jwk(key, kid)
    {
      "kid" => kid,
      "alg" => "RS256",
      "kty" => "RSA",
      "use" => "sig",
      "n" => base64url_bn(key.n),
      "e" => base64url_bn(key.e)
    }
  end

  def base64url_bn(number)
    hex = number.to_s(16)
    hex = "0#{hex}" if hex.length.odd?
    Base64.urlsafe_encode64([hex].pack("H*"), padding: false)
  end

  def fake_jwt(payload)
    encoded_header = Base64.urlsafe_encode64(JSON.generate({"alg" => "none"}), padding: false)
    encoded_payload = Base64.urlsafe_encode64(JSON.generate(payload), padding: false)
    "#{encoded_header}.#{encoded_payload}."
  end
end

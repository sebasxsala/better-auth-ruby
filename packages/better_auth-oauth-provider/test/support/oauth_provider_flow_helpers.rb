# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "rack/mock"
require "uri"

module OAuthProviderFlowHelpers
  SECRET = "phase-eleven-secret-with-enough-entropy-123"

  def build_auth(options = {})
    BetterAuth.auth(
      base_url: options.delete(:base_url) || "http://localhost:3000",
      secret: options.delete(:secret) || SECRET,
      database: options.delete(:database) || :memory,
      secondary_storage: options.delete(:secondary_storage),
      session: options.delete(:session),
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.oauth_provider({scopes: ["read", "write"], allow_dynamic_client_registration: true}.merge(options))]
    )
  end

  def sign_up_cookie(auth, email: "oauth-provider@example.com", name: "OAuth Owner")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: name},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def pkce_verifier
    "a" * 64
  end

  def alternate_pkce_verifier
    "b" * 64
  end

  def pkce_challenge(verifier = pkce_verifier)
    Base64.urlsafe_encode64(OpenSSL::Digest.digest("SHA256", verifier), padding: false)
  end

  def create_client(auth, cookie, overrides = {})
    auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token", "client_credentials"],
        response_types: ["code"],
        client_name: "OAuth Client",
        scope: "openid profile email offline_access read write"
      }.merge(overrides)
    )
  end

  def register_client(auth, cookie = nil, overrides = {})
    headers = cookie ? {"cookie" => cookie} : {}
    auth.api.register_o_auth_client(
      headers: headers,
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Registered OAuth Client",
        scope: "openid profile email offline_access"
      }.merge(overrides)
    )
  end

  def authorize_response(auth, cookie, client, scope:, redirect_uri: "https://resource.example/callback", state: "state-token", prompt: nil, verifier: pkce_verifier, extra: {})
    query = {
      response_type: "code",
      client_id: client[:client_id],
      redirect_uri: redirect_uri,
      scope: scope,
      state: state
    }.merge(extra)
    if verifier
      query[:code_challenge] = pkce_challenge(verifier)
      query[:code_challenge_method] = "S256"
    end
    query[:prompt] = prompt if prompt
    auth.api.o_auth2_authorize(headers: {"cookie" => cookie}, query: query, as_response: true)
  end

  def extract_redirect_params(headers)
    Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
  end

  def issue_authorization_code_tokens(auth, cookie, client, scope:, redirect_uri: "https://resource.example/callback", state: "state-token", nonce: nil, verifier: pkce_verifier, resource: nil)
    status, headers, = authorize_response(
      auth,
      cookie,
      client,
      scope: scope,
      redirect_uri: redirect_uri,
      state: state,
      prompt: "consent",
      verifier: verifier,
      extra: {nonce: nonce}.compact
    )
    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    if params["code"]
      return auth.api.o_auth2_token(
        body: {
          grant_type: "authorization_code",
          code: params.fetch("code"),
          redirect_uri: redirect_uri,
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          code_verifier: verifier,
          resource: resource
        }.compact
      )
    end

    flunk("expected authorize redirect to include code or consent_code, got #{params.inspect}") unless params["consent_code"]

    consent_code = params.fetch("consent_code")
    consent = auth.api.o_auth2_consent(
      headers: {"cookie" => cookie},
      body: {accept: true, consent_code: consent_code}
    )
    code = Rack::Utils.parse_query(URI.parse(consent.fetch(:redirectURI)).query).fetch("code")
    token_body = {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: redirect_uri,
      client_id: client[:client_id],
      client_secret: client[:client_secret],
      code_verifier: verifier
    }
    token_body[:resource] = resource if resource
    auth.api.o_auth2_token(body: token_body)
  end

  def authorization_code_for(auth, cookie, client, scope:, redirect_uri: "https://resource.example/callback", verifier: pkce_verifier, prompt: nil)
    status, headers, = authorize_response(auth, cookie, client, scope: scope, redirect_uri: redirect_uri, prompt: prompt, verifier: verifier)
    assert_equal 302, status
    params = extract_redirect_params(headers)
    return params.fetch("code") if params["code"]

    flunk("expected authorize redirect to include code or consent_code, got #{params.inspect}") unless params["consent_code"]

    consent = auth.api.o_auth2_consent(headers: {"cookie" => cookie}, body: {accept: true, consent_code: params.fetch("consent_code")})
    Rack::Utils.parse_query(URI.parse(consent.fetch(:redirectURI)).query).fetch("code")
  end

  def refresh_grant_body(client, refresh_token, scope: nil, resource: nil)
    {
      grant_type: "refresh_token",
      refresh_token: refresh_token,
      client_id: client[:client_id],
      client_secret: client[:client_secret],
      scope: scope,
      resource: resource
    }.compact
  end

  def introspect_body(client, token, hint: "access_token")
    {
      token: token,
      token_type_hint: hint,
      client_id: client[:client_id],
      client_secret: client[:client_secret]
    }.compact
  end

  def revoke_body(client, token, hint: nil)
    {
      token: token,
      token_type_hint: hint,
      client_id: client[:client_id],
      client_secret: client[:client_secret]
    }.compact
  end

  def decode_id_token(token, client)
    key = OpenSSL::HMAC.hexdigest("SHA256", SECRET, "oidc.id_token.#{client[:client_id]}")
    JWT.decode(token, key, true, algorithm: "HS256").first
  end

  def rack_env(method, path, body: nil, headers: {})
    Rack::MockRequest.env_for(
      path,
      :method => method,
      "CONTENT_TYPE" => "application/json",
      :input => body ? JSON.generate(body) : nil
    ).merge(headers)
  end

  def pairwise_client_body(redirect_uri)
    {
      redirect_uris: [redirect_uri],
      token_endpoint_auth_method: "client_secret_post",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "openid",
      subject_type: "pairwise"
    }
  end
end

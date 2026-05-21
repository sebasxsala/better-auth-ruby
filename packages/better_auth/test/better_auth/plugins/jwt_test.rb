# frozen_string_literal: true

require "jwt"
require "tempfile"
require_relative "../../test_helper"

class BetterAuthPluginsJWTTest < Minitest::Test
  SECRET = "phase-seven-secret-with-enough-entropy-123"

  def test_jwt_plugin_issues_token_header_and_jwks
    auth = build_auth(plugins: [BetterAuth::Plugins.jwt])
    cookie = sign_up_cookie(auth, email: "jwt@example.com")

    _status, headers, _body = auth.api.get_session(headers: {"cookie" => cookie}, as_response: true)
    token = headers.fetch("set-auth-jwt")
    jwks = auth.api.get_jwks

    assert_equal 1, jwks[:keys].length
    verified = auth.api.verify_jwt(body: {token: token})
    _decoded, header = JWT.decode(token, nil, false)
    decoded = verified[:payload]
    assert_equal "jwt@example.com", decoded.fetch("email")
    assert_equal decoded.fetch("id"), decoded.fetch("sub")
    assert_equal jwks[:keys].first[:kid], header.fetch("kid")
    assert_equal "EdDSA", jwks[:keys].first[:alg]
  end

  def test_jwt_plugin_persists_generated_jwks_with_sql_adapters
    require "sqlite3"

    Tempfile.create(["better-auth-jwt", ".sqlite3"]) do |file|
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      auth = build_auth(
        database: ->(options) { BetterAuth::Adapters::SQLite.new(options, connection: connection) },
        plugins: [BetterAuth::Plugins.jwt]
      )
      BetterAuth::Schema::SQL.create_statements(auth.options, dialect: :sqlite).each { |statement| connection.execute(statement) }
      cookie = sign_up_cookie(auth, email: "jwt-sql@example.com")

      _status, headers, _body = auth.api.get_session(headers: {"cookie" => cookie}, as_response: true)
      stored = auth.context.adapter.find_many(model: "jwks")

      assert headers.fetch("set-auth-jwt")
      assert_equal 1, stored.length
      assert stored.first.fetch("id")
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  def test_jwt_plugin_token_sign_and_verify_endpoints
    auth = build_auth(plugins: [BetterAuth::Plugins.jwt(jwt: {issuer: "https://issuer.example", audience: "ruby"})])
    cookie = sign_up_cookie(auth, email: "jwt-token@example.com")

    issued = auth.api.get_token(headers: {"cookie" => cookie})
    verified = auth.api.verify_jwt(body: {token: issued[:token], issuer: "https://issuer.example"})
    signed = auth.api.sign_jwt(body: {payload: {sub: "manual", aud: "ruby", iss: "https://issuer.example"}})

    assert_equal "jwt-token@example.com", verified[:payload]["email"]
    assert_match(/\A[\w-]+\.[\w-]+\.[\w-]+\z/, signed[:token])
  end

  def test_jwt_header_can_be_disabled
    auth = build_auth(plugins: [BetterAuth::Plugins.jwt(disable_setting_jwt_header: true)])
    cookie = sign_up_cookie(auth, email: "jwt-disabled-header@example.com")

    _status, headers, _body = auth.api.get_session(headers: {"cookie" => cookie}, as_response: true)

    refute headers.key?("set-auth-jwt")
  end

  def test_jwt_supports_custom_payload_and_subject
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.jwt(
          jwt: {
            define_payload: ->(session) { {"email" => session[:user]["email"], "role" => "admin"} },
            get_subject: ->(session) { "user:#{session[:user]["id"]}" }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "jwt-payload@example.com")

    token = auth.api.get_token(headers: {"cookie" => cookie})
    payload = auth.api.verify_jwt(body: {token: token[:token]})[:payload]

    assert_equal "jwt-payload@example.com", payload.fetch("email")
    assert_equal "admin", payload.fetch("role")
    assert_match(/\Auser:/, payload.fetch("sub"))
  end

  def test_jwt_verify_uses_base_url_as_default_issuer_and_audience
    auth = build_auth(plugins: [BetterAuth::Plugins.jwt])
    valid = auth.api.sign_jwt(body: {payload: {sub: "default-claims"}})
    wrong_issuer = auth.api.sign_jwt(body: {payload: {sub: "wrong-issuer", iss: "https://issuer.example", aud: "http://localhost:3000/api/auth"}})
    wrong_audience = auth.api.sign_jwt(body: {payload: {sub: "wrong-audience", iss: "http://localhost:3000/api/auth", aud: "https://audience.example"}})

    assert_equal "default-claims", auth.api.verify_jwt(body: {token: valid[:token]})[:payload]["sub"]
    assert_nil auth.api.verify_jwt(body: {token: wrong_issuer[:token]})[:payload]
    assert_nil auth.api.verify_jwt(body: {token: wrong_audience[:token]})[:payload]
  end

  def test_jwt_verify_rejects_payloads_without_subject_or_audience
    auth = build_auth(plugins: [BetterAuth::Plugins.jwt])
    auth.api.sign_jwt(body: {payload: {sub: "seed-key"}})
    key = auth.context.adapter.find_many(model: "jwks").first
    private_key = OpenSSL::PKey.read(BetterAuth::Crypto.symmetric_decrypt(key: SECRET, data: key.fetch("privateKey")))
    missing_sub = BetterAuth::Plugins.encode_eddsa_jwt(
      {"aud" => "http://localhost:3000/api/auth", "iss" => "http://localhost:3000/api/auth", "exp" => Time.now.to_i + 60},
      private_key,
      key.fetch("id")
    )
    missing_aud = BetterAuth::Plugins.encode_eddsa_jwt(
      {"sub" => "missing-aud", "iss" => "http://localhost:3000/api/auth", "exp" => Time.now.to_i + 60},
      private_key,
      key.fetch("id")
    )

    assert_nil auth.api.verify_jwt(body: {token: missing_sub})[:payload]
    assert_nil auth.api.verify_jwt(body: {token: missing_aud})[:payload]
  end

  def test_jwks_path_can_be_customized
    auth = build_auth(plugins: [BetterAuth::Plugins.jwt(jwks: {jwks_path: "/.well-known/jwks.json"})])

    custom_status, _custom_headers, custom_body = auth.call(rack_env("GET", "/api/auth/.well-known/jwks.json"))
    default_status, _default_headers, = auth.call(rack_env("GET", "/api/auth/jwks"))

    assert_equal 200, custom_status
    assert JSON.parse(custom_body.join).fetch("keys").any?
    assert_equal 404, default_status
  end

  def test_private_key_is_encrypted_by_default_and_plain_when_disabled
    encrypted_auth = build_auth(plugins: [BetterAuth::Plugins.jwt])
    encrypted_auth.api.sign_jwt(body: {payload: {sub: "encrypted"}})
    encrypted_key = encrypted_auth.context.adapter.find_many(model: "jwks").first.fetch("privateKey")

    refute_match(/\ABEGIN /, encrypted_key)
    assert BetterAuth::Crypto.symmetric_decrypt(key: SECRET, data: encrypted_key)

    plain_auth = build_auth(plugins: [BetterAuth::Plugins.jwt(jwks: {disable_private_key_encryption: true})])
    plain_auth.api.sign_jwt(body: {payload: {sub: "plain"}})
    plain_key = plain_auth.context.adapter.find_many(model: "jwks").first.fetch("privateKey")

    assert_match(/BEGIN/, plain_key)
  end

  def test_encrypted_private_key_survives_secret_rotation
    old_auth = build_auth(
      secrets: [{version: 1, value: "old-jwt-plugin-secret-with-enough-entropy"}],
      plugins: [BetterAuth::Plugins.jwt]
    )
    old_auth.api.sign_jwt(body: {payload: {sub: "seed"}})

    new_auth = build_auth(
      database: old_auth.context.adapter,
      secrets: [
        {version: 2, value: "new-jwt-plugin-secret-with-enough-entropy"},
        {version: 1, value: "old-jwt-plugin-secret-with-enough-entropy"}
      ],
      plugins: [BetterAuth::Plugins.jwt]
    )

    signed = new_auth.api.sign_jwt(body: {payload: {sub: "rotated-private-key"}})

    assert_equal "rotated-private-key", new_auth.api.verify_jwt(body: {token: signed[:token]})[:payload]["sub"]
  end

  def test_jwt_rotates_keys_when_latest_key_is_expired
    storage = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.jwt(
          jwks: {rotation_interval: 60},
          adapter: {
            get_jwks: ->(_ctx) { storage },
            create_jwk: ->(data, _ctx) {
              key = data.merge("id" => "key-#{storage.length + 1}")
              storage << key
              key
            }
          }
        )
      ]
    )

    auth.api.sign_jwt(body: {payload: {sub: "user-1"}})
    storage.first["expiresAt"] = Time.now - 1
    auth.api.sign_jwt(body: {payload: {sub: "user-1"}})

    assert_equal 2, storage.length
    refute_equal storage.first.fetch("id"), storage.last.fetch("id")
  end

  def test_jwks_returns_expired_keys_within_grace_period
    storage = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.jwt(
          jwks: {rotation_interval: 60, grace_period: 1},
          adapter: {
            get_jwks: ->(_ctx) { storage },
            create_jwk: ->(data, _ctx) {
              key = data.merge("id" => "key-#{storage.length + 1}")
              storage << key
              key
            }
          }
        )
      ]
    )

    auth.api.sign_jwt(body: {payload: {sub: "user-1"}})
    storage.first["expiresAt"] = Time.now - 0.5
    auth.api.sign_jwt(body: {payload: {sub: "user-1"}})

    assert_equal ["key-1", "key-2"], auth.api.get_jwks[:keys].map { |key| key[:kid] }

    storage.first["expiresAt"] = Time.now - 2

    assert_equal ["key-2"], auth.api.get_jwks[:keys].map { |key| key[:kid] }
  end

  def test_jwt_supports_rsa_ps_and_ec_signing_algorithms
    {
      "EdDSA" => {kty: "OKP", crv: "Ed25519", verifier: nil},
      "RS256" => {kty: "RSA", verifier: "RS256"},
      "PS256" => {kty: "RSA", verifier: "PS256"},
      "ES256" => {kty: "EC", crv: "P-256", verifier: "ES256"},
      "ES512" => {kty: "EC", crv: "P-521", verifier: "ES512"}
    }.each do |alg, expected|
      auth = build_auth(plugins: [BetterAuth::Plugins.jwt(jwks: {key_pair_config: {alg: alg}})])
      signed = auth.api.sign_jwt(body: {payload: {sub: "subject-#{alg}", aud: "http://localhost:3000/api/auth", iss: "http://localhost:3000/api/auth"}})
      jwk = auth.api.get_jwks[:keys].first

      decoded, header = if expected[:verifier]
        JWT.decode(signed[:token], BetterAuth::Plugins::JWT.public_key(jwk), true, algorithm: expected.fetch(:verifier))
      else
        [auth.api.verify_jwt(body: {token: signed[:token]})[:payload], JWT.decode(signed[:token], nil, false).last]
      end

      assert_equal "subject-#{alg}", decoded.fetch("sub")
      assert_equal alg, header.fetch("alg")
      assert_equal jwk[:kid], header.fetch("kid")
      assert_equal expected.fetch(:kty), jwk[:kty]
      assert_equal expected[:crv], jwk[:crv] if expected[:crv]
    end
  end

  def test_jwt_rejects_unsupported_jose_algorithms_with_a_documented_error
    error = assert_raises(BetterAuth::Error) do
      build_auth(plugins: [BetterAuth::Plugins.jwt(jwks: {key_pair_config: {alg: "HS256"}})])
    end

    assert_match(/HS256/, error.message)
  end

  def test_verify_jwt_uses_kid_selection_and_rejects_unknown_kid
    auth = build_auth(plugins: [BetterAuth::Plugins.jwt])
    first = auth.api.sign_jwt(body: {payload: {sub: "first"}})
    first_kid = auth.context.adapter.find_many(model: "jwks").first.fetch("id")
    auth.context.adapter.update(
      model: "jwks",
      where: [{field: "id", value: first_kid}],
      update: {"expiresAt" => Time.now - 1}
    )
    second = auth.api.sign_jwt(body: {payload: {sub: "second"}})

    assert_equal "first", auth.api.verify_jwt(body: {token: first[:token]})[:payload]["sub"]
    assert_equal "second", auth.api.verify_jwt(body: {token: second[:token]})[:payload]["sub"]

    tampered = first[:token].split(".")
    tampered[0] = BetterAuth::Crypto.base64url_encode(JSON.generate({"alg" => "RS256", "kid" => "missing"}))

    assert_nil auth.api.verify_jwt(body: {token: tampered.join(".")})[:payload]
  end

  def test_verify_jwt_can_validate_remote_jwks_with_pem_or_modulus
    pair = OpenSSL::PKey::RSA.generate(2048)
    token = JWT.encode(
      {
        sub: "remote-user",
        aud: "https://issuer.example",
        iss: "https://issuer.example",
        exp: Time.now.to_i + 60
      },
      pair,
      "RS256",
      kid: "remote-key"
    )
    remote_key = {
      kid: "remote-key",
      kty: "RSA",
      alg: "RS256",
      use: "sig",
      n: BetterAuth::Plugins.base64url_bn(pair.public_key.n),
      e: BetterAuth::Plugins.base64url_bn(pair.public_key.e),
      pem: pair.public_key.to_pem
    }
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.jwt(
          jwks: {
            remote_url: "https://issuer.example/.well-known/jwks.json",
            key_pair_config: {alg: "RS256"},
            fetch: ->(_url) { {"keys" => [remote_key]} }
          },
          jwt: {issuer: "https://issuer.example", audience: "https://issuer.example"}
        )
      ]
    )

    assert_equal "remote-user", auth.api.verify_jwt(body: {token: token})[:payload]["sub"]
    assert_raises(BetterAuth::APIError) { auth.api.get_jwks }
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "JWT User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def rack_env(method, path)
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(""),
      "CONTENT_LENGTH" => "0"
    }
  end
end

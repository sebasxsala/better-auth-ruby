# frozen_string_literal: true

require "forwardable"
require "json"
require "stringio"
require "webauthn/fake_client"
require_relative "../../test_helper"

module BetterAuthPasskeyTestSupport
  SECRET = "phase-eight-secret-with-enough-entropy-123"
  ORIGIN = "http://localhost:3000"

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({
      base_url: ORIGIN,
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.passkey]
    }.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Passkey User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def create_passkey(auth, user_id:, name:, credential_id: "#{name}-credential", transports: "internal", aaguid: nil)
    auth.context.adapter.create(
      model: "passkey",
      data: {
        userId: user_id,
        name: name,
        publicKey: "mock-public-key",
        credentialID: credential_id,
        counter: 0,
        deviceType: "singleDevice",
        backedUp: false,
        transports: transports,
        createdAt: Time.now,
        aaguid: aaguid
      }
    )
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def rack_env(method, path, body: "", query: "", headers: {})
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => query,
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(body),
      "CONTENT_TYPE" => "application/json",
      "CONTENT_LENGTH" => body.bytesize.to_s
    }.merge(headers)
  end

  def passkey_round_trip(auth, email:)
    cookie = sign_up_cookie(auth, email: email)
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    client = WebAuthn::FakeClient.new(ORIGIN)

    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    registration_response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    passkey = auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {name: "Adapter key", response: registration_response}
    )

    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")
    status, headers, body = auth.api.verify_passkey_authentication(
      headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
      body: {response: assertion},
      as_response: true
    )

    listed = auth.api.list_passkeys(headers: {"cookie" => cookie})
    updated = auth.api.update_passkey(headers: {"cookie" => cookie}, body: {id: passkey.fetch("id"), name: "Renamed adapter key"})
    updated_passkey = auth.context.adapter.find_one(model: "passkey", where: [{field: "id", value: passkey.fetch("id")}])
    deleted = auth.api.delete_passkey(headers: {"cookie" => cookie}, body: {id: passkey.fetch("id")})

    {
      cookie: cookie,
      user: user,
      passkey: passkey,
      auth_status: status,
      auth_headers: headers,
      auth_body: JSON.parse(body.join),
      updated_passkey: updated_passkey,
      listed: listed,
      updated: updated,
      deleted: deleted
    }
  end

  def assert_passkey_round_trip(result, email:)
    passkey = result.fetch(:passkey)
    auth_body = result.fetch(:auth_body)

    assert_equal email, result.fetch(:user).fetch("email")
    assert_equal "Adapter key", passkey.fetch("name")
    assert_equal result.fetch(:user).fetch("id"), passkey.fetch("userId")
    assert passkey.fetch("publicKey")
    assert_equal 0, passkey.fetch("counter")
    assert_equal "singleDevice", passkey.fetch("deviceType")
    assert_equal 200, result.fetch(:auth_status)
    assert_includes result.fetch(:auth_headers).fetch("set-cookie"), "better-auth.session_token="
    assert_equal email, auth_body.fetch("user").fetch("email")
    assert_operator result.fetch(:updated_passkey).fetch("counter"), :>, 0
    assert_equal [passkey.fetch("id")], result.fetch(:listed).map { |entry| entry.fetch("id") }
    assert_equal "Renamed adapter key", result.fetch(:updated).fetch(:passkey).fetch("name")
    assert_equal({status: true}, result.fetch(:deleted))
  end

  def create_sql_schema(connection, config, dialect:)
    BetterAuth::Schema::SQL.create_statements(config, dialect: dialect).each do |statement|
      case dialect
      when :postgres
        connection.exec(statement)
      when :mysql
        connection.query(statement)
      when :mssql
        connection.run(statement)
      else
        connection.execute(statement)
      end
    end
  end

  class MemorySecondaryStorage
    attr_reader :data, :ttls

    def initialize
      @data = {}
      @ttls = {}
    end

    def get(key)
      data[key]
    end

    def set(key, value, ttl = nil, **_options)
      data[key] = value
      ttls[key] = ttl if ttl
      value
    end

    def delete(key)
      data.delete(key)
      ttls.delete(key)
    end
  end

  class RateLimitStorage
    attr_reader :data, :ttls

    def initialize
      @data = {}
      @ttls = {}
    end

    def get(key)
      data[key]
    end

    def set(key, value, ttl:, update: false)
      data[key] = value
      ttls[key] = ttl
    end
  end
end

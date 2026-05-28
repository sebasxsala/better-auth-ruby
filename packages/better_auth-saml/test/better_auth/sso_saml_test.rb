# frozen_string_literal: true

require "better_auth/sso"
require "base64"
require "json"
require "openssl"
require "rack/mock"
require "zlib"
require_relative "../test_helper"

class BetterAuthPluginsSSOSAMLTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_sso_saml_hooks_merge_default_parser_options
    base = {organization_provisioning: {role: "admin"}, saml: {validate_response: ->(**) { true }}}
    parser_options = {saml: {parse_response: ->(**) { {email: "ada@example.com"} }}}

    merged = BetterAuth::SSO::SAMLHooks.merge_options(base, parser_options)

    assert_equal "admin", merged.dig(:organization_provisioning, :role)
    assert merged.dig(:saml, :validate_response)
    assert merged.dig(:saml, :parse_response)
  end

  def test_saml_response_parser_applies_upstream_mapping_fields
    response = Struct.new(:attributes, :nameid, :assertion_id, :sessionindex) do
      def is_valid?
        true
      end
    end.new(
      {
        "employeeNumber" => "saml-user-123",
        "mail" => "Mapped@Example.COM",
        "verified" => true,
        "display" => "Mapped Display",
        "first" => "Mapped",
        "last" => "User",
        "departmentName" => "Engineering"
      },
      "fallback@example.com",
      "assertion-123",
      "session-123"
    )
    provider = {
      "providerId" => "saml",
      "issuer" => "https://idp.example.com",
      "samlConfig" => {
        "entryPoint" => "https://idp.example.com/sso",
        "mapping" => {
          "id" => "employeeNumber",
          "email" => "mail",
          "emailVerified" => "verified",
          "name" => "display",
          "firstName" => "first",
          "lastName" => "last",
          "extraFields" => {"department" => "departmentName"}
        }
      }
    }
    context = Struct.new(:context).new(Struct.new(:base_url).new("http://localhost:3000/api/auth"))

    raw_response = Base64.strict_encode64("<Response><Assertion ID=\"assertion-123\"/></Response>")

    with_singleton_method(OneLogin::RubySaml::Response, :new, ->(*) { response }) do
      parsed = BetterAuth::SSO::SAML.response_parser.call(raw_response: raw_response, provider: provider, context: context)

      assert_equal "saml-user-123", parsed.fetch(:id)
      assert_equal "mapped@example.com", parsed.fetch(:email)
      assert_equal true, parsed.fetch(:email_verified)
      assert_equal "Mapped User", parsed.fetch(:name)
      assert_equal "Engineering", parsed.fetch(:department)
    end
  end

  def test_saml_metadata_authn_request_rejects_json_response_by_default
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          cert: "test-cert",
          callbackUrl: "http://localhost:3000/saml/callback",
          audience: "better-auth-ruby",
          spMetadata: {entityId: "http://localhost:3000/api/auth/sso/saml2/sp/metadata"}
        }
      }
    )

    metadata = auth.api.sp_metadata(query: {providerId: "saml", format: "json"})
    assert_equal "saml", metadata.fetch(:providerId)
    assert_includes metadata.fetch(:metadata), "EntityDescriptor"

    sign_in = auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})
    uri = URI.parse(sign_in[:url])
    params = Rack::Utils.parse_query(uri.query)
    assert_equal "https://idp.example.com/sso", "#{uri.scheme}://#{uri.host}#{uri.path}"
    assert params.fetch("SAMLRequest")
    assert params.fetch("RelayState")

    response = Base64.strict_encode64(JSON.generate({email: "saml@example.com", name: "SAML User", id: "saml-sub"}))
    status, _headers, body = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: response, RelayState: params.fetch("RelayState")},
      headers: {"origin" => "https://idp.example.com"},
      as_response: true
    )

    assert_equal 400, status
    assert_includes body.join, "Invalid SAML response"
    assert_nil auth.context.internal_adapter.find_user_by_email("saml@example.com")
  end

  def test_saml_rejects_malicious_relay_state_and_replayed_response
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(raw_response:, **_data) { JSON.parse(Base64.decode64(raw_response), symbolize_names: true) }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )
    sign_in = auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "https://evil.example.com"})
    relay_state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("RelayState")
    response = Base64.strict_encode64(JSON.generate({email: "saml@example.com", name: "SAML User", id: "assertion-1"}))

    status, headers, _body = auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: response, RelayState: relay_state}, as_response: true)
    assert_equal 302, status
    refute_includes headers.fetch("location"), "evil.example.com"

    replay_status, replay_headers, _replay_body = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: response, RelayState: relay_state},
      as_response: true
    )
    assert_equal 302, replay_status
    assert_equal "http://localhost:3000/api/auth?error=replay_detected&error_description=SAML+assertion+has+already+been+used", replay_headers.fetch("location")
  end

  def test_saml_respects_disable_implicit_signup_and_request_signup
    auth = build_auth(
      disable_implicit_sign_up: true,
      plugins: [
        BetterAuth::Plugins.sso(
          disable_implicit_sign_up: true,
          saml: {
            parse_response: ->(raw_response:, **_data) { JSON.parse(Base64.decode64(raw_response), symbolize_names: true) }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    blocked_relay = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})[:url]).query).fetch("RelayState")
    blocked_response = Base64.strict_encode64(JSON.generate({email: "blocked-saml@example.com", name: "Blocked SAML", id: "blocked-saml"}))
    blocked = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: blocked_response, RelayState: blocked_relay},
      as_response: true
    )

    assert_equal 302, blocked.first
    assert_equal "/dashboard?error=signup+disabled", blocked[1].fetch("location")
    assert_nil auth.context.internal_adapter.find_user_by_email("blocked-saml@example.com")

    allowed_relay = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard", requestSignUp: true})[:url]).query).fetch("RelayState")
    allowed_response = Base64.strict_encode64(JSON.generate({email: "allowed-saml@example.com", name: "Allowed SAML", id: "allowed-saml"}))
    allowed = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: allowed_response, RelayState: allowed_relay},
      as_response: true
    )

    assert_equal 302, allowed.first
    assert_equal "/dashboard", allowed[1].fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("allowed-saml@example.com")
  end

  def test_saml_runs_provision_user_hook_for_new_users_and_every_login_when_enabled
    provisioned = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          provision_user: ->(user:, provider:, **data) {
            user_info = data.fetch(:userInfo)
            provisioned << [user.fetch("email"), user_info.fetch(:id), provider.fetch("providerId")]
          },
          provision_user_on_every_login: true,
          saml: {
            parse_response: ->(raw_response:, **_data) { JSON.parse(Base64.decode64(raw_response), symbolize_names: true) }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    first_relay = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})[:url]).query).fetch("RelayState")
    first_response = Base64.strict_encode64(JSON.generate({email: "provision-saml@example.com", name: "Provision SAML", id: "provision-saml"}))
    auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: first_response, RelayState: first_relay})

    second_relay = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})[:url]).query).fetch("RelayState")
    second_response = Base64.strict_encode64(JSON.generate({email: "provision-saml@example.com", name: "Provision SAML", id: "provision-saml-2"}))
    auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: second_response, RelayState: second_relay})

    assert_equal [
      ["provision-saml@example.com", "provision-saml", "saml"],
      ["provision-saml@example.com", "provision-saml-2", "saml"]
    ], provisioned
  end

  def test_saml_defaults_email_verified_to_false_when_assertion_does_not_include_it
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(raw_response:, **_data) { JSON.parse(Base64.decode64(raw_response), symbolize_names: true) }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    relay_state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})[:url]).query).fetch("RelayState")
    response = Base64.strict_encode64(JSON.generate({email: "unverified-saml@example.com", name: "Unverified SAML", id: "unverified-saml"}))
    auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: response, RelayState: relay_state})

    user = auth.context.internal_adapter.find_user_by_email("unverified-saml@example.com").fetch(:user)
    refute user.fetch("emailVerified")
  end

  def test_saml_ignores_email_verified_assertion_unless_trusted
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(**_data) {
              {email: "asserted-verified@example.com", name: "Asserted Verified", id: "asserted-verified", email_verified: true}
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    relay_state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})[:url]).query).fetch("RelayState")
    auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: Base64.strict_encode64(JSON.generate({ignored: true})), RelayState: relay_state})

    user = auth.context.internal_adapter.find_user_by_email("asserted-verified@example.com").fetch(:user)
    refute user.fetch("emailVerified")
  end

  def test_saml_origin_check_is_skipped_only_for_saml_callbacks
    auth = build_auth
    app = auth.handler
    env = Rack::MockRequest.env_for(
      "http://localhost:3000/api/auth/sso/saml2/callback/saml",
      :method => "POST",
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "https://idp.example.com",
      :input => JSON.generate({SAMLResponse: Base64.strict_encode64(JSON.generate({email: "user@example.com"}))})
    )

    status, = app.call(env)
    refute_equal 403, status
  end

  def test_saml_response_validator_can_reject_assertions
    calls = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(raw_response:, **_data) { JSON.parse(Base64.decode64(raw_response), symbolize_names: true) },
            validate_response: ->(response:, provider:, context:) do
              calls << [provider.fetch("providerId"), context.context.base_url]
              response[:email] == "allowed@example.com"
            end
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )
    response = Base64.strict_encode64(JSON.generate({email: "blocked@example.com", name: "Blocked", id: "blocked-1"}))

    error = assert_raises(BetterAuth::APIError) do
      auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: response})
    end
    assert_equal 400, error.status_code
    assert_equal "Invalid SAML response", error.message
    assert_equal [["saml", "http://localhost:3000/api/auth"]], calls
  end

  def test_saml_response_parser_hook_enables_optional_real_xml_validator_adapter
    calls = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(raw_response:, provider:, context:) do
              calls << [raw_response, provider.fetch("providerId"), context.context.base_url]
              {email: "parsed@example.com", name: "Parsed User", id: "parsed-assertion"}
            end
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    raw_response = "signed-xml-from-sso-package"
    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: raw_response},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("parsed@example.com")[:user]
    assert_equal [[raw_response, "saml", "http://localhost:3000/api/auth"]], calls
  end

  def test_saml_auth_request_url_hook_enables_optional_real_xml_request_adapter
    calls = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            auth_request_url: ->(provider:, relay_state:, context:) do
              calls << [provider.fetch("providerId"), relay_state, context.context.base_url]
              "https://idp.example.com/real-saml?RelayState=#{URI.encode_www_form_component(relay_state)}"
            end
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    sign_in = auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})

    assert_match %r{\Ahttps://idp.example.com/real-saml\?RelayState=}, sign_in.fetch(:url)
    assert_equal "saml", calls.first.fetch(0)
    assert_equal "http://localhost:3000/api/auth", calls.first.fetch(2)
    assert calls.first.fetch(1).length.positive?
  end

  def test_saml_xml_response_rejects_missing_and_multiple_assertions
    no_assertion = Base64.strict_encode64("<Response></Response>")
    error = assert_raises(BetterAuth::APIError) { BetterAuth::Plugins.sso_validate_single_saml_assertion!(no_assertion) }
    assert_equal 400, error.status_code
    assert_equal "SAML response contains no assertions", error.message

    multiple = Base64.strict_encode64("<Response><Assertion ID=\"one\"/><EncryptedAssertion ID=\"two\"/></Response>")
    multiple_error = assert_raises(BetterAuth::APIError) { BetterAuth::Plugins.sso_validate_single_saml_assertion!(multiple) }
    assert_equal 400, multiple_error.status_code
    assert_match(/expected exactly 1/, multiple_error.message)

    valid = Base64.strict_encode64("<Response><Assertion ID=\"one\"><Subject /></Assertion></Response>")
    assert_equal true, BetterAuth::Plugins.sso_validate_single_saml_assertion!(valid)
  end

  def test_saml_custom_parser_rejects_xml_with_multiple_assertions_before_parsing
    calls = 0
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(**_data) {
              calls += 1
              {email: "multi-assertion@example.com", name: "Unsafe", id: "unsafe-assertion"}
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )
    response = Base64.strict_encode64("<Response><Assertion ID=\"one\"/><Assertion ID=\"two\"/></Response>")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: response})
    end

    assert_equal 400, error.status_code
    assert_equal "Invalid SAML response", error.message
    assert_equal 0, calls
    assert_nil auth.context.internal_adapter.find_user_by_email("multi-assertion@example.com")
  end

  def test_saml_timestamp_validation_matches_upstream_rules
    now = Time.now.utc
    valid_conditions = {
      not_before: (now - 60).iso8601,
      not_on_or_after: (now + 60).iso8601
    }
    assert_equal true, BetterAuth::Plugins.sso_validate_saml_timestamp!(valid_conditions)
    assert_equal true, BetterAuth::Plugins.sso_validate_saml_timestamp!({})

    required_error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({}, {saml: {require_timestamps: true}})
    end
    assert_equal "SAML assertion missing required timestamp conditions", required_error.message

    future_error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({notBefore: (now + 3).iso8601}, {saml: {clock_skew: 1000}})
    end
    assert_equal "SAML assertion is not yet valid", future_error.message

    expired_error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({notOnOrAfter: (now - 3).iso8601}, {saml: {clock_skew: 1000}})
    end
    assert_equal "SAML assertion has expired", expired_error.message

    invalid_not_before = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({not_before: "not-a-date"})
    end
    assert_equal "SAML assertion has invalid NotBefore timestamp", invalid_not_before.message

    invalid_not_on_or_after = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({not_on_or_after: "not-a-date"})
    end
    assert_equal "SAML assertion has invalid NotOnOrAfter timestamp", invalid_not_on_or_after.message
  end

  def test_saml_custom_parser_rejects_expired_timestamp_conditions
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(**_data) {
              {
                email: "expired-assertion@example.com",
                name: "Expired Assertion",
                id: "expired-assertion",
                conditions: {notOnOrAfter: (Time.now.utc - 600).iso8601}
              }
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )
    response = Base64.strict_encode64("<Response><Assertion ID=\"expired-assertion\"/></Response>")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: response})
    end

    assert_equal 400, error.status_code
    assert_equal "SAML assertion has expired", error.message
    assert_nil auth.context.internal_adapter.find_user_by_email("expired-assertion@example.com")
  end

  def test_saml_algorithm_validation_matches_upstream_policy
    valid = saml_algorithm_xml(
      signature_algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      digest_algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      key_encryption_algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep",
      data_encryption_algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm"
    )

    assert_equal true, BetterAuth::Plugins.sso_validate_saml_algorithms!(valid)

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_algorithms!(
        saml_algorithm_xml(signature_algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
        on_deprecated: "reject"
      )
    end
    assert_equal 400, error.status_code
    assert_match(/deprecated signature algorithm/, error.message)

    unknown_error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_algorithms!(saml_algorithm_xml(digest_algorithm: "urn:example:sha257"))
    end
    assert_equal 400, unknown_error.status_code
    assert_match(/not recognized/, unknown_error.message)

    allow_list_error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_algorithms!(
        saml_algorithm_xml(data_encryption_algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm"),
        allowed_data_encryption_algorithms: ["http://www.w3.org/2009/xmlenc11#aes128-gcm"]
      )
    end
    assert_match(/not in allow-list/, allow_list_error.message)
    assert_equal true, BetterAuth::Plugins.sso_validate_saml_algorithms!("<Response />")
  end

  def test_saml_registration_and_response_size_limits_match_upstream_defaults
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            max_metadata_size: 8,
            max_response_size: 8,
            parse_response: ->(**_data) { {email: "oversized@example.com", name: "Oversized", id: "oversized"} }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)

    metadata_error = assert_raises(BetterAuth::APIError) do
      auth.api.register_sso_provider(
        headers: {"cookie" => cookie},
        body: {
          providerId: "saml-big-metadata",
          issuer: "https://idp.example.com",
          domain: "example.com",
          samlConfig: {idpMetadata: "<EntityDescriptor>too large</EntityDescriptor>"}
        }
      )
    end
    assert_equal 400, metadata_error.status_code
    assert_equal "IdP metadata exceeds maximum allowed size (8 bytes)", metadata_error.message

    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    response_error = assert_raises(BetterAuth::APIError) do
      auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: "x" * 9})
    end
    assert_equal 400, response_error.status_code
    assert_equal "SAML response exceeds maximum allowed size (8 bytes)", response_error.message
  end

  def test_saml_metadata_includes_single_logout_service_only_when_enabled
    enabled = build_auth(plugins: [BetterAuth::Plugins.sso(saml: {enable_single_logout: true})])
    enabled_cookie = sign_up_cookie(enabled)
    enabled.api.register_sso_provider(
      headers: {"cookie" => enabled_cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )
    enabled_metadata = enabled.api.sp_metadata(query: {providerId: "saml", format: "json"}).fetch(:metadata)
    assert_includes enabled_metadata, "SingleLogoutService"
    assert_includes enabled_metadata, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    assert_includes enabled_metadata, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    assert_includes enabled_metadata, "/sso/saml2/sp/slo/saml"

    disabled = build_auth
    disabled_cookie = sign_up_cookie(disabled)
    disabled.api.register_sso_provider(
      headers: {"cookie" => disabled_cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )
    disabled_metadata = disabled.api.sp_metadata(query: {providerId: "saml", format: "json"}).fetch(:metadata)
    refute_includes disabled_metadata, "SingleLogoutService"
  end

  def test_saml_sp_metadata_returns_xml_body_and_content_type
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    status, headers, body = auth.api.sp_metadata(query: {providerId: "saml"}, as_response: true)

    assert_equal 200, status
    assert_includes headers.fetch("content-type"), "xml"
    assert_match(/\A(?:<\?xml[^>]*>\s*)?<EntityDescriptor\b/, body.join)
  end

  def test_signed_authn_request_includes_signature_params_and_verifies_relay_state
    private_key = saml_sp_private_key
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          cert: "test-cert",
          audience: "better-auth-ruby",
          authnRequestsSigned: true,
          privateKey: private_key.to_pem
        }
      }
    )

    sign_in = auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})
    uri = URI.parse(sign_in.fetch(:url))
    params = Rack::Utils.parse_query(uri.query)

    assert params.fetch("SAMLRequest")
    assert params.fetch("RelayState")
    assert_equal XMLSecurity::Document::RSA_SHA256, params.fetch("SigAlg")
    assert params.fetch("Signature")
    assert_operator sign_in.fetch(:url).index("RelayState="), :<, sign_in.fetch(:url).index("Signature=")

    signed_query = uri.query.split("&Signature=").first
    signature = Base64.decode64(params.fetch("Signature"))
    assert private_key.public_key.verify(OpenSSL::Digest.new("SHA256"), signature, signed_query)
  end

  def test_authn_requests_signed_requires_private_key
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          cert: "test-cert",
          audience: "better-auth-ruby",
          authnRequestsSigned: true
        }
      }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})
    end

    assert_equal 400, error.status_code
    assert_match(/privateKey/, error.message)
  end

  def test_saml_metadata_and_sanitized_config_expose_authn_requests_signed
    auth = build_auth
    cookie = sign_up_cookie(auth)
    provider = auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          cert: "test-cert",
          audience: "better-auth-ruby",
          authnRequestsSigned: true,
          privateKey: saml_sp_private_key.to_pem
        }
      }
    )
    metadata = auth.api.sp_metadata(query: {providerId: "saml", format: "json"}).fetch(:metadata)

    assert_equal true, provider.fetch("samlConfig").fetch("authnRequestsSigned")
    refute provider.fetch("samlConfig").key?("privateKey")
    assert_includes metadata, "AuthnRequestsSigned=\"true\""
  end

  def test_saml_slo_endpoint_requires_single_logout_enabled
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.slo_endpoint(params: {providerId: "saml"}, body: {SAMLRequest: Base64.strict_encode64("<LogoutRequest/>")})
    end
    assert_equal 400, error.status_code
    assert_equal "Single Logout is not enabled", error.message
  end

  def test_saml_login_stores_session_records_when_single_logout_is_enabled
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            enable_single_logout: true,
            parse_response: ->(**_data) {
              {
                email: "slo-session@example.com",
                name: "SLO Session",
                id: "assertion-slo-session",
                name_id: "name-id-123",
                session_index: "session-index-456"
              }
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: Base64.strict_encode64(JSON.generate({ignored: true}))},
      as_response: true
    )

    assert_equal 302, status
    session_token = headers.fetch("set-cookie")[/better-auth\.session_token=([^.;]+)/, 1]
    session_record = auth.context.internal_adapter.find_verification_value("saml-session:saml:name-id-123")
    by_id_record = auth.context.internal_adapter.find_verification_value("saml-session-by-id:#{session_token}")
    parsed = JSON.parse(session_record.fetch("value"))

    assert_equal session_token, parsed.fetch("sessionToken")
    assert_equal "saml", parsed.fetch("providerId")
    assert_equal "name-id-123", parsed.fetch("nameId")
    assert_equal "session-index-456", parsed.fetch("sessionIndex")
    assert_equal "saml-session:saml:name-id-123", by_id_record.fetch("value")
  end

  def test_saml_initiate_slo_uses_stored_name_id_and_session_index
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            enable_single_logout: true,
            parse_response: ->(**_data) {
              {
                email: "slo-request@example.com",
                name: "SLO Request",
                id: "assertion-slo-request",
                name_id: "name-id-request",
                session_index: "session-index-request"
              }
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          singleLogoutService: "https://idp.example.com/slo",
          cert: "test-cert",
          audience: "better-auth-ruby"
        }
      }
    )
    _status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: Base64.strict_encode64(JSON.generate({ignored: true}))},
      as_response: true
    )
    saml_cookie = headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")

    status, initiated_headers, _body = auth.api.initiate_slo(
      headers: {"cookie" => saml_cookie},
      params: {providerId: "saml"},
      body: {callbackURL: "/after-logout"},
      as_response: true
    )
    assert_equal 302, status
    logout_request_xml = saml_logout_request_xml_from_url(initiated_headers.fetch("location"))

    assert_includes logout_request_xml, "<saml:NameID>name-id-request</saml:NameID>"
    assert_includes logout_request_xml, "<samlp:SessionIndex>session-index-request</samlp:SessionIndex>"
    assert_nil auth.context.internal_adapter.find_verification_value("saml-session:saml:name-id-request")
    session_token = saml_cookie[/better-auth\.session_token=([^;]+)/, 1]
    assert_nil auth.context.internal_adapter.find_verification_value("saml-session-by-id:#{session_token}")
    assert_nil auth.context.internal_adapter.find_session(session_token)
  end

  def test_saml_slo_logout_request_deletes_matching_session_records
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            enable_single_logout: true,
            parse_response: ->(**_data) {
              {
                email: "slo-delete@example.com",
                name: "SLO Delete",
                id: "assertion-slo-delete",
                name_id: "name-id-delete",
                session_index: "session-index-delete"
              }
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          singleLogoutService: "https://idp.example.com/slo",
          cert: "test-cert",
          audience: "better-auth-ruby"
        }
      }
    )
    _status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: Base64.strict_encode64(JSON.generate({ignored: true}))},
      as_response: true
    )
    session_token = headers.fetch("set-cookie")[/better-auth\.session_token=([^.;]+)/, 1]
    assert auth.context.internal_adapter.find_session(session_token)

    status, response_headers, response_body = auth.api.slo_endpoint(
      params: {providerId: "saml"},
      body: {SAMLRequest: saml_logout_request(name_id: "name-id-delete", session_index: "session-index-delete"), RelayState: "/signed-out"},
      as_response: true
    )

    assert_equal 200, status
    assert_equal "text/html", response_headers.fetch("content-type")
    assert_includes response_body.join, "name=\"SAMLResponse\""
    assert_includes response_body.join, "name=\"RelayState\" value=\"/signed-out\""
    assert_nil auth.context.internal_adapter.find_session(session_token)
    assert_nil auth.context.internal_adapter.find_verification_value("saml-session:saml:name-id-delete")
    assert_nil auth.context.internal_adapter.find_verification_value("saml-session-by-id:#{session_token}")
  end

  def test_saml_initiate_slo_stores_logout_request_and_response_consumes_it
    auth = build_auth(plugins: [BetterAuth::Plugins.sso(saml: {enable_single_logout: true})])
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          singleLogoutService: "https://idp.example.com/slo",
          cert: "test-cert",
          audience: "better-auth-ruby"
        }
      }
    )

    status, initiated_headers, _body = auth.api.initiate_slo(
      headers: {"cookie" => cookie},
      params: {providerId: "saml"},
      body: {callbackURL: "/after-logout"},
      as_response: true
    )
    assert_equal 302, status
    request_id = saml_logout_request_id_from_url(initiated_headers.fetch("location"))

    verification = auth.context.internal_adapter.find_verification_value("saml-logout-request:#{request_id}")
    assert_equal "saml", verification.fetch("value")

    status, headers, _body = auth.api.slo_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: saml_logout_response(in_response_to: request_id), RelayState: "/after-logout"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/after-logout", headers.fetch("location")
    assert_nil auth.context.internal_adapter.find_verification_value("saml-logout-request:#{request_id}")
  end

  def test_saml_initiate_slo_uses_single_logout_service_from_idp_metadata
    auth = build_auth(plugins: [BetterAuth::Plugins.sso(saml: {enable_single_logout: true})])
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          idpMetadata: {
            metadata: "<EntityDescriptor><IDPSSODescriptor><SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.example.com/metadata-slo\" /></IDPSSODescriptor></EntityDescriptor>"
          },
          cert: "test-cert",
          audience: "better-auth-ruby"
        }
      }
    )

    status, headers, _body = auth.api.initiate_slo(
      headers: {"cookie" => cookie},
      params: {providerId: "saml"},
      body: {callbackURL: "/after-logout"},
      as_response: true
    )

    assert_equal 302, status
    assert_match %r{\Ahttps://idp\.example\.com/metadata-slo\?}, headers.fetch("location")
  end

  def test_saml_logout_response_failure_does_not_consume_pending_request
    auth = build_auth(plugins: [BetterAuth::Plugins.sso(saml: {enable_single_logout: true})])
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          singleLogoutService: "https://idp.example.com/slo",
          cert: "test-cert",
          audience: "better-auth-ruby"
        }
      }
    )

    _status, initiated_headers, _body = auth.api.initiate_slo(
      headers: {"cookie" => cookie},
      params: {providerId: "saml"},
      body: {callbackURL: "/after-logout"},
      as_response: true
    )
    request_id = saml_logout_request_id_from_url(initiated_headers.fetch("location"))

    error = assert_raises(BetterAuth::APIError) do
      auth.api.slo_endpoint(
        params: {providerId: "saml"},
        body: {
          SAMLResponse: saml_logout_response(
            in_response_to: request_id,
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Responder"
          ),
          RelayState: "/after-logout"
        }
      )
    end

    assert_equal 400, error.status_code
    assert_equal "Logout failed at IdP", error.message
    assert auth.context.internal_adapter.find_verification_value("saml-logout-request:#{request_id}")
  end

  def test_saml_logout_response_rejects_malicious_relay_state_redirect
    auth = build_auth(plugins: [BetterAuth::Plugins.sso(saml: {enable_single_logout: true})])
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          singleLogoutService: "https://idp.example.com/slo",
          cert: "test-cert",
          audience: "better-auth-ruby"
        }
      }
    )
    _status, initiated_headers, _body = auth.api.initiate_slo(
      headers: {"cookie" => cookie},
      params: {providerId: "saml"},
      body: {callbackURL: "/after-logout"},
      as_response: true
    )
    request_id = saml_logout_request_id_from_url(initiated_headers.fetch("location"))

    status, headers, _body = auth.api.slo_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: saml_logout_response(in_response_to: request_id), RelayState: "https://evil.com/phishing"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth", headers.fetch("location")
  end

  def test_saml_relay_state_is_opaque_and_stored_in_verification
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    sign_in = auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})
    relay_state = Rack::Utils.parse_query(URI.parse(sign_in.fetch(:url)).query).fetch("RelayState")
    stored = auth.context.internal_adapter.find_verification_value("saml-relay-state:#{relay_state}")
    state = JSON.parse(stored.fetch("value"))

    assert_match(/\A[a-zA-Z0-9_-]{24,}\z/, relay_state)
    assert_equal "/dashboard", state.fetch("callbackURL")
    assert_nil BetterAuth::Plugins.sso_verify_state(relay_state, SECRET)
  end

  def test_saml_existing_email_requires_trusted_provider_for_account_linking
    auth = build_auth(
      account: {account_linking: {enabled: true, trusted_providers: []}},
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(**_data) {
              {email: "existing-saml@example.com", name: "Existing SAML", id: "saml-existing-id"}
            }
          }
        )
      ]
    )
    sign_up_cookie(auth, email: "existing-saml@example.com")
    owner_cookie = sign_up_cookie(auth, email: "owner-linking@example.com")
    auth.api.register_sso_provider(
      headers: {"cookie" => owner_cookie},
      body: {
        providerId: "saml-link",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "saml-link"},
      body: {SAMLResponse: Base64.strict_encode64(JSON.generate({ignored: true}))},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/?error=account_not_linked", headers.fetch("location")
    user = auth.context.internal_adapter.find_user_by_email("existing-saml@example.com").fetch(:user)
    refute auth.context.internal_adapter.find_accounts(user.fetch("id")).any? { |account| account["providerId"] == "saml-link" }
  end

  def test_saml_trusted_provider_links_existing_email_with_upstream_provider_id
    auth = build_auth(
      account: {account_linking: {enabled: true, trusted_providers: ["saml-link"]}},
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(**_data) {
              {email: "trusted-saml@example.com", name: "Trusted SAML", id: "trusted-saml-id"}
            }
          }
        )
      ]
    )
    sign_up_cookie(auth, email: "trusted-saml@example.com")
    owner_cookie = sign_up_cookie(auth, email: "owner-trusted@example.com")
    auth.api.register_sso_provider(
      headers: {"cookie" => owner_cookie},
      body: {
        providerId: "saml-link",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "saml-link"},
      body: {SAMLResponse: Base64.strict_encode64(JSON.generate({ignored: true}))},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/", headers.fetch("location")
    user = auth.context.internal_adapter.find_user_by_email("trusted-saml@example.com").fetch(:user)
    account = auth.context.internal_adapter.find_account_by_provider_id("trusted-saml-id", "saml-link")
    assert_equal user.fetch("id"), account.fetch("userId")
  end

  def test_saml_sign_in_uses_idp_metadata_sso_fallbacks_and_entity_id
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml-metadata",
        issuer: "https://fallback.example.com/issuer",
        domain: "example.com",
        samlConfig: {
          cert: "fallback-cert",
          audience: "better-auth-ruby",
          idpMetadata: {
            metadata: <<~XML
              <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/entity">
                <md:IDPSSODescriptor>
                  <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>metadata-cert</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
                  <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/redirect"/>
                  <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/logout"/>
                </md:IDPSSODescriptor>
              </md:EntityDescriptor>
            XML
          }
        }
      }
    )

    provider = auth.context.adapter.find_one(model: "ssoProvider", where: [{field: "providerId", value: "saml-metadata"}])
    sign_in = auth.api.sign_in_sso(body: {providerId: "saml-metadata", callbackURL: "/dashboard"})

    assert_match %r{\Ahttps://idp\.example\.com/redirect\?}, sign_in.fetch(:url)
    assert_equal "https://idp.example.com/entity", BetterAuth::Plugins.sso_saml_idp_metadata(provider)[:entity_id]
    assert_equal "https://idp.example.com/logout", BetterAuth::Plugins.sso_saml_logout_destination(provider)
  end

  def test_saml_slo_redirects_include_signature_when_signing_flags_are_enabled
    private_key = saml_sp_private_key
    auth = build_auth(plugins: [BetterAuth::Plugins.sso(saml: {enable_single_logout: true, want_logout_request_signed: true, want_logout_response_signed: true})])
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml-signed-slo",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          singleLogoutService: "https://idp.example.com/slo",
          cert: "test-cert",
          audience: "better-auth-ruby",
          privateKey: private_key.to_pem
        }
      }
    )

    status, initiated_headers, _body = auth.api.initiate_slo(
      headers: {"cookie" => cookie},
      params: {providerId: "saml-signed-slo"},
      body: {callbackURL: "/after-logout"},
      as_response: true
    )
    assert_equal 302, status
    request_params = Rack::Utils.parse_query(URI.parse(initiated_headers.fetch("location")).query)
    assert_equal XMLSecurity::Document::RSA_SHA256, request_params.fetch("SigAlg")
    assert request_params.fetch("Signature")

    response_auth = build_auth(plugins: [BetterAuth::Plugins.sso(saml: {enable_single_logout: true, want_logout_response_signed: true})])
    response_cookie = sign_up_cookie(response_auth)
    response_auth.api.register_sso_provider(
      headers: {"cookie" => response_cookie},
      body: {
        providerId: "saml-signed-slo",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          singleLogoutService: "https://idp.example.com/slo",
          cert: "test-cert",
          audience: "better-auth-ruby",
          privateKey: private_key.to_pem
        }
      }
    )

    logout_request = saml_logout_request(name_id: "name-id", session_index: "session-index")
    status, response_headers, _body = response_auth.api.slo_endpoint(
      params: {providerId: "saml-signed-slo"},
      query: {
        SAMLRequest: logout_request,
        RelayState: "/signed-out"
      },
      as_response: true
    )
    assert_equal 302, status
    response_params = Rack::Utils.parse_query(URI.parse(response_headers.fetch("location")).query)
    assert_equal XMLSecurity::Document::RSA_SHA256, response_params.fetch("SigAlg")
    assert response_params.fetch("Signature")
  end

  def test_saml_sign_in_stores_authn_request_for_in_response_to_validation
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )

    sign_in = auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})
    request_id = saml_request_id_from_url(sign_in.fetch(:url))
    verification = auth.context.internal_adapter.find_verification_value("saml-authn-request:#{request_id}")
    record = JSON.parse(verification.fetch("value"))

    assert_equal request_id, record.fetch("id")
    assert_equal "saml", record.fetch("providerId")
  end

  def test_saml_acs_validates_in_response_to_records_and_consumes_them
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(raw_response:, **_data) {
              {email: "in-response@example.com", name: "In Response", id: "assertion-in-response"}
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )
    sign_in = auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})
    relay_state = Rack::Utils.parse_query(URI.parse(sign_in.fetch(:url)).query).fetch("RelayState")
    request_id = saml_request_id_from_url(sign_in.fetch(:url))

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: saml_response_xml(in_response_to: request_id), RelayState: relay_state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert_nil auth.context.internal_adapter.find_verification_value("saml-authn-request:#{request_id}")
  end

  def test_saml_acs_rejects_unknown_provider_mismatch_and_unsolicited_responses
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            allow_idp_initiated: false,
            parse_response: ->(**_data) { {email: "blocked-saml@example.com", name: "Blocked", id: "assertion-blocked"} }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )
    relay_state = Rack::Utils.parse_query(URI.parse(auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"}).fetch(:url)).query).fetch("RelayState")

    unknown = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: saml_response_xml(in_response_to: "_unknown"), RelayState: relay_state},
      as_response: true
    )
    assert_equal "/dashboard?error=invalid_saml_response&error_description=Unknown+or+expired+request+ID", unknown[1].fetch("location")

    auth.context.internal_adapter.create_verification_value(
      identifier: "saml-authn-request:_mismatch",
      value: JSON.generate({id: "_mismatch", providerId: "other", createdAt: Time.now.to_i * 1000, expiresAt: (Time.now.to_i + 300) * 1000}),
      expiresAt: Time.now + 300
    )
    mismatch = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: saml_response_xml(in_response_to: "_mismatch"), RelayState: relay_state},
      as_response: true
    )
    assert_equal "/dashboard?error=invalid_saml_response&error_description=Provider+mismatch", mismatch[1].fetch("location")
    assert_nil auth.context.internal_adapter.find_verification_value("saml-authn-request:_mismatch")

    unsolicited = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: saml_response_xml, RelayState: relay_state},
      as_response: true
    )
    assert_equal "/dashboard?error=unsolicited_response&error_description=IdP-initiated+SSO+not+allowed", unsolicited[1].fetch("location")
  end

  def test_saml_assertion_replay_tracking_is_global_across_providers
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(**_data) { {email: "replay-global@example.com", name: "Replay Global", id: "assertion-global"} }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth)
    %w[saml-one saml-two].each do |provider_id|
      auth.api.register_sso_provider(
        headers: {"cookie" => cookie},
        body: {
          providerId: provider_id,
          issuer: "https://#{provider_id}.example.com",
          domain: "#{provider_id}.example.com",
          samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
        }
      )
    end

    response = Base64.strict_encode64(JSON.generate({ignored: true}))
    auth.api.acs_endpoint(params: {providerId: "saml-one"}, body: {SAMLResponse: response})

    replay_status, replay_headers, _replay_body = auth.api.acs_endpoint(
      params: {providerId: "saml-two"},
      body: {SAMLResponse: response},
      as_response: true
    )
    assert_equal 302, replay_status
    assert_equal "/?error=replay_detected&error_description=SAML+assertion+has+already+been+used", replay_headers.fetch("location")
    assert auth.context.internal_adapter.find_verification_value("saml-used-assertion:assertion-global")
  end

  def test_sso_assigns_new_domain_user_to_verified_provider_organization
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(raw_response:, **_data) { JSON.parse(Base64.decode64(raw_response), symbolize_names: true) }
          }
        )
      ]
    )
    owner_cookie = sign_up_cookie(auth, email: "owner@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Example Org", slug: "example"})
    auth.api.register_sso_provider(
      headers: {"cookie" => owner_cookie},
      body: {
        providerId: "saml-org",
        issuer: "https://idp.example.com",
        domain: "example.com",
        organizationId: organization.fetch("id"),
        domainVerified: true,
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )
    response = Base64.strict_encode64(JSON.generate({email: "new-user@example.com", name: "New User", id: "assertion-org-1"}))

    auth.api.acs_endpoint(params: {providerId: "saml-org"}, body: {SAMLResponse: response}, as_response: true)

    user = auth.context.internal_adapter.find_user_by_email("new-user@example.com").fetch(:user)
    member = auth.context.adapter.find_one(
      model: "member",
      where: [
        {field: "organizationId", value: organization.fetch("id")},
        {field: "userId", value: user.fetch("id")}
      ]
    )
    assert_equal "member", member.fetch("role")
  end

  private

  def with_singleton_method(object, method_name, replacement)
    singleton_class = class << object; self; end
    original = singleton_class.instance_method(method_name)
    redefine_without_warning(singleton_class, method_name) { |*args, **kwargs, &block| replacement.call(*args, **kwargs, &block) }
    yield
  ensure
    redefine_without_warning(singleton_class, method_name, original)
  end

  def redefine_without_warning(singleton_class, method_name, original = nil, &block)
    previous_verbose = $VERBOSE
    $VERBOSE = nil
    original ? singleton_class.define_method(method_name, original) : singleton_class.define_method(method_name, &block)
  ensure
    $VERBOSE = previous_verbose
  end

  def build_auth(options = {})
    BetterAuth.auth(
      {
        base_url: "http://localhost:3000",
        secret: SECRET,
        database: :memory,
        email_and_password: {enabled: true},
        plugins: [BetterAuth::Plugins.sso]
      }.merge(options)
    )
  end

  def saml_sp_private_key
    OpenSSL::PKey::RSA.generate(2048)
  end

  def sign_up_cookie(auth, email: "owner@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: email.split("@").first},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def saml_response_xml(in_response_to: nil)
    attribute = in_response_to ? " InResponseTo=\"#{in_response_to}\"" : ""
    Base64.strict_encode64("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"#{attribute}><saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"assertion\" /></samlp:Response>")
  end

  def saml_logout_request(name_id:, session_index:)
    Base64.strict_encode64("<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:NameID>#{name_id}</saml:NameID><samlp:SessionIndex>#{session_index}</samlp:SessionIndex></samlp:LogoutRequest>")
  end

  def saml_logout_response(in_response_to:, status_code: "urn:oasis:names:tc:SAML:2.0:status:Success")
    Base64.strict_encode64("<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" InResponseTo=\"#{in_response_to}\"><samlp:Status><samlp:StatusCode Value=\"#{status_code}\"/></samlp:Status></samlp:LogoutResponse>")
  end

  def saml_logout_request_id_from_url(url)
    encoded = Rack::Utils.parse_query(URI.parse(url).query).fetch("SAMLRequest")
    Base64.decode64(encoded)[/\bID=['"]([^'"]+)['"]/, 1]
  end

  def saml_logout_request_xml_from_url(url)
    encoded = Rack::Utils.parse_query(URI.parse(url).query).fetch("SAMLRequest")
    Base64.decode64(encoded)
  end

  def saml_request_id_from_url(url)
    encoded = Rack::Utils.parse_query(URI.parse(url).query).fetch("SAMLRequest")
    compressed = Base64.decode64(encoded)
    xml = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(compressed)
    xml[/\bID=['"]([^'"]+)['"]/, 1]
  end

  def saml_algorithm_xml(signature_algorithm: nil, digest_algorithm: nil, key_encryption_algorithm: nil, data_encryption_algorithm: nil)
    signature = signature_algorithm ? "<ds:SignatureMethod Algorithm=\"#{signature_algorithm}\"/>" : nil
    digest = digest_algorithm ? "<ds:DigestMethod Algorithm=\"#{digest_algorithm}\"/>" : nil
    key_encryption = key_encryption_algorithm ? "<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"#{key_encryption_algorithm}\"/></xenc:EncryptedKey>" : nil
    data_encryption = data_encryption_algorithm ? "<xenc:EncryptedData><xenc:EncryptionMethod Algorithm=\"#{data_encryption_algorithm}\"/></xenc:EncryptedData>" : nil

    <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
        #{signature}
        #{digest}
        <xenc:EncryptedAssertion>
          #{key_encryption}
          #{data_encryption}
        </xenc:EncryptedAssertion>
      </samlp:Response>
    XML
  end
end

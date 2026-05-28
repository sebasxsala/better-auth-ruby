# frozen_string_literal: true

require "better_auth/sso"
require "base64"
require "cgi"
require "openssl"
require "rack/utils"
require "securerandom"
require "time"
require "uri"
require_relative "../test_helper"

class BetterAuthSSORubySAMLTest < Minitest::Test
  SECRET = "better-auth-sso-saml-test-secret-with-entropy"
  IDP_ISSUER = "https://idp.example.com/metadata"
  IDP_SSO = "https://idp.example.com/sso"
  SP_ENTITY_ID = "http://localhost:3000/api/auth/sso/saml2/sp/metadata?providerId=saml"
  ACS_URL = "http://localhost:3000/api/auth/sso/saml2/sp/acs/saml"

  def setup
    skip "ruby-saml is not installed" unless defined?(BetterAuth::SSO::SAML) && defined?(OneLogin::RubySaml)
    @idp_key = OpenSSL::PKey::RSA.new(2048)
    @idp_cert = certificate_for(@idp_key, "ruby-saml-idp.example.com")
  end

  def test_sso_options_exposes_core_parse_response_hook
    options = BetterAuth::SSO::SAML.sso_options

    assert_kind_of Hash, options.fetch(:saml)
    assert_respond_to options.fetch(:saml).fetch(:parse_response), :call
  end

  def test_valid_signed_assertion_is_accepted_by_core_sso
    auth = build_auth
    register_provider(auth)

    status, headers, _body = complete_saml(auth, signed_response(email: "signed@example.com", name: "Signed User"))

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert auth.context.internal_adapter.find_user_by_email("signed@example.com")[:user]
  end

  def test_unsigned_forged_response_is_rejected
    auth = build_auth
    register_provider(auth)

    assert_invalid_saml(auth, unsigned_response(email: "forged@example.com"))
  end

  def test_tampered_name_id_is_rejected
    auth = build_auth
    register_provider(auth)
    tampered = Base64.strict_encode64(Base64.decode64(signed_response(email: "signed@example.com")).sub("signed@example.com", "attacker@example.com"))

    assert_invalid_saml(auth, tampered)
  end

  def test_multiple_no_assertion_and_xsw_responses_are_rejected
    auth = build_auth
    register_provider(auth)

    assert_invalid_saml(auth, empty_response)
    assert_invalid_saml(auth, response_with_assertions([signed_assertion(email: "one@example.com"), signed_assertion(email: "two@example.com")]))
    assert_invalid_saml(auth, response_with_assertions([signed_assertion(email: "victim@example.com"), unsigned_assertion(email: "attacker@example.com")]))
  end

  def test_replayed_signed_assertion_is_rejected_by_core_sso
    auth = build_auth
    register_provider(auth)
    response = signed_response(email: "replay@example.com", assertion_id: "_replay_assertion")

    complete_saml(auth, response)
    status, headers, _body = complete_saml(auth, response)

    assert_equal 302, status
    assert_equal "/dashboard?error=replay_detected&error_description=SAML+assertion+has+already+been+used", headers.fetch("location")
  end

  def test_algorithm_policy_rejects_deprecated_sha1_signatures
    auth = build_auth
    register_provider(auth)
    response = signed_response(signature_method: XMLSecurity::Document::RSA_SHA1, digest_method: XMLSecurity::Document::SHA1)

    assert_invalid_saml(auth, response)
  end

  def test_encrypted_assertion_decryption_settings_are_wired_to_ruby_saml
    auth = build_auth
    provider = register_provider(auth)
    sp_key = OpenSSL::PKey::RSA.new(2048)
    sp_cert = certificate_for(sp_key, "sp.example.com")
    ctx = BetterAuth::Endpoint::Context.new(path: "/sso/saml2/sp/acs/saml", method: "POST", query: {}, body: {}, params: {}, headers: {}, context: auth.context)

    settings = BetterAuth::SSO::SAML.build_settings(
      provider,
      ctx,
      BetterAuth::Plugins.normalize_hash(provider.fetch("samlConfig")).merge(
        want_assertions_encrypted: true,
        sp_private_key: sp_key.to_pem,
        sp_certificate: sp_cert.to_pem
      )
    )

    assert_equal true, settings.security[:want_assertions_encrypted]
    assert_equal [sp_key.to_pem], settings.get_sp_decryption_keys.map(&:to_pem)
  end

  def test_audience_recipient_destination_issuer_and_timestamps_are_validated
    auth = build_auth
    register_provider(auth)

    invalid_responses = [
      signed_response(audience: "wrong-audience"),
      signed_response(recipient: "http://localhost:3000/wrong/acs"),
      signed_response(destination: "http://localhost:3000/wrong/destination"),
      signed_response(issuer: "https://evil.example.com/metadata"),
      signed_response(not_before: Time.now.utc + 300),
      signed_response(not_on_or_after: Time.now.utc - 60)
    ]

    invalid_responses.each do |response|
      assert_invalid_saml(auth, response)
    end
  end

  private

  def build_auth
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.sso(BetterAuth::SSO::SAML.sso_options)]
    )
  end

  def register_provider(auth)
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: IDP_ISSUER,
        domain: "example.com",
        samlConfig: {
          entryPoint: IDP_SSO,
          cert: @idp_cert.to_pem,
          audience: SP_ENTITY_ID,
          callbackUrl: ACS_URL,
          wantAssertionsSigned: true
        }
      }
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "owner@example.com", password: "password123", name: "Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def complete_saml(auth, response)
    sign_in = auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})
    relay_state = Rack::Utils.parse_query(URI.parse(sign_in.fetch(:url)).query).fetch("RelayState")
    auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: response, RelayState: relay_state},
      headers: {"origin" => IDP_SSO},
      as_response: true
    )
  end

  def assert_invalid_saml(auth, response)
    status, _headers, body = complete_saml(auth, response)
    assert_equal 400, status
    assert_includes body.join, "Invalid SAML response"
  end

  def signed_response(**options)
    assertion_options = options.except(:destination)
    response_with_assertions([signed_assertion(**assertion_options)], destination: options.fetch(:destination, ACS_URL), issuer: options.fetch(:issuer, IDP_ISSUER))
  end

  def unsigned_response(**options)
    response_with_assertions([unsigned_assertion(**options)])
  end

  def empty_response
    response_with_assertions([])
  end

  def signed_assertion(signature_method: XMLSecurity::Document::RSA_SHA256, digest_method: XMLSecurity::Document::SHA256, **options)
    document = XMLSecurity::Document.new(unsigned_assertion(**options))
    document.sign_document(@idp_key, @idp_cert, signature_method, digest_method)
    document.to_s
  end

  def unsigned_assertion(
    email: "signed@example.com",
    name: "Signed User",
    assertion_id: "_#{SecureRandom.hex(16)}",
    issuer: IDP_ISSUER,
    audience: SP_ENTITY_ID,
    recipient: ACS_URL,
    not_before: Time.now.utc - 60,
    not_on_or_after: Time.now.utc + 300
  )
    now = Time.now.utc.iso8601
    session_expires = (Time.now.utc + 3600).iso8601
    <<~XML
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="#{xml(assertion_id)}" Version="2.0" IssueInstant="#{now}">
        <saml:Issuer>#{xml(issuer)}</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{xml(email)}</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData Recipient="#{xml(recipient)}" NotOnOrAfter="#{not_on_or_after.utc.iso8601}"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="#{not_before.utc.iso8601}" NotOnOrAfter="#{not_on_or_after.utc.iso8601}">
          <saml:AudienceRestriction>
            <saml:Audience>#{xml(audience)}</saml:Audience>
          </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="#{now}" SessionIndex="#{xml(assertion_id)}" SessionNotOnOrAfter="#{session_expires}">
          <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
          </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
          <saml:Attribute Name="email"><saml:AttributeValue>#{xml(email)}</saml:AttributeValue></saml:Attribute>
          <saml:Attribute Name="name"><saml:AttributeValue>#{xml(name)}</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    XML
  end

  def response_with_assertions(assertions, destination: ACS_URL, issuer: IDP_ISSUER)
    encoded = assertions.join("\n")
    Base64.strict_encode64(<<~XML)
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_#{SecureRandom.hex(16)}" Version="2.0" IssueInstant="#{Time.now.utc.iso8601}" Destination="#{xml(destination)}">
        <saml:Issuer>#{xml(issuer)}</saml:Issuer>
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        </samlp:Status>
        #{encoded}
      </samlp:Response>
    XML
  end

  def certificate_for(key, common_name)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{common_name}")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now.utc - 60
    cert.not_after = Time.now.utc + 3600
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  def xml(value)
    CGI.escapeHTML(value.to_s)
  end
end

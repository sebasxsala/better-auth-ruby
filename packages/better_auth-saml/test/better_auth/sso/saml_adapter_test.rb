# frozen_string_literal: true

require "base64"
require "rack/utils"
require "uri"
require "zlib"
require_relative "../../test_helper"

class BetterAuthSSOSAMLAdapterTest < Minitest::Test
  IDP_CERT = <<~CERT
    -----BEGIN CERTIFICATE-----
    MIIBszCCARygAwIBAgIBATANBgkqhkiG9w0BAQsFADAcMRowGAYDVQQDDBFpZHAu
    ZXhhbXBsZS5jb20wHhcNMjYwNTAxMDAwMDAwWhcNMjcwNTAxMDAwMDAwWjAcMRow
    GAYDVQQDDBFpZHAuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
    AoGBAMv5X4hxxHP3RxbIiIBl+ZOTw2mi9R/vBSeTZVkflkiGzTx4R8JdK/dckIIv
    cdGyo09ulyn1hoNGgYG81Ng38riU7MMPGBbSeEHkdV24SfLe+j6xZNJVmLRy8/WZ
    7V6Brv6N+AiFdumOcgKQwTVe2E2RmT+VfS0HmkZ4bH8ZAgMBAAEwDQYJKoZIhvcN
    AQELBQADgYEAZ8L9IdhQMtH3H7haV+hUAg0U4xF5bI8uiUzx5fzc0ZFiZ/yXH0go
    K9wH4KGkgEXOdjZqgA9k9i4ZVW+E6VqKGlQrWeVtwC00qBz0E6UsX+jbGUZgLkS4
    E3Sf4qznO+3cFhfHhPQeyKwG3S8p0v2iwA0QntJ2bWQ=
    -----END CERTIFICATE-----
  CERT

  def setup
    skip "ruby-saml is not installed" unless defined?(BetterAuth::SSO::SAML) && defined?(OneLogin::RubySaml)

    @ruby_saml_logger_level = OneLogin::RubySaml::Logging.logger.level
    OneLogin::RubySaml::Logging.logger.level = Logger::WARN
  end

  def teardown
    OneLogin::RubySaml::Logging.logger.level = @ruby_saml_logger_level if defined?(@ruby_saml_logger_level)
  end

  def test_sso_options_exposes_saml_boundary_hooks
    options = BetterAuth::SSO::SAML.sso_options

    assert_equal [:saml], options.keys
    assert_respond_to options.fetch(:saml).fetch(:auth_request_url), :call
    assert_respond_to options.fetch(:saml).fetch(:parse_response), :call
  end

  def test_build_settings_derives_provider_acs_when_callback_url_is_app_destination
    settings = BetterAuth::SSO::SAML.build_settings(
      provider("provider with/slash", callbackUrl: "https://app.example.com/dashboard"),
      context("https://auth.example.com/api/auth"),
      normalized_config(callbackUrl: "https://app.example.com/dashboard")
    )

    assert_equal "https://auth.example.com/api/auth/sso/saml2/sp/acs/provider+with%2Fslash", settings.assertion_consumer_service_url
    refute_equal "https://app.example.com/dashboard", settings.assertion_consumer_service_url
  end

  def test_build_settings_preserves_explicit_acs_callback_url
    settings = BetterAuth::SSO::SAML.build_settings(
      provider("saml", callbackUrl: "https://auth.example.com/api/auth/sso/saml2/sp/acs/custom-saml"),
      context("https://auth.example.com/api/auth"),
      normalized_config(callbackUrl: "https://auth.example.com/api/auth/sso/saml2/sp/acs/custom-saml")
    )

    assert_equal "https://auth.example.com/api/auth/sso/saml2/sp/acs/custom-saml", settings.assertion_consumer_service_url
  end

  def test_build_settings_normalizes_sp_idp_and_security_fields
    settings = BetterAuth::SSO::SAML.build_settings(
      provider(
        "normalized-saml",
        issuer: "https://fallback-idp.example.com",
        entryPoint: nil,
        spMetadata: {entityID: "https://sp.example.com/entity"},
        idpMetadata: {
          entityID: "https://idp.example.com/entity",
          singleSignOnService: [
            {Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: "https://idp.example.com/post"},
            {Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: "https://idp.example.com/redirect"}
          ]
        },
        identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        wantAssertionsSigned: false,
        wantMessagesSigned: true,
        signatureAlgorithm: "rsa-sha512",
        digestAlgorithm: XMLSecurity::Document::SHA512
      ),
      context("https://auth.example.com/api/auth"),
      normalized_config(
        entryPoint: nil,
        spMetadata: {entityID: "https://sp.example.com/entity"},
        idpMetadata: {
          entityID: "https://idp.example.com/entity",
          singleSignOnService: [
            {Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: "https://idp.example.com/post"},
            {Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: "https://idp.example.com/redirect"}
          ]
        },
        identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        wantAssertionsSigned: false,
        wantMessagesSigned: true,
        signatureAlgorithm: "rsa-sha512",
        digestAlgorithm: XMLSecurity::Document::SHA512
      )
    )

    assert_equal "https://sp.example.com/entity", settings.sp_entity_id
    assert_equal "https://idp.example.com/entity", settings.idp_entity_id
    assert_equal "https://idp.example.com/redirect", settings.idp_sso_service_url
    assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", settings.name_identifier_format
    assert_equal false, settings.security[:want_assertions_signed]
    assert_equal true, settings.security[:want_messages_signed]
    assert_equal true, settings.security[:strict_audience_validation]
    assert_equal XMLSecurity::Document::SHA512, settings.security[:digest_method]
    assert_equal XMLSecurity::Document::RSA_SHA512, settings.security[:signature_method]
  end

  def test_auth_request_url_uses_normalized_config_and_request_options
    captured = nil
    hook = BetterAuth::SSO::SAML.auth_request_url(
      request_options: {ForceAuthn: true},
      settings: lambda do |provider:, context:, saml_config:|
        captured = [provider.fetch("providerId"), context.context.base_url, saml_config]
        BetterAuth::SSO::SAML.build_settings(provider, context, saml_config)
      end
    )

    url = hook.call(
      provider: provider("auth-request", callbackUrl: "https://app.example.com/dashboard"),
      relay_state: "relay-123",
      context: context("https://auth.example.com/api/auth")
    )
    params = Rack::Utils.parse_query(URI.parse(url).query)
    request_xml = inflate_saml_request(params.fetch("SAMLRequest"))

    assert_equal ["auth-request", "https://auth.example.com/api/auth"], captured.first(2)
    assert_equal "https://app.example.com/dashboard", captured.last.fetch(:callback_url)
    assert_equal "relay-123", params.fetch("RelayState")
    assert_equal "true", params.fetch("ForceAuthn")
    assert_includes request_xml, "AssertionConsumerServiceURL='https://auth.example.com/api/auth/sso/saml2/sp/acs/auth-request'"
  end

  def test_response_parser_builds_settings_and_maps_attributes_without_idp_network
    raw_response = Base64.strict_encode64('<Response><Assertion ID="assertion-123"/></Response>')
    response = fake_response(
      {
        "employeeNumber" => "saml-user-123",
        "mail" => "Mapped@Example.COM",
        "first" => "Mapped",
        "last" => "User",
        "departmentName" => "Engineering"
      },
      nameid: "nameid@example.com",
      assertion_id: "assertion-123",
      sessionindex: "session-123"
    )
    new_calls = []

    with_singleton_method(OneLogin::RubySaml::Response, :new, ->(*args) {
      new_calls << args
      response
    }) do
      parsed = BetterAuth::SSO::SAML.response_parser(response_options: {allowed_clock_drift: 3}).call(
        raw_response: raw_response,
        provider: provider(
          "parser-saml",
          mapping: {
            id: "employeeNumber",
            email: "mail",
            firstName: "first",
            lastName: "last",
            extraFields: {department: "departmentName"}
          }
        ),
        context: context("https://auth.example.com/api/auth")
      )

      assert_equal "saml-user-123", parsed.fetch(:id)
      assert_equal "mapped@example.com", parsed.fetch(:email)
      assert_equal "Mapped User", parsed.fetch(:name)
      assert_equal "Engineering", parsed.fetch(:department)
      assert_equal "nameid@example.com", parsed.fetch(:name_id)
      assert_equal "session-123", parsed.fetch(:session_index)
    end

    assert_equal raw_response, new_calls.first.fetch(0)
    assert_kind_of OneLogin::RubySaml::Settings, new_calls.first.fetch(1).fetch(:settings)
    assert_equal 3, new_calls.first.fetch(1).fetch(:allowed_clock_drift)
  end

  private

  def provider(provider_id, issuer: "https://idp.example.com/entity", **saml_config)
    {
      "providerId" => provider_id,
      "issuer" => issuer,
      "samlConfig" => {
        entryPoint: "https://idp.example.com/sso",
        cert: IDP_CERT
      }.merge(saml_config)
    }
  end

  def normalized_config(**saml_config)
    BetterAuth::Plugins.normalize_hash(provider("saml", **saml_config).fetch("samlConfig"))
  end

  def context(base_url)
    Struct.new(:context).new(Struct.new(:base_url).new(base_url))
  end

  def fake_response(attributes, nameid:, assertion_id:, sessionindex:)
    Struct.new(:attributes, :nameid, :assertion_id, :sessionindex) do
      def is_valid?
        true
      end
    end.new(attributes, nameid, assertion_id, sessionindex)
  end

  def inflate_saml_request(encoded)
    inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    inflater.inflate(Base64.decode64(encoded))
  ensure
    inflater&.finish
    inflater&.close
  end

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
end

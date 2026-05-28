# frozen_string_literal: true

require "openssl"
require "rack/mock"
require "base64"
require "json"
require "zlib"
require_relative "../../test_helper"

class BetterAuthSSOSAMLMirrorTest < Minitest::Test
  SECRET = "saml-mirror-secret-with-enough-entropy-123"
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
  end

  def test_default_saml_sso_provider_from_array_is_used_when_provider_is_not_in_database
    auth = build_auth(
      default_sso: [
        default_saml_provider(provider_id: "default-saml", domain: "localhost:8081")
      ]
    )

    sign_in = sign_in_params(auth, providerId: "default-saml", callbackURL: "http://localhost:3000/dashboard")

    assert_equal "http://localhost:8081/api/sso/saml2/idp/redirect", sign_in.fetch(:url_without_query)
    assert sign_in.fetch(:params).fetch("SAMLRequest")
    assert sign_in.fetch(:params).fetch("RelayState")
  end

  def test_signed_authn_request_includes_signature_sigalg_and_relay_state
    key = OpenSSL::PKey::RSA.new(2048)
    auth = build_auth(
      default_sso: [
        default_saml_provider(
          provider_id: "signed-saml",
          domain: "localhost:8082",
          saml_config: {
            entryPoint: "http://localhost:8082/api/sso/saml2/idp/redirect",
            authnRequestsSigned: true,
            privateKey: key.to_pem,
            spMetadata: {privateKey: key.to_pem}
          }
        )
      ]
    )

    sign_in = sign_in_params(auth, providerId: "signed-saml", callbackURL: "http://localhost:3000/dashboard")

    assert_equal "http://localhost:8082/api/sso/saml2/idp/redirect", sign_in.fetch(:url_without_query)
    assert sign_in.fetch(:params).fetch("SAMLRequest")
    assert sign_in.fetch(:params).fetch("RelayState")
    assert sign_in.fetch(:params).fetch("SigAlg")
    assert sign_in.fetch(:params).fetch("Signature")
    assert_operator sign_in.fetch(:url).index("RelayState="), :<, sign_in.fetch(:url).index("Signature=")
  end

  def test_signed_authn_request_signature_can_be_verified_by_idp
    key = OpenSSL::PKey::RSA.new(2048)
    auth = build_auth(
      default_sso: [
        default_saml_provider(
          provider_id: "verifiable-signed-saml",
          domain: "localhost:8082",
          saml_config: {
            entryPoint: "http://localhost:8082/api/sso/saml2/idp/redirect",
            authnRequestsSigned: true,
            privateKey: key.to_pem,
            spMetadata: {privateKey: key.to_pem}
          }
        )
      ]
    )

    sign_in = sign_in_params(auth, providerId: "verifiable-signed-saml", callbackURL: "http://localhost:3000/dashboard")
    query = URI.parse(sign_in.fetch(:url)).query
    signed_query = query.split("&").take_while { |part| !part.start_with?("Signature=") }.join("&")
    signature = Base64.decode64(sign_in.fetch(:params).fetch("Signature"))

    assert key.public_key.verify(OpenSSL::Digest.new("SHA256"), signature, signed_query)
  end

  def test_unsigned_authn_request_does_not_include_signature_fields
    auth = build_auth(
      default_sso: [
        default_saml_provider(
          provider_id: "unsigned-saml",
          domain: "localhost:8082",
          saml_config: {
            entryPoint: "http://localhost:8081/api/sso/saml2/idp/post",
            authnRequestsSigned: false
          }
        )
      ]
    )

    sign_in = sign_in_params(auth, providerId: "unsigned-saml", callbackURL: "http://localhost:3000/dashboard")

    assert_equal "http://localhost:8081/api/sso/saml2/idp/post", sign_in.fetch(:url_without_query)
    refute sign_in.fetch(:params).key?("SigAlg")
    refute sign_in.fetch(:params).key?("Signature")
  end

  def test_signed_authn_request_requires_private_key
    auth = build_auth(
      default_sso: [
        default_saml_provider(
          provider_id: "no-key-saml",
          domain: "localhost:8082",
          saml_config: {
            authnRequestsSigned: true,
            spMetadata: {}
          }
        )
      ]
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_sso(body: {providerId: "no-key-saml", callbackURL: "http://localhost:3000/dashboard"})
    end

    assert_equal 400, error.status_code
    assert_match(/privateKey/, error.message)
  end

  def test_partial_idp_metadata_falls_back_to_top_level_entry_point_cert_and_entity_id
    provider = {
      "providerId" => "partial-idp-metadata-saml",
      "issuer" => "http://localhost:8083/issuer",
      "samlConfig" => {
        issuer: "http://localhost:8083/issuer",
        entryPoint: "http://localhost:8081/api/sso/saml2/idp/redirect",
        cert: IDP_CERT,
        callbackUrl: "http://localhost:8083/dashboard",
        idpMetadata: {
          entityID: "http://localhost:8081/custom-entity-id"
        }
      }
    }
    ctx = Struct.new(:context).new(Struct.new(:base_url).new("http://localhost:3000/api/auth"))

    settings = BetterAuth::SSO::SAML.build_settings(provider, ctx, BetterAuth::Plugins.normalize_hash(provider.fetch("samlConfig")))
    metadata = BetterAuth::Plugins.sso_saml_idp_metadata(provider)

    assert_equal "http://localhost:8081/api/sso/saml2/idp/redirect", settings.idp_sso_service_url
    assert_equal "http://localhost:8081/custom-entity-id", settings.idp_entity_id
    assert_equal IDP_CERT.strip, settings.idp_cert.strip
    assert_equal "http://localhost:8081/custom-entity-id", metadata.fetch(:entity_id)
  end

  def test_idp_metadata_xml_parses_entity_id_cert_sso_and_slo_services
    raw_cert = IDP_CERT.lines.reject { |line| line.include?("CERTIFICATE") }.join.delete("\n")
    metadata = BetterAuth::Plugins.sso_saml_idp_metadata(
      idpMetadata: {
        metadata: <<~XML
          <EntityDescriptor entityID="https://idp.example.com/entity" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
            <IDPSSODescriptor>
              <KeyDescriptor use="signing">
                <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                  <X509Data><X509Certificate>#{raw_cert}</X509Certificate></X509Data>
                </KeyInfo>
              </KeyDescriptor>
              <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/post" />
              <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/redirect" />
              <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/logout" />
            </IDPSSODescriptor>
          </EntityDescriptor>
        XML
      }
    )

    assert_equal "https://idp.example.com/entity", metadata.fetch(:entity_id)
    assert_equal IDP_CERT.strip, metadata.fetch(:cert).strip
    assert_equal "https://idp.example.com/post", metadata.fetch(:single_sign_on_service).first.fetch(:location)
    assert_equal "https://idp.example.com/redirect", metadata.fetch(:single_sign_on_service).last.fetch(:location)
    assert_equal "https://idp.example.com/logout", metadata.fetch(:single_logout_service).first.fetch(:location)
  end

  def test_saml_login_uses_redirect_sso_service_from_idp_metadata_when_entry_point_is_missing
    auth = build_auth({})
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "metadata-entry-point-saml",
        issuer: "https://idp.example.com",
        domain: "metadata-entry-point.example.com",
        samlConfig: {
          cert: IDP_CERT,
          callbackUrl: "/dashboard",
          wantAssertionsSigned: false,
          idpMetadata: {
            metadata: <<~XML
              <EntityDescriptor entityID="https://idp.example.com/entity" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
                <IDPSSODescriptor>
                  <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/post" />
                  <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/redirect" />
                </IDPSSODescriptor>
              </EntityDescriptor>
            XML
          }
        }
      }
    )

    sign_in = sign_in_params(auth, providerId: "metadata-entry-point-saml", callbackURL: "/dashboard")

    assert_equal "https://idp.example.com:443/redirect", sign_in.fetch(:url_without_query)
    assert sign_in.fetch(:params).fetch("SAMLRequest")
    assert sign_in.fetch(:params).fetch("RelayState")
  end

  def test_registers_saml_provider_and_returns_sanitized_config
    auth = build_auth({})
    cookie = sign_up_cookie(auth)

    provider = register_saml_provider(auth, cookie, provider_id: "registered-saml")
    stored = auth.context.adapter.find_one(model: "ssoProvider", where: [{field: "providerId", value: "registered-saml"}])

    assert_equal "registered-saml", provider.fetch("providerId")
    assert_equal "saml", provider.fetch("type")
    assert_equal "https://idp.example.com/sso", provider.fetch("samlConfig").fetch("entryPoint")
    refute JSON.generate(provider).include?(IDP_CERT.strip)
    assert_equal IDP_CERT, stored.fetch("samlConfig").fetch(:cert)
  end

  def test_register_saml_provider_preserves_safe_nested_config_without_secret_leaks
    auth = build_auth({})
    cookie = sign_up_cookie(auth)

    provider = register_saml_provider(
      auth,
      cookie,
      provider_id: "nested-config-saml",
      saml_config: {
        spMetadata: {
          entityID: "https://sp.example.com/entity",
          binding: "post",
          privateKey: "sp-private-key",
          privateKeyPass: "sp-private-key-pass"
        },
        idpMetadata: {
          entityID: "https://idp.example.com/entity",
          singleSignOnService: [{binding: "redirect", location: "https://idp.example.com/sso"}],
          privateKey: "idp-private-key",
          encPrivateKey: "idp-encryption-key"
        },
        mapping: {
          email: "mail",
          firstName: "given_name",
          extraFields: {department: "department"}
        }
      }
    )
    serialized = JSON.generate(provider.fetch("samlConfig"))

    assert_equal "https://sp.example.com/entity", provider.fetch("samlConfig").fetch("spMetadata").fetch("entityID")
    assert_equal "post", provider.fetch("samlConfig").fetch("spMetadata").fetch("binding")
    assert_equal "https://idp.example.com/entity", provider.fetch("samlConfig").fetch("idpMetadata").fetch("entityID")
    assert_equal "mail", provider.fetch("samlConfig").fetch("mapping").fetch("email")
    assert_equal "given_name", provider.fetch("samlConfig").fetch("mapping").fetch("firstName")
    refute_includes serialized, "[object Object]"
    refute_includes serialized, "sp-private-key"
    refute_includes serialized, "idp-private-key"
    refute_includes serialized, "idp-encryption-key"
  end

  def test_register_saml_provider_rejects_duplicate_provider_id
    auth = build_auth({})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "duplicate-saml")

    error = assert_raises(BetterAuth::APIError) do
      register_saml_provider(auth, cookie, provider_id: "duplicate-saml")
    end

    assert_equal 422, error.status_code
    assert_equal "SSO provider with this providerId already exists", error.message
  end

  def test_register_saml_provider_respects_zero_provider_limit
    auth = build_auth(providers_limit: 0)
    cookie = sign_up_cookie(auth)

    error = assert_raises(BetterAuth::APIError) do
      register_saml_provider(auth, cookie, provider_id: "disabled-registration-saml")
    end

    assert_equal 403, error.status_code
    assert_equal "SSO provider registration is disabled", error.message
  end

  def test_register_saml_provider_rejects_when_provider_limit_is_reached
    auth = build_auth(providers_limit: 1)
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "first-limited-saml")

    error = assert_raises(BetterAuth::APIError) do
      register_saml_provider(auth, cookie, provider_id: "second-limited-saml")
    end

    assert_equal 403, error.status_code
    assert_equal "You have reached the maximum number of SSO providers", error.message
  end

  def test_register_saml_provider_uses_function_provider_limit
    auth = build_auth(providers_limit: ->(_user) { 1 })
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "first-function-limited-saml")

    error = assert_raises(BetterAuth::APIError) do
      register_saml_provider(auth, cookie, provider_id: "second-function-limited-saml")
    end

    assert_equal 403, error.status_code
    assert_equal "You have reached the maximum number of SSO providers", error.message
  end

  def test_sp_metadata_returns_entity_descriptor_for_registered_saml_provider
    auth = build_auth({})
    cookie = sign_up_cookie(auth)
    register_saml_provider(
      auth,
      cookie,
      provider_id: "metadata-saml",
      saml_config: {
        authnRequestsSigned: true,
        spMetadata: {entityId: "https://sp.example.com/metadata"}
      }
    )

    metadata = auth.api.sp_metadata(query: {providerId: "metadata-saml", format: "json"}).fetch(:metadata)

    assert_includes metadata, "EntityDescriptor"
    assert_includes metadata, "entityID=\"https://sp.example.com/metadata\""
    assert_includes metadata, "AuthnRequestsSigned=\"true\""
    assert_includes metadata, "AssertionConsumerService"
  end

  def test_sp_metadata_returns_explicit_sp_metadata_xml_when_configured
    auth = build_auth({})
    cookie = sign_up_cookie(auth)
    custom_metadata = "<EntityDescriptor entityID=\"https://custom-sp.example.com\"><SPSSODescriptor /></EntityDescriptor>"
    register_saml_provider(
      auth,
      cookie,
      provider_id: "custom-sp-metadata-saml",
      saml_config: {spMetadata: {metadata: custom_metadata}}
    )

    metadata = auth.api.sp_metadata(query: {providerId: "custom-sp-metadata-saml", format: "json"}).fetch(:metadata)

    assert_equal custom_metadata, metadata
  end

  def test_generated_sp_metadata_uses_provider_acs_when_callback_url_is_app_destination
    auth = build_auth({})
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "generated-sp-metadata-saml",
        issuer: "https://sp-issuer.example.com",
        domain: "generated-sp-metadata.example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          cert: IDP_CERT,
          callbackUrl: "https://sp-issuer.example.com/dashboard",
          wantAssertionsSigned: false,
          identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
          spMetadata: {binding: "post"}
        }
      }
    )

    metadata = auth.api.sp_metadata(query: {providerId: "generated-sp-metadata-saml", format: "json"}).fetch(:metadata)

    assert_includes metadata, "<EntityDescriptor entityID=\"https://sp-issuer.example.com\""
    assert_includes metadata, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    assert_includes metadata, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    assert_includes metadata, "Location=\"http://localhost:3000/api/auth/sso/saml2/sp/acs/generated-sp-metadata-saml\""
    refute_includes metadata, "Location=\"https://sp-issuer.example.com/dashboard\""
  end

  def test_saml_settings_use_provider_acs_when_callback_url_is_app_destination
    provider = {
      "providerId" => "settings-acs-provider",
      "issuer" => "https://sp-issuer.example.com",
      "samlConfig" => {
        entryPoint: "https://idp.example.com/sso",
        cert: IDP_CERT,
        callbackUrl: "https://sp-issuer.example.com/dashboard",
        wantAssertionsSigned: false
      }
    }
    ctx = Struct.new(:context).new(Struct.new(:base_url).new("http://localhost:3000/api/auth"))

    settings = BetterAuth::SSO::SAML.build_settings(provider, ctx, BetterAuth::Plugins.normalize_hash(provider.fetch("samlConfig")))

    assert_equal "http://localhost:3000/api/auth/sso/saml2/sp/acs/settings-acs-provider", settings.assertion_consumer_service_url
  end

  def test_relay_state_is_opaque_stored_in_verification_and_acs_allows_cross_site_post_without_cookie
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "relay-saml")

    sign_in = sign_in_params(auth, providerId: "relay-saml", callbackURL: "/dashboard")
    relay_state = sign_in.fetch(:params).fetch("RelayState")
    verification = auth.context.internal_adapter.find_verification_value("#{BetterAuth::Plugins::SSO_SAML_RELAY_STATE_KEY_PREFIX}#{relay_state}")
    response = saml_json_response(id: "relay-assertion", email: "relay@example.com")
    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "relay-saml"},
      body: {SAMLResponse: response, RelayState: relay_state},
      headers: {"origin" => "https://idp.example.com"},
      as_response: true
    )

    refute_includes relay_state, "."
    assert verification
    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("relay@example.com")
  end

  def test_callback_route_allows_cross_site_post_without_relay_state_cookie
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "callback-relay-saml")

    sign_in = sign_in_params(auth, providerId: "callback-relay-saml", callbackURL: "/dashboard")
    relay_state = sign_in.fetch(:params).fetch("RelayState")
    response = saml_json_response(id: "callback-relay-assertion", email: "callback-relay@example.com")

    status, headers, _body = auth.api.callback_sso_saml(
      params: {providerId: "callback-relay-saml"},
      body: {SAMLResponse: response, RelayState: relay_state},
      headers: {"origin" => "https://idp.example.com"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("callback-relay@example.com")
  end

  def test_invalid_relay_state_falls_back_to_provider_callback_url
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "invalid-relay-saml", saml_config: {callbackUrl: "/provider-callback"})
    response = saml_json_response(id: "invalid-relay-assertion", email: "invalid-relay@example.com")

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "invalid-relay-saml"},
      body: {SAMLResponse: response, RelayState: "not-a-valid-relay-state"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/provider-callback", headers.fetch("location")
  end

  def test_relay_state_callback_url_has_priority_over_provider_callback_url
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "callback-priority-saml", saml_config: {callbackUrl: "/provider-callback"})

    sign_in = sign_in_params(auth, providerId: "callback-priority-saml", callbackURL: "/state-callback")
    response = saml_json_response(id: "callback-priority-assertion", email: "callback-priority@example.com")
    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "callback-priority-saml"},
      body: {SAMLResponse: response, RelayState: sign_in.fetch(:params).fetch("RelayState")},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/state-callback", headers.fetch("location")
  end

  def test_saml_callback_allows_signup_when_disable_implicit_sign_up_and_request_sign_up_is_true
    auth = build_auth_with_json_saml_parser(plugin_options: {disable_implicit_sign_up: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "signup-allowed-saml", saml_config: {callbackUrl: "/dashboard"})

    sign_in = sign_in_params(auth, providerId: "signup-allowed-saml", callbackURL: "/dashboard", requestSignUp: true)
    status, headers, _body = auth.api.callback_sso_saml(
      params: {providerId: "signup-allowed-saml"},
      body: {
        SAMLResponse: saml_json_response(id: "signup-allowed-assertion", email: "signup-allowed@example.com"),
        RelayState: sign_in.fetch(:params).fetch("RelayState")
      },
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("signup-allowed@example.com")
  end

  def test_saml_callback_rejects_signup_when_disable_implicit_sign_up_without_request_sign_up
    auth = build_auth_with_json_saml_parser(plugin_options: {disable_implicit_sign_up: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "signup-blocked-saml", saml_config: {callbackUrl: "/dashboard"})

    sign_in = sign_in_params(auth, providerId: "signup-blocked-saml", callbackURL: "/dashboard")
    status, headers, _body = auth.api.callback_sso_saml(
      params: {providerId: "signup-blocked-saml"},
      body: {
        SAMLResponse: saml_json_response(id: "signup-blocked-assertion", email: "signup-blocked@example.com"),
        RelayState: sign_in.fetch(:params).fetch("RelayState")
      },
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard?error=signup+disabled", headers.fetch("location")
    assert_nil auth.context.internal_adapter.find_user_by_email("signup-blocked@example.com")
  end

  def test_saml_acs_rejects_idp_initiated_signup_when_disable_implicit_sign_up
    auth = build_auth_with_json_saml_parser(plugin_options: {disable_implicit_sign_up: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "signup-blocked-acs-saml", saml_config: {callbackUrl: "/dashboard"})

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "signup-blocked-acs-saml"},
      body: {
        SAMLResponse: saml_json_response(id: "signup-blocked-acs-assertion", email: "signup-blocked-acs@example.com"),
        RelayState: "/dashboard"
      },
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard?error=signup+disabled", headers.fetch("location")
    assert_nil auth.context.internal_adapter.find_user_by_email("signup-blocked-acs@example.com")
  end

  def test_untrusted_saml_provider_does_not_link_existing_email
    auth = build_auth_with_json_saml_parser(
      account: {account_linking: {enabled: true, trusted_providers: []}},
      saml_user_info: {id: "untrusted-saml-id", email: "existing-saml@example.com", name: "Existing SAML"}
    )
    sign_up_cookie(auth, email: "existing-saml@example.com")
    owner_cookie = sign_up_cookie(auth, email: "owner-untrusted@example.com")
    register_saml_provider(auth, owner_cookie, provider_id: "untrusted-saml-provider", saml_config: {callbackUrl: "/dashboard"})

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "untrusted-saml-provider"},
      body: {SAMLResponse: saml_json_response(id: "ignored", email: "ignored@example.com")},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard?error=account_not_linked", headers.fetch("location")
    user = auth.context.internal_adapter.find_user_by_email("existing-saml@example.com").fetch(:user)
    refute auth.context.internal_adapter.find_accounts(user.fetch("id")).any? { |account| account["providerId"] == "untrusted-saml-provider" }
  end

  def test_trusted_saml_provider_links_existing_email_with_upstream_provider_id
    auth = build_auth_with_json_saml_parser(
      account: {account_linking: {enabled: true, trusted_providers: ["trusted-saml-provider"]}},
      saml_user_info: {id: "trusted-saml-id", email: "trusted-saml@example.com", name: "Trusted SAML"}
    )
    sign_up_cookie(auth, email: "trusted-saml@example.com")
    owner_cookie = sign_up_cookie(auth, email: "owner-trusted@example.com")
    register_saml_provider(auth, owner_cookie, provider_id: "trusted-saml-provider", saml_config: {callbackUrl: "/dashboard"})

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "trusted-saml-provider"},
      body: {SAMLResponse: saml_json_response(id: "ignored", email: "ignored@example.com")},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    user = auth.context.internal_adapter.find_user_by_email("trusted-saml@example.com").fetch(:user)
    account = auth.context.internal_adapter.find_account_by_provider_id("trusted-saml-id", "trusted-saml-provider")
    assert_equal user.fetch("id"), account.fetch("userId")
  end

  def test_verified_saml_provider_domain_links_existing_matching_email
    auth = build_auth_with_json_saml_parser(
      account: {account_linking: {enabled: true, trusted_providers: []}},
      plugin_options: {domain_verification: {enabled: true}},
      saml_user_info: {id: "verified-domain-saml-id", email: "member@verified-saml.example.com", name: "Verified Domain"}
    )
    sign_up_cookie(auth, email: "member@verified-saml.example.com")
    sign_up_cookie(auth, email: "owner-verified-domain@example.com")
    owner = auth.context.internal_adapter.find_user_by_email("owner-verified-domain@example.com").fetch(:user)
    auth.context.adapter.create(
      model: "ssoProvider",
      data: {
        providerId: "verified-domain-saml",
        issuer: "https://idp.example.com",
        domain: "verified-saml.example.com",
        userId: owner.fetch("id"),
        domainVerified: true,
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          cert: IDP_CERT,
          callbackUrl: "/dashboard",
          audience: "better-auth-ruby",
          wantAssertionsSigned: false
        }
      }
    )

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "verified-domain-saml"},
      body: {SAMLResponse: saml_json_response(id: "ignored", email: "ignored@example.com")},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    user = auth.context.internal_adapter.find_user_by_email("member@verified-saml.example.com").fetch(:user)
    account = auth.context.internal_adapter.find_account_by_provider_id("verified-domain-saml-id", "verified-domain-saml")
    assert_equal user.fetch("id"), account.fetch("userId")
  end

  def test_saml_login_reuses_legacy_sso_prefixed_account_lookup
    auth = build_auth_with_json_saml_parser(
      saml_user_info: {id: "legacy-prefixed-saml-id", email: "legacy-prefixed@example.com", name: "Legacy Prefixed"}
    )
    sign_up_cookie(auth, email: "legacy-prefixed@example.com")
    user = auth.context.internal_adapter.find_user_by_email("legacy-prefixed@example.com").fetch(:user)
    owner_cookie = sign_up_cookie(auth, email: "owner-legacy-prefixed@example.com")
    register_saml_provider(auth, owner_cookie, provider_id: "legacy-prefixed-saml", saml_config: {callbackUrl: "/dashboard"})
    auth.context.internal_adapter.create_account(
      accountId: "legacy-prefixed-saml-id",
      providerId: "sso:legacy-prefixed-saml",
      userId: user.fetch("id")
    )

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "legacy-prefixed-saml"},
      body: {SAMLResponse: saml_json_response(id: "ignored", email: "ignored@example.com")},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert_equal user.fetch("id"), auth.context.internal_adapter.find_account_by_provider_id("legacy-prefixed-saml-id", "sso:legacy-prefixed-saml").fetch("userId")
    assert_nil auth.context.internal_adapter.find_account_by_provider_id("legacy-prefixed-saml-id", "legacy-prefixed-saml")
  end

  def test_saml_provision_user_runs_only_for_new_users_by_default
    provisioned = []
    auth = build_auth_with_json_saml_parser(
      plugin_options: {
        provision_user: ->(user:, provider:, **data) {
          provisioned << [user.fetch("email"), data.fetch(:userInfo).fetch(:id), provider.fetch("providerId")]
        }
      }
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "saml-provision-test", saml_config: {callbackUrl: "/dashboard"})

    first_relay = sign_in_params(auth, providerId: "saml-provision-test", callbackURL: "/dashboard").fetch(:params).fetch("RelayState")
    auth.api.callback_sso_saml(
      params: {providerId: "saml-provision-test"},
      body: {
        SAMLResponse: saml_json_response(id: "saml-provision-one", email: "saml-provision@example.com"),
        RelayState: first_relay
      }
    )

    second_relay = sign_in_params(auth, providerId: "saml-provision-test", callbackURL: "/dashboard").fetch(:params).fetch("RelayState")
    auth.api.callback_sso_saml(
      params: {providerId: "saml-provision-test"},
      body: {
        SAMLResponse: saml_json_response(id: "saml-provision-two", email: "saml-provision@example.com"),
        RelayState: second_relay
      }
    )

    assert_equal [["saml-provision@example.com", "saml-provision-one", "saml-provision-test"]], provisioned
  end

  def test_saml_provision_user_can_run_on_every_login
    provisioned = []
    auth = build_auth_with_json_saml_parser(
      plugin_options: {
        provision_user_on_every_login: true,
        provision_user: ->(user:, **_data) { provisioned << user.fetch("email") }
      }
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "saml-provision-every-login", saml_config: {callbackUrl: "/dashboard"})

    first_relay = sign_in_params(auth, providerId: "saml-provision-every-login", callbackURL: "/dashboard").fetch(:params).fetch("RelayState")
    auth.api.callback_sso_saml(
      params: {providerId: "saml-provision-every-login"},
      body: {
        SAMLResponse: saml_json_response(id: "saml-provision-every-one", email: "saml-provision-every@example.com"),
        RelayState: first_relay
      }
    )

    second_relay = sign_in_params(auth, providerId: "saml-provision-every-login", callbackURL: "/dashboard").fetch(:params).fetch("RelayState")
    auth.api.callback_sso_saml(
      params: {providerId: "saml-provision-every-login"},
      body: {
        SAMLResponse: saml_json_response(id: "saml-provision-every-two", email: "saml-provision-every@example.com"),
        RelayState: second_relay
      }
    )

    assert_equal ["saml-provision-every@example.com", "saml-provision-every@example.com"], provisioned
  end

  def test_saml_acs_finds_db_provider_when_default_sso_is_configured
    auth = build_auth_with_json_saml_parser(
      plugin_options: {
        default_sso: [
          default_saml_provider(provider_id: "default-provider", domain: "default.example.com")
        ]
      }
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "db-provider", saml_config: {callbackUrl: "/dashboard"})

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "db-provider"},
      body: {SAMLResponse: saml_json_response(id: "db-provider-assertion", email: "db-provider@example.com")},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("db-provider@example.com")
  end

  def test_saml_acs_returns_not_found_for_unknown_provider_even_with_default_sso
    auth = build_auth_with_json_saml_parser(
      plugin_options: {
        default_sso: [
          default_saml_provider(provider_id: "default-provider", domain: "default.example.com")
        ]
      }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.acs_endpoint(
        params: {providerId: "nonexistent-provider"},
        body: {SAMLResponse: saml_json_response(id: "unknown-provider-assertion", email: "unknown-provider@example.com")}
      )
    end

    assert_equal 404, error.status_code
    assert_equal "Provider not found", error.message
  end

  def test_register_saml_provider_rejects_invalid_or_missing_entry_point_without_metadata
    auth = build_auth({})
    cookie = sign_up_cookie(auth)

    invalid = assert_raises(BetterAuth::APIError) do
      register_saml_provider(
        auth,
        cookie,
        provider_id: "invalid-entry-point-provider",
        saml_config: {entryPoint: "not-a-url"}
      )
    end
    assert_equal 400, invalid.status_code
    assert_match(/entryPoint/, invalid.message)

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.register_sso_provider(
        headers: {"cookie" => cookie},
        body: {
          providerId: "missing-entry-point-provider",
          issuer: "https://idp.example.com",
          domain: "missing-entry-point.example.com",
          samlConfig: {cert: IDP_CERT}
        }
      )
    end
    assert_equal 400, missing.status_code
    assert_match(/entryPoint/, missing.message)
  end

  def test_unsolicited_saml_response_is_rejected_when_idp_initiated_is_disabled
    auth = build_auth_with_json_saml_parser(
      saml_options: {allowIdpInitiated: false},
      saml_user_info: {id: "strict-unsolicited-id", email: "strict-unsolicited@example.com", name: "Strict"}
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "strict-saml-provider", saml_config: {callbackUrl: "/dashboard"})
    relay_state = sign_in_params(auth, providerId: "strict-saml-provider", callbackURL: "/dashboard").fetch(:params).fetch("RelayState")

    status, headers, _body = auth.api.callback_sso_saml(
      params: {providerId: "strict-saml-provider"},
      body: {SAMLResponse: saml_xml_response(assertion_id: "strict-unsolicited"), RelayState: relay_state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard?error=unsolicited_response&error_description=IdP-initiated+SSO+not+allowed", headers.fetch("location")
    assert_nil auth.context.internal_adapter.find_user_by_email("strict-unsolicited@example.com")
  end

  def test_unsolicited_saml_response_is_allowed_when_idp_initiated_is_enabled
    auth = build_auth_with_json_saml_parser(
      saml_options: {allowIdpInitiated: true},
      saml_user_info: {id: "permissive-unsolicited-id", email: "permissive-unsolicited@example.com", name: "Permissive"}
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "permissive-saml-provider", saml_config: {callbackUrl: "/dashboard"})

    status, headers, _body = auth.api.callback_sso_saml(
      params: {providerId: "permissive-saml-provider"},
      body: {SAMLResponse: saml_xml_response(assertion_id: "permissive-unsolicited")},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("permissive-unsolicited@example.com")
  end

  def test_in_response_to_validation_can_be_disabled
    auth = build_auth_with_json_saml_parser(
      saml_options: {enableInResponseToValidation: false, allowIdpInitiated: false},
      saml_user_info: {id: "legacy-saml-id", email: "legacy-saml@example.com", name: "Legacy"}
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "legacy-saml-provider", saml_config: {callbackUrl: "/dashboard"})

    status, headers, _body = auth.api.callback_sso_saml(
      params: {providerId: "legacy-saml-provider"},
      body: {SAMLResponse: saml_xml_response(assertion_id: "legacy-saml")},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("legacy-saml@example.com")
  end

  def test_in_response_to_validation_uses_verification_table_and_deletes_used_request
    auth = build_auth_with_json_saml_parser(
      saml_options: {enableInResponseToValidation: true, allowIdpInitiated: false},
      saml_user_info: {id: "known-request-id", email: "known-request@example.com", name: "Known Request"}
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "db-fallback-provider", saml_config: {callbackUrl: "/dashboard"})
    sign_in = sign_in_params(auth, providerId: "db-fallback-provider", callbackURL: "/dashboard")
    request_id = saml_request_id_from_url(sign_in.fetch(:url))
    relay_state = sign_in.fetch(:params).fetch("RelayState")

    status, headers, _body = auth.api.callback_sso_saml(
      params: {providerId: "db-fallback-provider"},
      body: {SAMLResponse: saml_xml_response(assertion_id: "known-request", in_response_to: request_id), RelayState: relay_state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert_nil auth.context.internal_adapter.find_verification_value("#{BetterAuth::Plugins::SSO_SAML_AUTHN_REQUEST_KEY_PREFIX}#{request_id}")
  end

  def test_in_response_to_validation_rejects_unknown_and_provider_mismatch_requests
    auth = build_auth_with_json_saml_parser(
      saml_options: {enableInResponseToValidation: true, allowIdpInitiated: false},
      saml_user_info: {id: "blocked-request-id", email: "blocked-request@example.com", name: "Blocked"}
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "strict-request-provider", saml_config: {callbackUrl: "/dashboard"})
    relay_state = sign_in_params(auth, providerId: "strict-request-provider", callbackURL: "/dashboard").fetch(:params).fetch("RelayState")

    unknown = auth.api.callback_sso_saml(
      params: {providerId: "strict-request-provider"},
      body: {SAMLResponse: saml_xml_response(assertion_id: "unknown-request", in_response_to: "_unknown"), RelayState: relay_state},
      as_response: true
    )
    assert_equal "/dashboard?error=invalid_saml_response&error_description=Unknown+or+expired+request+ID", unknown[1].fetch("location")

    auth.context.internal_adapter.create_verification_value(
      identifier: "#{BetterAuth::Plugins::SSO_SAML_AUTHN_REQUEST_KEY_PREFIX}_mismatch",
      value: JSON.generate({id: "_mismatch", providerId: "other-provider", createdAt: Time.now.to_i * 1000, expiresAt: (Time.now.to_i + 300) * 1000}),
      expiresAt: Time.now + 300
    )
    mismatch = auth.api.callback_sso_saml(
      params: {providerId: "strict-request-provider"},
      body: {SAMLResponse: saml_xml_response(assertion_id: "mismatch-request", in_response_to: "_mismatch"), RelayState: relay_state},
      as_response: true
    )

    assert_equal "/dashboard?error=invalid_saml_response&error_description=Provider+mismatch", mismatch[1].fetch("location")
    assert_nil auth.context.internal_adapter.find_verification_value("#{BetterAuth::Plugins::SSO_SAML_AUTHN_REQUEST_KEY_PREFIX}_mismatch")
  end

  def test_raw_relay_state_external_urls_do_not_create_open_redirects
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "open-redirect-provider", saml_config: {callbackUrl: "/dashboard"})

    ["https://evil.example.com/phishing", "//evil.example.com/phishing"].each_with_index do |relay_state, index|
      status, headers, _body = auth.api.callback_sso_saml(
        params: {providerId: "open-redirect-provider"},
        body: {SAMLResponse: saml_json_response(id: "open-redirect-#{index}", email: "open-redirect-#{index}@example.com"), RelayState: relay_state},
        as_response: true
      )

      assert_equal 302, status
      refute_includes headers.fetch("location"), "evil.example.com"
      assert_equal "/dashboard", headers.fetch("location")
    end
  end

  def test_raw_relay_state_relative_path_falls_back_to_provider_callback_url
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "relative-relay-provider", saml_config: {callbackUrl: "http://localhost:3000/dashboard"})

    status, headers, _body = auth.api.callback_sso_saml(
      params: {providerId: "relative-relay-provider"},
      body: {
        SAMLResponse: saml_json_response(id: "relative-relay-assertion", email: "relative-relay@example.com"),
        RelayState: "/dashboard/settings"
      },
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/dashboard", headers.fetch("location")
  end

  def test_idp_initiated_get_blocks_protocol_relative_relay_state_with_existing_session
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "get-protocol-relative", saml_config: {callbackUrl: "http://localhost:3000/dashboard"})
    _post_status, post_headers, _post_body = auth.api.callback_sso_saml(
      params: {providerId: "get-protocol-relative"},
      body: {SAMLResponse: saml_json_response(id: "get-protocol-relative-assertion", email: "get-protocol-relative@example.com")},
      as_response: true
    )
    session_cookie = post_headers.fetch("set-cookie").to_s.lines.map { |line| line.split(";").first }.join("; ")

    status, headers, _body = auth.api.callback_sso_saml(
      method: "GET",
      params: {providerId: "get-protocol-relative"},
      query: {RelayState: "//evil.example.com/phishing"},
      headers: {"cookie" => session_cookie},
      as_response: true
    )

    assert_equal 302, status
    refute_includes headers.fetch("location"), "evil.example.com"
    assert_equal "http://localhost:3000/api/auth", headers.fetch("location")
  end

  def test_saml_callback_post_from_external_idp_origin_bypasses_origin_check
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "origin-callback-provider", saml_config: {callbackUrl: "/dashboard"})

    status, headers, _body = rack_json_request(
      auth,
      "/sso/saml2/callback/origin-callback-provider",
      origin: "https://external-idp.example.com",
      body: {
        SAMLResponse: saml_json_response(id: "origin-callback-assertion", email: "origin-callback@example.com"),
        RelayState: "/dashboard"
      }
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    refute_equal 403, status
  end

  def test_saml_acs_post_from_external_idp_origin_bypasses_origin_check
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "origin-acs-provider", saml_config: {callbackUrl: "/dashboard"})

    status, headers, _body = rack_json_request(
      auth,
      "/sso/saml2/sp/acs/origin-acs-provider",
      origin: "https://external-idp.example.com",
      body: {
        SAMLResponse: saml_json_response(id: "origin-acs-assertion", email: "origin-acs@example.com"),
        RelayState: "/dashboard"
      }
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    refute_equal 403, status
  end

  def test_origin_check_still_blocks_non_saml_cross_site_posts
    auth = build_auth_with_json_saml_parser

    status, _headers, body = rack_json_request(
      auth,
      "/sign-up/email",
      origin: "https://attacker.example.com",
      cookie: "better-auth.session_token=fake-session",
      body: {
        email: "blocked-cross-site@example.com",
        password: "password123",
        name: "Blocked"
      }
    )
    data = JSON.parse(body.join)

    assert_equal 403, status
    assert_equal "Invalid origin", data.fetch("message")
  end

  def test_saml_metadata_get_from_external_origin_is_not_blocked
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "origin-metadata-provider")

    status, _headers, body = rack_json_request(
      auth,
      "/sso/saml2/sp/metadata?providerId=origin-metadata-provider&format=json",
      method: "GET",
      origin: "https://external-idp.example.com"
    )
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_includes data.fetch("metadata"), "EntityDescriptor"
  end

  def test_saml_origin_bypass_does_not_allow_malicious_relay_state_redirect
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "origin-open-redirect-provider", saml_config: {callbackUrl: "/dashboard"})

    status, headers, _body = rack_json_request(
      auth,
      "/sso/saml2/callback/origin-open-redirect-provider",
      origin: "https://external-idp.example.com",
      body: {
        SAMLResponse: saml_json_response(id: "origin-open-redirect-assertion", email: "origin-open-redirect@example.com"),
        RelayState: "https://evil.example.com/phishing"
      }
    )

    assert_equal 302, status
    refute_includes headers.fetch("location"), "evil.example.com"
    assert_equal "/dashboard", headers.fetch("location")
  end

  def test_provider_callback_url_pointing_to_saml_callback_route_does_not_loop
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(
      auth,
      cookie,
      provider_id: "callback-loop-provider",
      saml_config: {callbackUrl: "http://localhost:3000/api/auth/sso/saml2/callback/callback-loop-provider"}
    )

    status, headers, _body = auth.api.callback_sso_saml(
      params: {providerId: "callback-loop-provider"},
      body: {SAMLResponse: saml_json_response(id: "callback-loop-assertion", email: "callback-loop@example.com")},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth", headers.fetch("location")
  end

  def test_get_after_callback_loop_post_without_relay_state_redirects_to_base_url
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(
      auth,
      cookie,
      provider_id: "callback-loop-get-provider",
      saml_config: {callbackUrl: "http://localhost:3000/api/auth/sso/saml2/callback/callback-loop-get-provider"}
    )

    _post_status, post_headers, _post_body = auth.api.callback_sso_saml(
      params: {providerId: "callback-loop-get-provider"},
      body: {SAMLResponse: saml_json_response(id: "callback-loop-get-assertion", email: "callback-loop-get@example.com")},
      as_response: true
    )
    session_cookie = post_headers.fetch("set-cookie").to_s.lines.map { |line| line.split(";").first }.join("; ")

    status, headers, _body = auth.api.callback_sso_saml(
      method: "GET",
      params: {providerId: "callback-loop-get-provider"},
      headers: {"cookie" => session_cookie},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth", headers.fetch("location")
  end

  def test_provider_callback_url_pointing_to_saml_acs_route_does_not_loop
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(
      auth,
      cookie,
      provider_id: "acs-loop-provider",
      saml_config: {callbackUrl: "http://localhost:3000/api/auth/sso/saml2/sp/acs/acs-loop-provider"}
    )

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "acs-loop-provider"},
      body: {SAMLResponse: saml_json_response(id: "acs-loop-assertion", email: "acs-loop@example.com")},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth", headers.fetch("location")
  end

  def test_idp_initiated_get_after_post_uses_query_relay_state_with_existing_session
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(
      auth,
      cookie,
      provider_id: "idp-get-after-post",
      saml_config: {callbackUrl: "http://localhost:3000/dashboard"}
    )
    _post_status, post_headers, _post_body = auth.api.callback_sso_saml(
      params: {providerId: "idp-get-after-post"},
      body: {
        SAMLResponse: saml_json_response(id: "idp-get-after-post-assertion", email: "idp-get-after-post@example.com"),
        RelayState: "http://localhost:3000/dashboard"
      },
      as_response: true
    )
    session_cookie = post_headers.fetch("set-cookie").to_s.lines.map { |line| line.split(";").first }.join("; ")

    status, headers, _body = auth.api.callback_sso_saml(
      method: "GET",
      params: {providerId: "idp-get-after-post"},
      query: {RelayState: "http://localhost:3000/custom-path"},
      headers: {"cookie" => session_cookie},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/custom-path", headers.fetch("location")
  end

  def test_idp_initiated_get_without_session_redirects_to_error
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "idp-get-no-session", saml_config: {callbackUrl: "/dashboard"})

    status, headers, _body = auth.api.callback_sso_saml(
      method: "GET",
      params: {providerId: "idp-get-no-session"},
      query: {RelayState: "/dashboard"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth/error?error=invalid_request", headers.fetch("location")
  end

  def test_idp_initiated_get_blocks_malicious_relay_state_with_existing_session
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "idp-get-malicious", saml_config: {callbackUrl: "/dashboard"})
    _post_status, post_headers, _post_body = auth.api.callback_sso_saml(
      params: {providerId: "idp-get-malicious"},
      body: {SAMLResponse: saml_json_response(id: "idp-get-malicious-assertion", email: "idp-get-malicious@example.com")},
      as_response: true
    )
    session_cookie = post_headers.fetch("set-cookie").to_s.lines.map { |line| line.split(";").first }.join("; ")

    status, headers, _body = auth.api.callback_sso_saml(
      method: "GET",
      params: {providerId: "idp-get-malicious"},
      query: {RelayState: "https://evil.example.com/steal"},
      headers: {"cookie" => session_cookie},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth", headers.fetch("location")
  end

  def test_timestamp_validation_accepts_valid_clock_skew_and_partial_conditions
    now = Time.utc(2026, 5, 1, 12, 0, 0)

    assert_equal true, BetterAuth::Plugins.sso_validate_saml_timestamp!(
      {notBefore: now.iso8601, notOnOrAfter: (now + 300).iso8601},
      {},
      now: now
    )
    assert_equal true, BetterAuth::Plugins.sso_validate_saml_timestamp!({notOnOrAfter: (now - 120).iso8601}, {}, now: now)
    assert_equal true, BetterAuth::Plugins.sso_validate_saml_timestamp!({notBefore: (now + 120).iso8601}, {}, now: now)
    assert_equal true, BetterAuth::Plugins.sso_validate_saml_timestamp!({notBefore: now.iso8601}, {}, now: now)
    assert_equal true, BetterAuth::Plugins.sso_validate_saml_timestamp!({notOnOrAfter: (now + 600).iso8601}, {}, now: now)
  end

  def test_timestamp_validation_rejects_future_expired_and_strict_clock_skew_cases
    now = Time.utc(2026, 5, 1, 12, 0, 0)

    future = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({notBefore: (now + 600).iso8601}, {}, now: now)
    end
    assert_equal "SAML assertion is not yet valid", future.message

    strict_future = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({notBefore: (now + 3).iso8601}, {saml: {clock_skew: 1000}}, now: now)
    end
    assert_equal "SAML assertion is not yet valid", strict_future.message

    expired = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({notOnOrAfter: (now - 600).iso8601}, {}, now: now)
    end
    assert_equal "SAML assertion has expired", expired.message

    strict_expired = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({notOnOrAfter: (now - 3).iso8601}, {saml: {clock_skew: 1000}}, now: now)
    end
    assert_equal "SAML assertion has expired", strict_expired.message
  end

  def test_timestamp_validation_boundary_missing_and_malformed_cases
    now = Time.utc(2026, 5, 1, 12, 0, 0)
    skew = BetterAuth::Plugins::SSO_DEFAULT_CLOCK_SKEW_MS / 1000.0

    assert_equal true, BetterAuth::Plugins.sso_validate_saml_timestamp!({notOnOrAfter: (now - skew).iso8601}, {}, now: now)
    assert_raises(BetterAuth::APIError) { BetterAuth::Plugins.sso_validate_saml_timestamp!({notOnOrAfter: (now - skew - 0.001).iso8601(3)}, {}, now: now) }
    assert_equal true, BetterAuth::Plugins.sso_validate_saml_timestamp!({notBefore: (now + skew).iso8601}, {}, now: now)
    assert_raises(BetterAuth::APIError) { BetterAuth::Plugins.sso_validate_saml_timestamp!({notBefore: (now + skew + 0.001).iso8601(3)}, {}, now: now) }
    assert_equal true, BetterAuth::Plugins.sso_validate_saml_timestamp!({}, {saml: {require_timestamps: false}}, now: now)

    required = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({}, {saml: {require_timestamps: true}}, now: now)
    end
    assert_equal "SAML assertion missing required timestamp conditions", required.message

    invalid_not_before = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({notBefore: "not-a-valid-date"}, {}, now: now)
    end
    assert_equal "SAML assertion has invalid NotBefore timestamp", invalid_not_before.message

    invalid_not_on_or_after = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_timestamp!({notOnOrAfter: "invalid-timestamp"}, {}, now: now)
    end
    assert_equal "SAML assertion has invalid NotOnOrAfter timestamp", invalid_not_on_or_after.message
  end

  def test_saml_response_and_metadata_size_limits_are_enforced
    assert_equal 256 * 1024, BetterAuth::Plugins::SSO_DEFAULT_MAX_SAML_RESPONSE_SIZE
    assert_equal 100 * 1024, BetterAuth::Plugins::SSO_DEFAULT_MAX_SAML_METADATA_SIZE

    auth = build_auth_with_json_saml_parser(saml_options: {maxResponseSize: 8})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "size-limit-provider")

    response_error = assert_raises(BetterAuth::APIError) do
      auth.api.acs_endpoint(params: {providerId: "size-limit-provider"}, body: {SAMLResponse: "x" * 9})
    end
    assert_equal "SAML response exceeds maximum allowed size (8 bytes)", response_error.message

    metadata_auth = build_auth(BetterAuth::SSO::SAML.sso_options.merge(saml: {maxMetadataSize: 8}))
    metadata_cookie = sign_up_cookie(metadata_auth)
    metadata_error = assert_raises(BetterAuth::APIError) do
      metadata_auth.api.register_sso_provider(
        headers: {"cookie" => metadata_cookie},
        body: {
          providerId: "metadata-size-provider",
          issuer: "https://idp.example.com",
          domain: "metadata-size.example.com",
          samlConfig: {idpMetadata: "<EntityDescriptor>too large</EntityDescriptor>"}
        }
      )
    end
    assert_equal "IdP metadata exceeds maximum allowed size (8 bytes)", metadata_error.message
  end

  def test_single_assertion_validation_rejects_none_multiple_and_xsw_but_accepts_one
    no_assertion = Base64.strict_encode64("<Response></Response>")
    no_assertion_error = assert_raises(BetterAuth::APIError) { BetterAuth::Plugins.sso_validate_single_saml_assertion!(no_assertion) }
    assert_equal "SAML response contains no assertions", no_assertion_error.message

    multiple = Base64.strict_encode64("<Response><Assertion ID=\"one\"/><EncryptedAssertion ID=\"two\"/></Response>")
    multiple_error = assert_raises(BetterAuth::APIError) { BetterAuth::Plugins.sso_validate_single_saml_assertion!(multiple) }
    assert_match(/expected exactly 1/, multiple_error.message)

    xsw = Base64.strict_encode64("<Response><Extensions><Assertion ID=\"injected\"/></Extensions><Assertion ID=\"real\"/></Response>")
    xsw_error = assert_raises(BetterAuth::APIError) { BetterAuth::Plugins.sso_validate_single_saml_assertion!(xsw) }
    assert_match(/expected exactly 1/, xsw_error.message)

    valid = Base64.strict_encode64("<Response><Assertion ID=\"one\"><Subject /></Assertion></Response>")
    assert_equal true, BetterAuth::Plugins.sso_validate_single_saml_assertion!(valid)
  end

  def test_replayed_saml_assertion_is_rejected_across_callback_and_acs
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "replay-provider")
    response = saml_json_response(id: "replayed-assertion", email: "replay@example.com")

    first = auth.api.callback_sso_saml(
      params: {providerId: "replay-provider"},
      body: {SAMLResponse: response, RelayState: "/dashboard"},
      as_response: true
    )
    assert_equal 302, first[0]

    replay_status, replay_headers, _replay_body = auth.api.acs_endpoint(
      params: {providerId: "replay-provider"},
      body: {SAMLResponse: response, RelayState: "/dashboard"},
      as_response: true
    )
    assert_equal 302, replay_status
    assert_equal "/dashboard?error=replay_detected&error_description=SAML+assertion+has+already+been+used", replay_headers.fetch("location")
  end

  def test_saml_default_provider_is_used_for_acs_callback
    auth = build_auth_with_json_saml_parser(
      plugin_options: {
        defaultSSO: [
          default_saml_provider(provider_id: "default-callback", domain: "default-callback.example.com")
        ]
      }
    )
    sign_in = sign_in_params(auth, providerId: "default-callback", callbackURL: "/dashboard")

    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "default-callback"},
      body: {SAMLResponse: saml_json_response(id: "default-callback-id", email: "default-callback@example.com"), RelayState: sign_in.fetch(:params).fetch("RelayState")},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("default-callback@example.com")
  end

  def test_saml_replay_without_assertion_id_does_not_block_later_email_login
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "no-assertion-id")

    first = auth.api.acs_endpoint(
      params: {providerId: "no-assertion-id"},
      body: {SAMLResponse: Base64.strict_encode64(JSON.generate({email: "no-id@example.com", name: "No ID One"})), RelayState: "/dashboard"},
      as_response: true
    )
    second = auth.api.acs_endpoint(
      params: {providerId: "no-assertion-id"},
      body: {SAMLResponse: Base64.strict_encode64(JSON.generate({email: "no-id@example.com", name: "No ID Two"})), RelayState: "/dashboard"},
      as_response: true
    )

    assert_equal 302, first[0]
    assert_equal 302, second[0]
  end

  def test_saml_email_is_normalized_to_lowercase_and_existing_user_is_reused
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "email-case-provider")

    first = auth.api.callback_sso_saml(
      params: {providerId: "email-case-provider"},
      body: {SAMLResponse: saml_json_response(id: "email-case-one", email: "SAMLUser@Example.COM"), RelayState: "/dashboard"},
      as_response: true
    )
    first_user = auth.context.internal_adapter.find_user_by_email("samluser@example.com").fetch(:user)
    second = auth.api.callback_sso_saml(
      params: {providerId: "email-case-provider"},
      body: {SAMLResponse: saml_json_response(id: "email-case-two", email: "samluser@example.com"), RelayState: "/dashboard"},
      as_response: true
    )
    second_user = auth.context.internal_adapter.find_user_by_email("samluser@example.com").fetch(:user)

    assert_equal 302, first[0]
    assert_equal 302, second[0]
    assert_equal "samluser@example.com", second_user.fetch("email")
    assert_equal first_user.fetch("id"), second_user.fetch("id")
  end

  def test_slo_endpoint_requires_single_logout_to_be_enabled
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "slo-disabled-test")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.slo_endpoint(
        params: {providerId: "slo-disabled-test"},
        body: {SAMLRequest: saml_logout_request(name_id: "user@example.com", session_index: "session-index")}
      )
    end

    assert_equal 400, error.status_code
    assert_equal "Single Logout is not enabled", error.message
  end

  def test_slo_endpoint_returns_not_found_for_unknown_provider
    auth = build_auth_with_json_saml_parser(saml_options: {enableSingleLogout: true})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.slo_endpoint(
        params: {providerId: "missing-slo-provider"},
        body: {SAMLRequest: saml_logout_request(name_id: "user@example.com", session_index: "session-index")}
      )
    end

    assert_equal 404, error.status_code
    assert_equal "Provider not found", error.message
  end

  def test_slo_endpoint_rejects_missing_saml_payload
    auth = build_auth_with_json_saml_parser(saml_options: {enableSingleLogout: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "missing-slo-payload", saml_config: {singleLogoutService: "https://idp.example.com/slo"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.slo_endpoint(params: {providerId: "missing-slo-payload"}, body: {})
    end

    assert_equal 400, error.status_code
    assert_equal "Invalid LogoutRequest", error.message
  end

  def test_slo_rejects_fake_logout_request_signature_and_keeps_session
    auth = build_auth_with_json_saml_parser(
      saml_options: {enableSingleLogout: true, wantLogoutRequestSigned: true},
      saml_user_info: {
        id: "assertion-fake-sig",
        email: "fake-sig@example.com",
        name: "Fake Sig",
        name_id: "fake-sig-name-id",
        session_index: "fake-sig-session"
      }
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "fake-sig-slo", saml_config: {singleLogoutService: "https://idp.example.com/slo"})
    _login_status, login_headers, _login_body = auth.api.acs_endpoint(
      params: {providerId: "fake-sig-slo"},
      body: {SAMLResponse: saml_xml_response(assertion_id: "assertion-fake-sig")},
      as_response: true
    )
    session_token = login_headers.fetch("set-cookie")[/better-auth\.session_token=([^.;]+)/, 1]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.slo_endpoint(
        params: {providerId: "fake-sig-slo"},
        body: {
          SAMLRequest: saml_logout_request(name_id: "fake-sig-name-id", session_index: "fake-sig-session"),
          SigAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
          Signature: "not-a-valid-signature"
        }
      )
    end

    assert_equal 400, error.status_code
    assert_equal "Invalid LogoutRequest", error.message
    assert auth.context.internal_adapter.find_session(session_token)
  end

  def test_slo_post_from_external_idp_origin_bypasses_origin_check
    auth = build_auth_with_json_saml_parser(saml_options: {enableSingleLogout: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "slo-origin-bypass", saml_config: {singleLogoutService: "https://idp.example.com/slo"})

    status, headers, body = rack_json_request(
      auth,
      "/sso/saml2/sp/slo/slo-origin-bypass",
      origin: "https://external-idp.example.com",
      cookie: cookie,
      body: {
        SAMLRequest: saml_logout_request(name_id: "slo-origin@example.com", session_index: "slo-origin-session")
      }
    )

    refute_equal 403, status
    assert_equal 200, status
    assert_equal "text/html", headers.fetch("content-type")
    assert_includes body.join, "name=\"SAMLResponse\""
  end

  def test_sp_metadata_includes_single_logout_service_only_when_slo_is_enabled
    enabled = build_auth_with_json_saml_parser(saml_options: {enableSingleLogout: true})
    enabled_cookie = sign_up_cookie(enabled)
    register_saml_provider(enabled, enabled_cookie, provider_id: "slo-metadata-test", saml_config: {spMetadata: {entityId: "https://sp.example.com/metadata"}})

    enabled_metadata = enabled.api.sp_metadata(query: {providerId: "slo-metadata-test", format: "json"}).fetch(:metadata)
    assert_includes enabled_metadata, "SingleLogoutService"
    assert_includes enabled_metadata, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    assert_includes enabled_metadata, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    assert_includes enabled_metadata, "/sso/saml2/sp/slo/slo-metadata-test"

    disabled = build_auth_with_json_saml_parser
    disabled_cookie = sign_up_cookie(disabled)
    register_saml_provider(disabled, disabled_cookie, provider_id: "slo-metadata-disabled", saml_config: {spMetadata: {entityId: "https://sp.example.com/metadata"}})

    disabled_metadata = disabled.api.sp_metadata(query: {providerId: "slo-metadata-disabled", format: "json"}).fetch(:metadata)
    refute_includes disabled_metadata, "SingleLogoutService"
  end

  def test_register_saml_rejects_idp_metadata_without_metadata_or_sso_service
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)

    error = assert_raises(BetterAuth::APIError) do
      register_saml_provider(
        auth,
        cookie,
        provider_id: "invalid-idp-metadata",
        saml_config: {
          entryPoint: nil,
          idpMetadata: {entityID: "https://idp.example.com/entity"}
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/SAML configuration requires/, error.message)
  end

  def test_sp_metadata_escapes_configured_xml_values
    auth = build_auth_with_json_saml_parser
    cookie = sign_up_cookie(auth)
    register_saml_provider(
      auth,
      cookie,
      provider_id: "escaped-metadata",
      saml_config: {
        spMetadata: {entityId: "https://sp.example.com/metadata?x=1&y=<bad>"},
        identifierFormat: "urn:test:nameid&format"
      }
    )

    metadata = auth.api.sp_metadata(query: {providerId: "escaped-metadata", format: "json"}).fetch(:metadata)

    assert_includes metadata, "x=1&amp;y=&lt;bad&gt;"
    assert_includes metadata, "urn:test:nameid&amp;format"
    REXML::Document.new(metadata)
  end

  def test_sp_initiated_slo_requires_idp_single_logout_service
    auth = build_auth_with_json_saml_parser(saml_options: {enableSingleLogout: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "sp-slo-no-idp-slo", saml_config: {callbackUrl: "/dashboard"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.initiate_slo(
        headers: {"cookie" => cookie},
        params: {providerId: "sp-slo-no-idp-slo"},
        body: {callbackURL: "/logged-out"}
      )
    end

    assert_equal 400, error.status_code
    assert_equal "IdP does not support Single Logout Service", error.message
  end

  def test_sp_initiated_slo_generates_logout_request_and_stores_pending_request
    auth = build_auth_with_json_saml_parser(saml_options: {enableSingleLogout: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "sp-slo-initiate", saml_config: {singleLogoutService: "https://idp.example.com/slo"})

    status, headers, _body = auth.api.initiate_slo(
      headers: {"cookie" => cookie},
      params: {providerId: "sp-slo-initiate"},
      body: {callbackURL: "/logged-out"},
      as_response: true
    )
    request_id = saml_logout_request_id_from_url(headers.fetch("location"))

    assert_equal 302, status
    assert_match %r{\Ahttps://idp\.example\.com/slo\?}, headers.fetch("location")
    assert headers.fetch("location").include?("SAMLRequest=")
    assert_equal "sp-slo-initiate", auth.context.internal_adapter.find_verification_value("#{BetterAuth::Plugins::SSO_SAML_LOGOUT_REQUEST_KEY_PREFIX}#{request_id}").fetch("value")
  end

  def test_sp_initiated_slo_uses_stored_saml_name_id_and_session_index
    auth = build_auth_with_json_saml_parser(
      saml_options: {enableSingleLogout: true},
      saml_user_info: {
        id: "assertion-slo-request",
        email: "slo-request@example.com",
        name: "SLO Request",
        name_id: "name-id-request",
        session_index: "session-index-request"
      }
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "slo-session-provider", saml_config: {singleLogoutService: "https://idp.example.com/slo"})

    _login_status, login_headers, _login_body = auth.api.acs_endpoint(
      params: {providerId: "slo-session-provider"},
      body: {SAMLResponse: saml_xml_response(assertion_id: "assertion-slo-request")},
      as_response: true
    )
    saml_cookie = login_headers.fetch("set-cookie").to_s.lines.map { |line| line.split(";").first }.join("; ")
    status, headers, _body = auth.api.initiate_slo(
      headers: {"cookie" => saml_cookie},
      params: {providerId: "slo-session-provider"},
      body: {callbackURL: "/after-logout"},
      as_response: true
    )
    logout_request_xml = saml_logout_request_xml_from_url(headers.fetch("location"))

    assert_equal 302, status
    assert_includes logout_request_xml, "<saml:NameID>name-id-request</saml:NameID>"
    assert_includes logout_request_xml, "<samlp:SessionIndex>session-index-request</samlp:SessionIndex>"
  end

  def test_idp_initiated_slo_logout_request_deletes_matching_session_and_returns_response
    auth = build_auth_with_json_saml_parser(
      saml_options: {enableSingleLogout: true},
      saml_user_info: {
        id: "assertion-slo-delete",
        email: "slo-delete@example.com",
        name: "SLO Delete",
        name_id: "name-id-delete",
        session_index: "session-index-delete"
      }
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "idp-slo-test", saml_config: {singleLogoutService: "https://idp.example.com/slo"})
    _login_status, login_headers, _login_body = auth.api.acs_endpoint(
      params: {providerId: "idp-slo-test"},
      body: {SAMLResponse: saml_xml_response(assertion_id: "assertion-slo-delete")},
      as_response: true
    )
    session_token = login_headers.fetch("set-cookie")[/better-auth\.session_token=([^.;]+)/, 1]
    assert auth.context.internal_adapter.find_session(session_token)

    status, response_headers, response_body = auth.api.slo_endpoint(
      params: {providerId: "idp-slo-test"},
      body: {SAMLRequest: saml_logout_request(name_id: "name-id-delete", session_index: "session-index-delete"), RelayState: "/signed-out"},
      as_response: true
    )

    assert_equal 200, status
    assert_equal "text/html", response_headers.fetch("content-type")
    assert_includes response_body.join, "name=\"SAMLResponse\""
    assert_includes response_body.join, "name=\"RelayState\" value=\"/signed-out\""
    assert_nil auth.context.internal_adapter.find_session(session_token)
  end

  def test_idp_initiated_slo_logout_response_includes_in_response_to
    auth = build_auth_with_json_saml_parser(
      saml_options: {enableSingleLogout: true},
      saml_user_info: {
        id: "assertion-slo-in-response-to",
        email: "slo-in-response-to@example.com",
        name: "SLO InResponseTo",
        name_id: "name-id-in-response-to",
        session_index: "session-index-in-response-to"
      }
    )
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "idp-slo-in-response-to", saml_config: {singleLogoutService: "https://idp.example.com/slo"})
    auth.api.acs_endpoint(
      params: {providerId: "idp-slo-in-response-to"},
      body: {SAMLResponse: saml_xml_response(assertion_id: "assertion-slo-in-response-to")},
      as_response: true
    )

    status, _headers, response_body = auth.api.slo_endpoint(
      params: {providerId: "idp-slo-in-response-to"},
      body: {
        SAMLRequest: saml_logout_request(name_id: "name-id-in-response-to", session_index: "session-index-in-response-to", id: "_logout-request-id"),
        RelayState: "/signed-out"
      },
      as_response: true
    )
    encoded_response = response_body.join[/name="SAMLResponse" value="([^"]+)"/, 1]
    xml = Base64.decode64(encoded_response)

    assert_equal 200, status
    assert_includes xml, 'InResponseTo="_logout-request-id"'
  end

  def test_slo_rejects_unsigned_logout_request_when_signature_required
    auth = build_auth_with_json_saml_parser(saml_options: {enableSingleLogout: true, wantLogoutRequestSigned: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "signed-request-required", saml_config: {singleLogoutService: "https://idp.example.com/slo"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.slo_endpoint(
        params: {providerId: "signed-request-required"},
        body: {SAMLRequest: saml_logout_request(name_id: "name-id", session_index: "session-index")}
      )
    end

    assert_equal 400, error.status_code
    assert_equal "Invalid LogoutRequest", error.message
  end

  def test_slo_rejects_unsigned_logout_response_when_signature_required
    auth = build_auth_with_json_saml_parser(saml_options: {enableSingleLogout: true, wantLogoutResponseSigned: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "signed-response-required", saml_config: {singleLogoutService: "https://idp.example.com/slo"})
    _init_status, init_headers, _init_body = auth.api.initiate_slo(
      headers: {"cookie" => cookie},
      params: {providerId: "signed-response-required"},
      body: {callbackURL: "/after-logout"},
      as_response: true
    )
    request_id = saml_logout_request_id_from_url(init_headers.fetch("location"))

    error = assert_raises(BetterAuth::APIError) do
      auth.api.slo_endpoint(
        params: {providerId: "signed-response-required"},
        body: {SAMLResponse: saml_logout_response(in_response_to: request_id), RelayState: "/after-logout"}
      )
    end

    assert_equal 400, error.status_code
    assert_equal "Invalid LogoutResponse", error.message
  end

  def test_logout_response_consumes_pending_request_and_redirects_safely
    auth = build_auth_with_json_saml_parser(saml_options: {enableSingleLogout: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "logout-response-test", saml_config: {singleLogoutService: "https://idp.example.com/slo"})
    _init_status, init_headers, _init_body = auth.api.initiate_slo(
      headers: {"cookie" => cookie},
      params: {providerId: "logout-response-test"},
      body: {callbackURL: "/after-logout"},
      as_response: true
    )
    request_id = saml_logout_request_id_from_url(init_headers.fetch("location"))

    status, headers, _body = auth.api.slo_endpoint(
      params: {providerId: "logout-response-test"},
      body: {SAMLResponse: saml_logout_response(in_response_to: request_id), RelayState: "/after-logout"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/after-logout", headers.fetch("location")
    assert_nil auth.context.internal_adapter.find_verification_value("#{BetterAuth::Plugins::SSO_SAML_LOGOUT_REQUEST_KEY_PREFIX}#{request_id}")

    _init_status, malicious_init_headers, _init_body = auth.api.initiate_slo(
      headers: {"cookie" => sign_up_cookie(auth, email: "logout-response-second@example.com")},
      params: {providerId: "logout-response-test"},
      body: {callbackURL: "/after-logout"},
      as_response: true
    )
    malicious_request_id = saml_logout_request_id_from_url(malicious_init_headers.fetch("location"))
    malicious = auth.api.slo_endpoint(
      params: {providerId: "logout-response-test"},
      body: {SAMLResponse: saml_logout_response(in_response_to: malicious_request_id), RelayState: "https://evil.example.com/phishing"},
      as_response: true
    )
    assert_equal "http://localhost:3000/api/auth", malicious[1].fetch("location")
  end

  def test_logout_response_without_relay_state_redirects_to_base_url
    auth = build_auth_with_json_saml_parser(saml_options: {enableSingleLogout: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "logout-response-no-relay", saml_config: {singleLogoutService: "https://idp.example.com/slo"})
    _init_status, init_headers, _init_body = auth.api.initiate_slo(
      headers: {"cookie" => cookie},
      params: {providerId: "logout-response-no-relay"},
      body: {},
      as_response: true
    )
    request_id = saml_logout_request_id_from_url(init_headers.fetch("location"))

    status, headers, _body = auth.api.slo_endpoint(
      params: {providerId: "logout-response-no-relay"},
      body: {SAMLResponse: saml_logout_response(in_response_to: request_id)},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth", headers.fetch("location")
  end

  def test_logout_response_failure_does_not_consume_pending_request
    auth = build_auth_with_json_saml_parser(saml_options: {enableSingleLogout: true})
    cookie = sign_up_cookie(auth)
    register_saml_provider(auth, cookie, provider_id: "logout-failure-test", saml_config: {singleLogoutService: "https://idp.example.com/slo"})
    _init_status, init_headers, _init_body = auth.api.initiate_slo(
      headers: {"cookie" => cookie},
      params: {providerId: "logout-failure-test"},
      body: {callbackURL: "/after-logout"},
      as_response: true
    )
    request_id = saml_logout_request_id_from_url(init_headers.fetch("location"))

    error = assert_raises(BetterAuth::APIError) do
      auth.api.slo_endpoint(
        params: {providerId: "logout-failure-test"},
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
    assert auth.context.internal_adapter.find_verification_value("#{BetterAuth::Plugins::SSO_SAML_LOGOUT_REQUEST_KEY_PREFIX}#{request_id}")
  end

  private

  def build_auth(options = {})
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.sso(BetterAuth::SSO::SAML.sso_options.merge(options))]
    )
  end

  def build_auth_with_json_saml_parser(account: {}, saml_options: {}, saml_user_info: nil, plugin_options: {})
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      account: account,
      plugins: [
        BetterAuth::Plugins.sso(
          plugin_options.merge(
            saml: saml_options.merge(
              parse_response: ->(raw_response:, **_data) { saml_user_info || JSON.parse(Base64.decode64(raw_response), symbolize_names: true) }
            )
          )
        )
      ]
    )
  end

  def sign_up_cookie(auth, email: "owner@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: email.split("@").first},
      as_response: true
    )
    headers.fetch("set-cookie").to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def rack_json_request(auth, path, method: "POST", origin: "http://localhost:3000", cookie: nil, body: {})
    input = (method == "GET") ? "" : JSON.generate(body)
    headers = {
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => origin
    }
    headers["HTTP_COOKIE"] = cookie if cookie

    auth.handler.call(
      Rack::MockRequest.env_for(
        "http://localhost:3000/api/auth#{path}",
        headers.merge(method: method, input: input)
      )
    )
  end

  def register_saml_provider(auth, cookie, provider_id:, saml_config: {})
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: provider_id,
        issuer: "https://idp.example.com",
        domain: "#{provider_id}.example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          cert: IDP_CERT,
          callbackUrl: "/dashboard",
          audience: "better-auth-ruby",
          wantAssertionsSigned: false
        }.merge(saml_config)
      }
    )
  end

  def saml_json_response(id:, email:, name: "SAML User")
    Base64.strict_encode64(JSON.generate({id: id, email: email, name: name}))
  end

  def saml_xml_response(assertion_id:, in_response_to: nil)
    attribute = in_response_to ? " InResponseTo=\"#{in_response_to}\"" : ""
    Base64.strict_encode64("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"#{attribute}><saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"#{assertion_id}\" /></samlp:Response>")
  end

  def saml_request_id_from_url(url)
    encoded = Rack::Utils.parse_query(URI.parse(url).query).fetch("SAMLRequest")
    compressed = Base64.decode64(encoded)
    xml = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(compressed)
    xml[/\bID=['"]([^'"]+)['"]/, 1]
  end

  def saml_logout_request(name_id:, session_index:, id: nil)
    id_attribute = id ? " ID=\"#{id}\"" : ""
    Base64.strict_encode64("<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"#{id_attribute}><saml:NameID>#{name_id}</saml:NameID><samlp:SessionIndex>#{session_index}</samlp:SessionIndex></samlp:LogoutRequest>")
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

  def default_saml_provider(provider_id:, domain:, saml_config: {})
    {
      domain: domain,
      providerId: provider_id,
      samlConfig: {
        issuer: "http://#{domain}",
        entryPoint: "http://#{domain}/api/sso/saml2/idp/redirect",
        cert: IDP_CERT,
        callbackUrl: "http://#{domain}/dashboard",
        wantAssertionsSigned: false,
        signatureAlgorithm: "sha256",
        digestAlgorithm: "sha256",
        identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      }.merge(saml_config)
    }
  end

  def sign_in_params(auth, body = {})
    result = auth.api.sign_in_sso(body: body)
    uri = URI.parse(result.fetch(:url))
    {
      url: result.fetch(:url),
      url_without_query: "#{uri.scheme}://#{uri.host}:#{uri.port}#{uri.path}",
      params: Rack::Utils.parse_query(uri.query)
    }
  end
end

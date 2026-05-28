# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthSSOSAMLAlgorithmsTest < Minitest::Test
  Algorithms = BetterAuth::SSO::SAML::Algorithms

  ENCRYPTED_ASSERTION_XML = <<~XML
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <xenc:EncryptedKey>
              <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
            </xenc:EncryptedKey>
          </ds:KeyInfo>
        </xenc:EncryptedData>
      </saml:EncryptedAssertion>
    </samlp:Response>
  XML

  DEPRECATED_ENCRYPTION_XML = <<~XML
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <xenc:EncryptedKey>
              <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
            </xenc:EncryptedKey>
          </ds:KeyInfo>
        </xenc:EncryptedData>
      </saml:EncryptedAssertion>
    </samlp:Response>
  XML

  PLAIN_ASSERTION_XML = <<~XML
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Subject>test</saml:Subject>
      </saml:Assertion>
    </samlp:Response>
  XML

  def test_validate_response_accepts_secure_signature_algorithms
    assert Algorithms.validate_response(sig_alg: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256), saml_content: PLAIN_ASSERTION_XML)
  end

  def test_validate_response_warn_behavior_allows_deprecated_signature_by_default
    assert Algorithms.validate_response(sig_alg: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA1), saml_content: PLAIN_ASSERTION_XML)
  end

  def test_validate_response_rejects_deprecated_signature_when_configured
    error = assert_algorithm_error do
      Algorithms.validate_response(
        sig_alg: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA1),
        saml_content: PLAIN_ASSERTION_XML,
        onDeprecated: "reject"
      )
    end

    assert_match(/deprecated/i, error.message)
  end

  def test_validate_response_allows_deprecated_signature_when_configured
    assert Algorithms.validate_response(
      sig_alg: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA1),
      saml_content: PLAIN_ASSERTION_XML,
      onDeprecated: "allow"
    )
  end

  def test_validate_response_enforces_custom_signature_allow_list
    error = assert_algorithm_error do
      Algorithms.validate_response(
        sig_alg: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256),
        saml_content: PLAIN_ASSERTION_XML,
        allowedSignatureAlgorithms: [Algorithms::SignatureAlgorithm.fetch(:RSA_SHA512)]
      )
    end

    assert_match(/not in allow-list/i, error.message)
  end

  def test_validate_response_allows_nil_signature_algorithm
    assert Algorithms.validate_response(sig_alg: nil, saml_content: PLAIN_ASSERTION_XML)
  end

  def test_validate_response_rejects_unknown_signature_algorithms
    error = assert_algorithm_error do
      Algorithms.validate_response(sig_alg: "http://example.com/unknown-algo", saml_content: PLAIN_ASSERTION_XML)
    end

    assert_match(/not recognized/i, error.message)
  end

  def test_validate_response_accepts_secure_encryption_algorithms
    assert Algorithms.validate_response(sig_alg: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256), saml_content: ENCRYPTED_ASSERTION_XML)
  end

  def test_validate_response_warn_behavior_allows_deprecated_encryption_by_default
    assert Algorithms.validate_response(sig_alg: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256), saml_content: DEPRECATED_ENCRYPTION_XML)
  end

  def test_validate_response_rejects_deprecated_encryption_when_configured
    error = assert_algorithm_error do
      Algorithms.validate_response(
        sig_alg: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256),
        saml_content: DEPRECATED_ENCRYPTION_XML,
        onDeprecated: "reject"
      )
    end

    assert_match(/deprecated/i, error.message)
  end

  def test_validate_response_skips_encryption_validation_for_plain_assertions
    assert Algorithms.validate_response(sig_alg: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256), saml_content: PLAIN_ASSERTION_XML)
  end

  def test_validate_response_handles_malformed_xml_gracefully
    assert Algorithms.validate_response(sig_alg: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256), saml_content: "not valid xml")
  end

  def test_exports_signature_algorithm_constants
    assert_equal "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256)
    assert_equal "http://www.w3.org/2000/09/xmldsig#rsa-sha1", Algorithms::SignatureAlgorithm.fetch(:RSA_SHA1)
  end

  def test_exports_encryption_algorithm_constants
    assert_equal "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", Algorithms::KEY_ENCRYPTION_ALGORITHM.fetch(:RSA_OAEP)
    assert_equal "http://www.w3.org/2009/xmlenc11#aes256-gcm", Algorithms::DATA_ENCRYPTION_ALGORITHM.fetch(:AES_256_GCM)
  end

  def test_validate_config_accepts_secure_signature_algorithms
    assert Algorithms.validate_config(signatureAlgorithm: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256))
  end

  def test_validate_config_warn_behavior_allows_deprecated_signature_by_default
    assert Algorithms.validate_config(signatureAlgorithm: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA1))
  end

  def test_validate_config_rejects_deprecated_signature_when_configured
    error = assert_algorithm_error do
      Algorithms.validate_config({signatureAlgorithm: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA1)}, onDeprecated: "reject")
    end

    assert_match(/deprecated/i, error.message)
  end

  def test_validate_config_allows_deprecated_signature_when_configured
    assert Algorithms.validate_config({signatureAlgorithm: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA1)}, onDeprecated: "allow")
  end

  def test_validate_config_enforces_custom_signature_allow_list
    error = assert_algorithm_error do
      Algorithms.validate_config(
        {signatureAlgorithm: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256)},
        allowedSignatureAlgorithms: [Algorithms::SignatureAlgorithm.fetch(:RSA_SHA512)]
      )
    end

    assert_match(/not in allow-list/i, error.message)
  end

  def test_validate_config_rejects_unknown_signature_algorithms
    error = assert_algorithm_error do
      Algorithms.validate_config(signatureAlgorithm: "http://example.com/unknown-algo")
    end

    assert_match(/not recognized/i, error.message)
  end

  def test_validate_config_allows_missing_signature_algorithm
    assert Algorithms.validate_config({})
  end

  def test_validate_config_accepts_short_form_signature_algorithm_names
    assert Algorithms.validate_config(signatureAlgorithm: "rsa-sha256")
  end

  def test_validate_config_accepts_digest_style_short_form_for_signature
    assert Algorithms.validate_config(signatureAlgorithm: "sha256")
  end

  def test_validate_config_rejects_typos_in_short_form_signature_names
    error = assert_algorithm_error do
      Algorithms.validate_config(signatureAlgorithm: "rsa-sha257")
    end

    assert_match(/not recognized/i, error.message)
  end

  def test_validate_config_warn_behavior_allows_deprecated_short_form_signature_by_default
    assert Algorithms.validate_config(signatureAlgorithm: "rsa-sha1")
  end

  def test_validate_config_supports_short_form_names_in_signature_allow_list
    assert Algorithms.validate_config(
      {signatureAlgorithm: "rsa-sha256"},
      allowedSignatureAlgorithms: ["rsa-sha256", "rsa-sha512"]
    )
  end

  def test_validate_config_accepts_secure_digest_algorithms
    assert Algorithms.validate_config(digestAlgorithm: Algorithms::DigestAlgorithm.fetch(:SHA256))
  end

  def test_validate_config_warn_behavior_allows_deprecated_digest_by_default
    assert Algorithms.validate_config(digestAlgorithm: Algorithms::DigestAlgorithm.fetch(:SHA1))
  end

  def test_validate_config_rejects_deprecated_digest_when_configured
    error = assert_algorithm_error do
      Algorithms.validate_config({digestAlgorithm: Algorithms::DigestAlgorithm.fetch(:SHA1)}, onDeprecated: "reject")
    end

    assert_match(/deprecated/i, error.message)
  end

  def test_validate_config_enforces_custom_digest_allow_list
    error = assert_algorithm_error do
      Algorithms.validate_config(
        {digestAlgorithm: Algorithms::DigestAlgorithm.fetch(:SHA256)},
        allowedDigestAlgorithms: [Algorithms::DigestAlgorithm.fetch(:SHA512)]
      )
    end

    assert_match(/not in allow-list/i, error.message)
  end

  def test_validate_config_rejects_unknown_digest_algorithms
    error = assert_algorithm_error do
      Algorithms.validate_config(digestAlgorithm: "http://example.com/unknown-digest")
    end

    assert_match(/not recognized/i, error.message)
  end

  def test_validate_config_accepts_short_form_digest_algorithm_names
    assert Algorithms.validate_config(digestAlgorithm: "sha256")
  end

  def test_validate_config_rejects_typos_in_short_form_digest_names
    error = assert_algorithm_error do
      Algorithms.validate_config(digestAlgorithm: "sha257")
    end

    assert_match(/not recognized/i, error.message)
  end

  def test_validate_config_warn_behavior_allows_deprecated_short_form_digest_by_default
    assert Algorithms.validate_config(digestAlgorithm: "sha1")
  end

  def test_validate_config_supports_short_form_names_in_digest_allow_list
    assert Algorithms.validate_config(
      {digestAlgorithm: "sha256"},
      allowedDigestAlgorithms: ["sha256", "sha512"]
    )
  end

  def test_validate_config_validates_signature_and_digest_together
    assert Algorithms.validate_config(
      signatureAlgorithm: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256),
      digestAlgorithm: Algorithms::DigestAlgorithm.fetch(:SHA256)
    )
  end

  def test_validate_config_rejects_deprecated_signature_even_when_digest_is_secure
    error = assert_algorithm_error do
      Algorithms.validate_config(
        {
          signatureAlgorithm: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA1),
          digestAlgorithm: Algorithms::DigestAlgorithm.fetch(:SHA256)
        },
        onDeprecated: "reject"
      )
    end

    assert_match(/deprecated/i, error.message)
  end

  def test_validate_config_rejects_deprecated_digest_even_when_signature_is_secure
    error = assert_algorithm_error do
      Algorithms.validate_config(
        {
          signatureAlgorithm: Algorithms::SignatureAlgorithm.fetch(:RSA_SHA256),
          digestAlgorithm: Algorithms::DigestAlgorithm.fetch(:SHA1)
        },
        onDeprecated: "reject"
      )
    end

    assert_match(/deprecated/i, error.message)
  end

  private

  def assert_algorithm_error(&block)
    assert_raises(BetterAuth::APIError, &block)
  end
end

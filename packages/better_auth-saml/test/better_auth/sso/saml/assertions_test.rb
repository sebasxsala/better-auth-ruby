# frozen_string_literal: true

require "base64"
require_relative "../../../test_helper"

class BetterAuthSSOSAMLAssertionsTest < Minitest::Test
  def test_accepts_response_with_single_assertion
    assert_valid_single_assertion <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Assertion ID="123">
          <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
        </saml:Assertion>
      </samlp:Response>
    XML
  end

  def test_accepts_response_with_single_encrypted_assertion
    assert_valid_single_assertion <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:EncryptedAssertion>
          <xenc:EncryptedData>...</xenc:EncryptedData>
        </saml:EncryptedAssertion>
      </samlp:Response>
    XML
  end

  def test_accepts_base64_with_embedded_whitespace_from_wrapping_idps
    encoded = encode <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Assertion ID="123">
          <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
        </saml:Assertion>
      </samlp:Response>
    XML

    wrapped_lf = encoded.gsub(/.{76}/, "\\0\n")
    wrapped_crlf = encoded.gsub(/.{76}/, "\\0\r\n")
    wrapped_spaces_and_tabs = encoded.gsub(/.{20}/, "\\0 \t ")

    assert_includes wrapped_lf, "\n"
    assert_includes wrapped_crlf, "\r\n"
    assert_includes wrapped_spaces_and_tabs, " \t "

    assert BetterAuth::SSO::SAML::Assertions.validate_single_assertion!(wrapped_lf)
    assert BetterAuth::SSO::SAML::Assertions.validate_single_assertion!(wrapped_crlf)
    assert BetterAuth::SSO::SAML::Assertions.validate_single_assertion!(wrapped_spaces_and_tabs)
  end

  def test_rejects_response_with_no_assertions
    error = assert_invalid_single_assertion <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        </samlp:Status>
      </samlp:Response>
    XML

    assert_equal "SAML response contains no assertions", error.message
  end

  def test_rejects_response_with_multiple_unencrypted_assertions
    error = assert_invalid_single_assertion <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Assertion ID="assertion1">
          <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
        </saml:Assertion>
        <saml:Assertion ID="assertion2">
          <saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
        </saml:Assertion>
      </samlp:Response>
    XML

    assert_equal "SAML response contains 2 assertions, expected exactly 1", error.message
  end

  def test_rejects_response_with_multiple_encrypted_assertions
    error = assert_invalid_single_assertion <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:EncryptedAssertion>
          <xenc:EncryptedData>...</xenc:EncryptedData>
        </saml:EncryptedAssertion>
        <saml:EncryptedAssertion>
          <xenc:EncryptedData>...</xenc:EncryptedData>
        </saml:EncryptedAssertion>
      </samlp:Response>
    XML

    assert_equal "SAML response contains 2 assertions, expected exactly 1", error.message
  end

  def test_rejects_response_with_mixed_assertion_types
    error = assert_invalid_single_assertion <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Assertion ID="plain-assertion">
          <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
        </saml:Assertion>
        <saml:EncryptedAssertion>
          <xenc:EncryptedData>...</xenc:EncryptedData>
        </saml:EncryptedAssertion>
      </samlp:Response>
    XML

    assert_equal "SAML response contains 2 assertions, expected exactly 1", error.message
  end

  def test_rejects_assertion_injected_in_extensions
    error = assert_invalid_single_assertion <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <samlp:Extensions>
          <saml:Assertion ID="injected-assertion">
            <saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
          </saml:Assertion>
        </samlp:Extensions>
        <saml:Assertion ID="legitimate-assertion">
          <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
        </saml:Assertion>
      </samlp:Response>
    XML

    assert_equal "SAML response contains 2 assertions, expected exactly 1", error.message
  end

  def test_rejects_assertion_wrapped_in_arbitrary_element
    error = assert_invalid_single_assertion <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <Wrapper>
          <saml:Assertion ID="wrapped-assertion">
            <saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
          </saml:Assertion>
        </Wrapper>
        <saml:Assertion ID="legitimate-assertion">
          <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
        </saml:Assertion>
      </samlp:Response>
    XML

    assert_equal "SAML response contains 2 assertions, expected exactly 1", error.message
  end

  def test_rejects_deeply_nested_injected_assertion
    error = assert_invalid_single_assertion <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <Level1><Level2><Level3>
          <saml:Assertion ID="deep-injected">
            <saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
          </saml:Assertion>
        </Level3></Level2></Level1>
        <saml:Assertion ID="legitimate-assertion">
          <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
        </saml:Assertion>
      </samlp:Response>
    XML

    assert_equal "SAML response contains 2 assertions, expected exactly 1", error.message
  end

  def test_handles_assertion_without_namespace_prefix
    assert_valid_single_assertion <<~XML
      <Response>
        <Assertion ID="123">
          <Subject><NameID>user@example.com</NameID></Subject>
        </Assertion>
      </Response>
    XML
  end

  def test_handles_assertion_with_saml2_prefix
    assert_valid_single_assertion <<~XML
      <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml2:Assertion ID="123">
          <saml2:Subject><saml2:NameID>user@example.com</saml2:NameID></saml2:Subject>
        </saml2:Assertion>
      </saml2p:Response>
    XML
  end

  def test_handles_assertion_with_custom_prefix
    assert_valid_single_assertion <<~XML
      <custom:Response xmlns:custom="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:myprefix="urn:oasis:names:tc:SAML:2.0:assertion">
        <myprefix:Assertion ID="123">
          <myprefix:Subject><myprefix:NameID>user@example.com</myprefix:NameID></myprefix:Subject>
        </myprefix:Assertion>
      </custom:Response>
    XML
  end

  def test_count_returns_separate_assertion_and_encrypted_assertion_counts
    counts = BetterAuth::SSO::SAML::Assertions.count <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Assertion ID="plain">
          <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
        </saml:Assertion>
        <saml:EncryptedAssertion>
          <xenc:EncryptedData>...</xenc:EncryptedData>
        </saml:EncryptedAssertion>
      </samlp:Response>
    XML

    assert_equal 1, counts.fetch(:assertions)
    assert_equal 1, counts.fetch(:encrypted_assertions)
    assert_equal 2, counts.fetch(:total)
  end

  def test_count_does_not_count_assertion_consumer_service
    counts = BetterAuth::SSO::SAML::Assertions.count <<~XML
      <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
        <md:SPSSODescriptor>
          <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://example.com/acs"/>
        </md:SPSSODescriptor>
      </md:EntityDescriptor>
    XML

    assert_equal 0, counts.fetch(:assertions)
    assert_equal 0, counts.fetch(:total)
  end

  def test_rejects_invalid_base64_input
    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::SSO::SAML::Assertions.validate_single_assertion!("not-valid-base64!!!")
    end

    assert_equal "Invalid base64-encoded SAML response", error.message
  end

  def test_rejects_non_xml_content
    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::SSO::SAML::Assertions.validate_single_assertion!(encode("this is not xml at all"))
    end

    assert_equal "Invalid base64-encoded SAML response", error.message
  end

  private

  def encode(xml)
    Base64.strict_encode64(xml)
  end

  def assert_valid_single_assertion(xml)
    assert BetterAuth::SSO::SAML::Assertions.validate_single_assertion!(encode(xml))
  end

  def assert_invalid_single_assertion(xml)
    assert_raises(BetterAuth::APIError) do
      BetterAuth::SSO::SAML::Assertions.validate_single_assertion!(encode(xml))
    end
  end
end

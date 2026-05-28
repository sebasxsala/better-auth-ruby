# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthSAMLStructureContractTest < Minitest::Test
  Constants = BetterAuth::SSO::Constants

  def test_constants_mirror_plugin_storage_and_ttl_contract
    assert_equal "saml-authn-request:", Constants::AUTHN_REQUEST_KEY_PREFIX
    assert_equal "saml-used-assertion:", Constants::USED_ASSERTION_KEY_PREFIX
    assert_equal "saml-session:", Constants::SAML_SESSION_KEY_PREFIX
    assert_equal "saml-session-by-id:", Constants::SAML_SESSION_BY_ID_PREFIX
    assert_equal "saml-logout-request:", Constants::LOGOUT_REQUEST_KEY_PREFIX
    assert_equal 5 * 60 * 1000, Constants::DEFAULT_AUTHN_REQUEST_TTL_MS
    assert_equal 15 * 60 * 1000, Constants::DEFAULT_ASSERTION_TTL_MS
    assert_equal 5 * 60 * 1000, Constants::DEFAULT_LOGOUT_REQUEST_TTL_MS
    assert_equal 5 * 60 * 1000, Constants::DEFAULT_CLOCK_SKEW_MS
    assert_equal 256 * 1024, Constants::DEFAULT_MAX_SAML_RESPONSE_SIZE
    assert_equal 100 * 1024, Constants::DEFAULT_MAX_SAML_METADATA_SIZE
    assert_equal "urn:oasis:names:tc:SAML:2.0:status:Success", Constants::SAML_STATUS_SUCCESS
  end

  def test_saml_index_reexports_algorithm_and_assertion_helpers
    assert_respond_to BetterAuth::SSO::SAML, :validate_config_algorithms
    assert_respond_to BetterAuth::SSO::SAML, :validate_saml_algorithms
    assert_respond_to BetterAuth::SSO::SAML, :validate_single_assertion

    assert_equal true, BetterAuth::SSO::SAML.validate_config_algorithms({})
  end
end

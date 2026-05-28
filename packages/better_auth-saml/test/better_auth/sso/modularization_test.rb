# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthSAMLModularizationTest < Minitest::Test
  SAML_DIR = File.expand_path("../../../lib/better_auth/sso", __dir__)

  def test_saml_helpers_live_in_the_sso_saml_modules
    assert_saml_source BetterAuth::Plugins.method(:sso_parse_saml_response), "SAML parsing"
    assert_saml_source BetterAuth::Plugins.method(:sso_validate_saml_timestamp!), "SAML timestamp validation"
    assert_saml_source BetterAuth::Plugins.method(:sso_validate_saml_algorithms!), "SAML algorithm validation"
  end

  private

  def assert_saml_source(method, label)
    source_path = File.expand_path(method.source_location.fetch(0))

    assert source_path.start_with?(SAML_DIR), "#{label} should be defined under #{SAML_DIR}, got #{source_path}"
  end
end

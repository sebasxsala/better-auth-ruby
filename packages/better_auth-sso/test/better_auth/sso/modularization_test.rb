# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthSSOModularizationTest < Minitest::Test
  PLUGIN_FILE = File.expand_path("../../../lib/better_auth/plugins/sso.rb", __dir__)
  SSO_DIR = File.expand_path("../../../lib/better_auth/sso", __dir__)

  def test_core_plugin_entrypoint_is_kept_out_of_the_monolithic_plugin_file
    assert_sso_source BetterAuth::Plugins.method(:sso), "plugin factory"
    assert_sso_source BetterAuth::Plugins.method(:sso_hooks), "plugin hooks"
    assert_sso_source BetterAuth::Plugins.method(:sso_schema), "plugin schema"
  end

  def test_oidc_helpers_live_in_the_oidc_package
    assert_oidc_source BetterAuth::Plugins.method(:sso_discover_oidc_config), "OIDC discovery"
    assert_oidc_source BetterAuth::Plugins.method(:sso_oidc_authorization_url), "OIDC authorization URL"
    assert_oidc_source BetterAuth::Plugins.method(:sso_validate_oidc_id_token), "OIDC ID token validation"
  end

  def test_saml_helpers_live_in_the_saml_package
    assert_saml_source BetterAuth::Plugins.method(:sso_parse_saml_response), "SAML parsing"
    assert_saml_source BetterAuth::Plugins.method(:sso_validate_saml_timestamp!), "SAML timestamp validation"
    assert_saml_source BetterAuth::Plugins.method(:sso_validate_saml_algorithms!), "SAML algorithm validation"
  end

  private

  def assert_sso_source(method, label)
    source_path = File.expand_path(method.source_location.fetch(0))

    refute_equal PLUGIN_FILE, source_path, "#{label} is still defined in the monolithic plugin file"
    assert source_path.start_with?(SSO_DIR), "#{label} should be defined under #{SSO_DIR}, got #{source_path}"
  end

  def assert_oidc_source(method, label)
    source_path = File.expand_path(method.source_location.fetch(0))
    oidc_dir = File.expand_path("../../../../better_auth-oidc/lib/better_auth/sso", __dir__)

    assert source_path.start_with?(oidc_dir), "#{label} should be defined in better_auth-oidc, got #{source_path}"
  end

  def assert_saml_source(method, label)
    source_path = File.expand_path(method.source_location.fetch(0))
    saml_dir = File.expand_path("../../../../better_auth-saml/lib/better_auth/sso", __dir__)

    assert source_path.start_with?(saml_dir), "#{label} should be defined in better_auth-saml, got #{source_path}"
  end
end

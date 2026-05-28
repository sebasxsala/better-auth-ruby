# frozen_string_literal: true

require_relative "../../test_helper"

class ExternalPluginShimTest < Minitest::Test
  def test_sso_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:sso, "better_auth-sso", "better_auth/sso")
  end

  def test_scim_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:scim, "better_auth-scim", "better_auth/scim")
  end

  def test_passkey_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:passkey, "better_auth-passkey", "better_auth/passkey")
  end

  def test_oauth_provider_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:oauth_provider, "better_auth-oauth-provider", "better_auth/oauth_provider")
  end

  def test_api_key_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:api_key, "better_auth-api-key", "better_auth/api_key")
  end

  private

  def assert_external_plugin_shim(method_name, gem_name, require_path)
    loader_called = false
    ensure_loader = lambda do |**|
      loader_called = true
      raise LoadError,
        "BetterAuth requires the #{gem_name} gem. Add it to your Gemfile and require \"#{require_path}\"."
    end

    error = BetterAuth::Plugins.stub(:ensure_external_plugin_loaded!, ensure_loader) do
      assert_raises(LoadError) do
        BetterAuth::Plugins.public_send(method_name)
      end
    end

    assert loader_called, "expected #{method_name} lazy loader to run"
    assert_includes error.message, gem_name
    assert_includes error.message, require_path
  end
end

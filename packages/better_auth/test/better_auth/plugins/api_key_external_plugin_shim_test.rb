# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "external_plugin_shim_test"

class APIKeyExternalPluginShimTest < ExternalPluginShimTest
  def test_api_key_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:api_key, "better_auth-api-key", "better_auth/api_key")
  end
end

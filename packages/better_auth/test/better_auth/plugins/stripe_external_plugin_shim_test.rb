# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "external_plugin_shim_test"

class StripeExternalPluginShimTest < ExternalPluginShimTest
  def test_stripe_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:stripe, "better_auth-stripe", "better_auth/stripe")
  end
end

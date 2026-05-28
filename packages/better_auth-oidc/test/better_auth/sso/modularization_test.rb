# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthOIDCModularizationTest < Minitest::Test
  OIDC_DIR = File.expand_path("../../../lib/better_auth/sso", __dir__)

  def test_oidc_helpers_live_in_the_sso_oidc_modules
    assert_oidc_source BetterAuth::Plugins.method(:sso_discover_oidc_config), "OIDC discovery"
    assert_oidc_source BetterAuth::Plugins.method(:sso_oidc_authorization_url), "OIDC authorization URL"
    assert_oidc_source BetterAuth::Plugins.method(:sso_validate_oidc_id_token), "OIDC ID token validation"
  end

  private

  def assert_oidc_source(method, label)
    source_path = File.expand_path(method.source_location.fetch(0))

    assert source_path.start_with?(OIDC_DIR), "#{label} should be defined under #{OIDC_DIR}, got #{source_path}"
  end
end

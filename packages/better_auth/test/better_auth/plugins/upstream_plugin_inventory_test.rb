# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPluginsUpstreamInventoryTest < Minitest::Test
  def test_every_top_level_plugin_file_has_an_explicit_test_owner
    plugin_root = File.expand_path("../../../lib/better_auth/plugins", __dir__)
    test_root = File.expand_path(".", __dir__)
    top_level_plugins = Dir[File.join(plugin_root, "*.rb")].map { |path| File.basename(path, ".rb") }.sort
    direct_tests = Dir[File.join(test_root, "*_test.rb")].map { |path| File.basename(path, "_test.rb") }
    submodule_tests = Dir[File.join(test_root, "*", "*_test.rb")].map { |path| File.basename(File.dirname(path)) }
    external_shim_tested = %w[api_key oauth_provider passkey scim sso stripe]
    protocol_helper_tested = %w[oauth_protocol]

    coverage = top_level_plugins.to_h do |plugin|
      category = if direct_tests.include?(plugin)
        :direct_test
      elsif submodule_tests.include?(plugin)
        :submodule_test
      elsif external_shim_tested.include?(plugin)
        :external_shim_test
      elsif protocol_helper_tested.include?(plugin)
        :protocol_helper_test
      end

      [plugin, category]
    end

    assert_empty coverage.select { |_plugin, category| category.nil? }
    assert_equal :submodule_test, coverage.fetch("mcp")
    assert_equal :protocol_helper_test, coverage.fetch("oauth_protocol")
    external_shim_tested.each do |plugin|
      assert_equal :external_shim_test, coverage.fetch(plugin)
    end
  end

  def test_upstream_hook_only_plugins_do_not_register_http_endpoints
    plugins = [
      BetterAuth::Plugins.additional_fields(user: {plan: {type: "string", required: false}}),
      BetterAuth::Plugins.bearer,
      BetterAuth::Plugins.captcha(provider: "cloudflare-turnstile", secret_key: "captcha-secret"),
      BetterAuth::Plugins.have_i_been_pwned,
      BetterAuth::Plugins.last_login_method
    ]

    plugins.each do |plugin|
      assert_empty plugin.endpoints, "#{plugin.id} should not register its own HTTP endpoints"
    end
  end

  def test_access_matches_upstream_helper_surface_not_plugin_endpoint_surface
    access_control = BetterAuth::Plugins.create_access_control(project: ["read"])

    assert_equal({success: true}, access_control.new_role(project: ["read"]).authorize(project: ["read"]))
    refute_respond_to access_control, :endpoints
  end
end

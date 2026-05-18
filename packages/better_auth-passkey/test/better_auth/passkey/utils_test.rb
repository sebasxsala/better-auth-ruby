# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPasskeyUtilsTest < Minitest::Test
  def test_rp_id_prefers_explicit_config
    assert_equal "explicit.example", BetterAuth::Passkey::Utils.rp_id({rp_id: "explicit.example"}, ctx("https://ignored.example"))
  end

  def test_rp_id_uses_base_url_hostname_without_port
    assert_equal "example.com", BetterAuth::Passkey::Utils.rp_id({}, ctx("https://example.com:8443/api/auth"))
  end

  def test_rp_id_defaults_to_localhost_without_base_url
    assert_equal "localhost", BetterAuth::Passkey::Utils.rp_id({}, ctx(nil))
  end

  def test_rp_id_falls_back_to_localhost_for_invalid_ruby_base_url
    assert_equal "localhost", BetterAuth::Passkey::Utils.rp_id({}, ctx("not a url"))
  end

  def test_rp_id_raises_for_nonblank_invalid_base_url_when_not_explicitly_configured
    assert_raises(BetterAuth::APIError) do
      BetterAuth::Passkey::Utils.rp_id({}, ctx("not a url", strict: true))
    end
  end

  def test_allowed_origins_do_not_fall_back_to_request_origin
    context = ctx("https://app.example.com/api/auth")

    origins = BetterAuth::Passkey::Utils.allowed_origins({}, context, origin: "https://evil.example.com")

    assert_equal ["https://app.example.com"], origins
  end

  def test_allowed_origins_preserve_explicit_origin_array
    origins = BetterAuth::Passkey::Utils.allowed_origins(
      {origin: ["https://app.example.com", "https://admin.example.com"]},
      ctx("https://ignored.example.com"),
      origin: "https://evil.example.com"
    )

    assert_equal ["https://app.example.com", "https://admin.example.com"], origins
  end

  def test_legacy_private_plugin_rp_id_delegates_to_utils
    assert_equal "example.com", BetterAuth::Plugins.send(:passkey_rp_id, {}, ctx("https://example.com:8443/api/auth"))
  end

  private

  def ctx(base_url, strict: false)
    options = Struct.new(:base_url).new(base_url)
    context = Struct.new(:options, :app_name, :base_url, :passkey_strict_base_url?).new(options, "Test App", base_url, strict)
    Struct.new(:context).new(context)
  end
end

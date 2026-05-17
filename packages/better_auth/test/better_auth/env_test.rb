# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthEnvTest < Minitest::Test
  def test_get_prefers_open_auth_alias_for_better_auth_env_names
    with_env(
      "OPEN_AUTH_SECRET" => "open-secret",
      "BETTER_AUTH_SECRET" => "better-secret"
    ) do
      assert_equal "open-secret", BetterAuth::Env.get("BETTER_AUTH_SECRET")
    end
  end

  def test_get_supports_prefixed_public_open_auth_aliases
    with_env(
      "NEXT_PUBLIC_OPEN_AUTH_URL" => "http://open.example",
      "NEXT_PUBLIC_BETTER_AUTH_URL" => "http://better.example"
    ) do
      assert_equal "http://open.example", BetterAuth::Env.get("NEXT_PUBLIC_BETTER_AUTH_URL")
    end
  end

  def test_get_falls_back_to_better_auth_when_open_auth_alias_is_missing
    with_env(
      "OPEN_AUTH_SECRET" => nil,
      "BETTER_AUTH_SECRET" => "better-secret"
    ) do
      assert_equal "better-secret", BetterAuth::Env.get("BETTER_AUTH_SECRET")
    end
  end

  private

  def with_env(values)
    previous = values.keys.to_h { |key| [key, ENV[key]] }
    values.each do |key, value|
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
    yield
  ensure
    previous.each do |key, value|
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
  end
end

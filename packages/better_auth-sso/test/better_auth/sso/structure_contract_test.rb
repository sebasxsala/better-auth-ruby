# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthSSOStructureContractTest < Minitest::Test
  Types = BetterAuth::SSO::Types

  def test_type_helpers_accept_upstream_strings_and_ruby_symbols
    assert_equal %w[oidc saml], Types::PROVIDER_TYPES
    assert Types::PROVIDER_TYPES.frozen?
    assert Types.provider_type?("oidc")
    assert Types.provider_type?(:saml)
    refute Types.provider_type?("oauth")
    refute Types.provider_type?(nil)

    assert_equal %w[client_secret_post client_secret_basic], Types::OIDC_TOKEN_ENDPOINT_AUTH_METHODS
    assert Types::OIDC_TOKEN_ENDPOINT_AUTH_METHODS.frozen?
    assert Types.oidc_token_endpoint_auth_method?("client_secret_basic")
    assert Types.oidc_token_endpoint_auth_method?(:client_secret_post)
    refute Types.oidc_token_endpoint_auth_method?("private_key_jwt")
    refute Types.oidc_token_endpoint_auth_method?(nil)
  end

  def test_linking_normalized_profile_accepts_upstream_and_ruby_keys
    upstream_profile = BetterAuth::SSO::Linking.normalized_profile(
      "providerType" => "saml",
      "providerId" => "saml-provider",
      "accountId" => "account-1",
      "email" => "ALICE@EXAMPLE.COM",
      "emailVerified" => true,
      "rawAttributes" => {"department" => "engineering"}
    )

    assert_equal "saml", upstream_profile.fetch(:provider_type)
    assert_equal "saml-provider", upstream_profile.fetch(:provider_id)
    assert_equal "account-1", upstream_profile.fetch(:account_id)
    assert_equal "alice@example.com", upstream_profile.fetch(:email)
    assert_equal true, upstream_profile.fetch(:email_verified)
    assert_equal({"department" => "engineering"}, upstream_profile.fetch(:raw_attributes))

    ruby_profile = BetterAuth::SSO::Linking.normalized_profile(
      provider_type: :oidc,
      provider_id: "oidc-provider",
      account_id: "account-2",
      email: "bob@example.com",
      email_verified: false
    )

    assert_equal "oidc", ruby_profile.fetch(:provider_type)
    assert_equal false, ruby_profile.fetch(:email_verified)
  end

  def test_linking_normalized_profile_rejects_missing_required_fields
    error = assert_raises(ArgumentError) do
      BetterAuth::SSO::Linking.normalized_profile(providerType: "saml", email: "alice@example.com")
    end

    assert_match(/providerId/, error.message)
  end
end

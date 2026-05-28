# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthSSOSAMLStateTest < Minitest::Test
  ContextWrapper = Struct.new(:body, :context) do
    def set_signed_cookie(*args)
      context.cookies << args
    end
  end
  Context = Struct.new(:secret, :internal_adapter, :cookies)

  def test_generate_relay_state_requires_callback_url
    ctx = build_context(body: {})

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::SSO::SAMLState.generate_relay_state(ctx, nil, {})
    end

    assert_equal 400, error.status_code
    assert_instance_of BetterAuth::APIError, error
    assert_match(/callbackURL is required/, error.message)
  end

  def test_generate_relay_state_stores_upstream_state_shape_with_link_and_optional_additional_data
    ctx = build_context(
      body: {
        callbackURL: "/dashboard",
        errorCallbackURL: "/error",
        newUserCallbackURL: "/welcome",
        requestSignUp: true
      }
    )

    relay_state = BetterAuth::SSO::SAMLState.generate_relay_state(
      ctx,
      {email: "alice@example.com", userId: "user-1"},
      {providerId: "saml-provider"}
    )
    stored = ctx.context.internal_adapter.find_verification_value("#{BetterAuth::Plugins::SSO_SAML_RELAY_STATE_KEY_PREFIX}#{relay_state}")
    payload = JSON.parse(stored.fetch("value"))

    assert_equal "/dashboard", payload.fetch("callbackURL")
    assert_equal "/error", payload.fetch("errorURL")
    assert_equal "/welcome", payload.fetch("newUserURL")
    assert_equal true, payload.fetch("requestSignUp")
    assert_equal "saml-provider", payload.fetch("providerId")
    assert_equal({"email" => "alice@example.com", "userId" => "user-1"}, payload.fetch("link"))
    assert_equal 128, payload.fetch("codeVerifier").length
    assert_operator payload.fetch("expiresAt"), :>, (Time.now.to_f * 1000).to_i
    assert_equal "relay_state", ctx.context.cookies.first.first
  end

  def test_generate_relay_state_omits_false_additional_data_but_keeps_link
    ctx = build_context(body: {callbackURL: "/dashboard"})

    relay_state = BetterAuth::SSO::SAMLState.generate_relay_state(
      ctx,
      {email: "alice@example.com", userId: "user-1"},
      false
    )
    stored = ctx.context.internal_adapter.find_verification_value("#{BetterAuth::Plugins::SSO_SAML_RELAY_STATE_KEY_PREFIX}#{relay_state}")
    payload = JSON.parse(stored.fetch("value"))

    assert_equal "/dashboard", payload.fetch("callbackURL")
    assert_equal({"email" => "alice@example.com", "userId" => "user-1"}, payload.fetch("link"))
    refute payload.key?("providerId")
  end

  def test_parse_relay_state_reads_body_relay_state_without_requiring_cookie
    ctx = build_context(body: {callbackURL: "/dashboard"})
    relay_state = BetterAuth::SSO::SAMLState.generate_relay_state(ctx, nil, false)
    parse_ctx = build_context(body: {RelayState: relay_state}, adapter: ctx.context.internal_adapter)

    parsed = BetterAuth::SSO::SAMLState.parse_relay_state(parse_ctx)

    assert_equal "/dashboard", parsed.fetch("callbackURL")
  end

  private

  def build_context(body:, adapter: FakeVerificationAdapter.new)
    ContextWrapper.new(body, Context.new("saml-state-test-secret", adapter, []))
  end

  class FakeVerificationAdapter
    def initialize
      @values = {}
    end

    def create_verification_value(identifier:, value:, **options)
      expires_at = options.fetch(:expiresAt)
      @values[identifier] = {
        "identifier" => identifier,
        "value" => value,
        "expiresAt" => expires_at
      }
    end

    def find_verification_value(identifier)
      @values[identifier]
    end
  end
end

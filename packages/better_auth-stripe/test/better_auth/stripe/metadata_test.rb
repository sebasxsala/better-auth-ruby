# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthStripeMetadataTest < Minitest::Test
  def test_customer_metadata_preserves_internal_fields_and_custom_values
    customer = BetterAuth::Stripe::Metadata.customer_set(
      {userId: "real", customerType: "user"},
      {userId: "fake", customField: "value"}
    )

    assert_equal "real", customer.fetch("userId")
    assert_equal "user", customer.fetch("customerType")
    assert_equal "value", customer.fetch("customField")
    assert_equal({userId: "real", organizationId: nil, customerType: "user"}, BetterAuth::Stripe::Metadata.customer_get(customer))
  end

  def test_subscription_metadata_preserves_internal_fields_and_custom_values
    subscription = BetterAuth::Stripe::Metadata.subscription_set(
      {userId: "u1", subscriptionId: "s1", referenceId: "r1"},
      {subscriptionId: "fake", customField: "value"}
    )

    assert_equal "s1", subscription.fetch("subscriptionId")
    assert_equal "value", subscription.fetch("customField")
    assert_equal({userId: "u1", subscriptionId: "s1", referenceId: "r1"}, BetterAuth::Stripe::Metadata.subscription_get(subscription))
  end

  def test_metadata_drops_unsafe_keys
    customer = BetterAuth::Stripe::Metadata.customer_set(
      {userId: "real", customerType: "user"},
      {"__proto__" => "polluted", "constructor" => "polluted", "prototype" => "polluted", "safe" => "kept"}
    )

    refute customer.key?("__proto__")
    refute customer.key?("constructor")
    refute customer.key?("prototype")
    assert_equal "kept", customer.fetch("safe")
  end

  def test_metadata_accepts_symbol_and_string_keys
    metadata = BetterAuth::Stripe::Metadata.customer_set(
      {userId: "u1", customerType: "user"},
      {"customField" => "value", :organization_id => "ignored"}
    )

    assert_equal "u1", metadata.fetch("userId")
    assert_equal "user", metadata.fetch("customerType")
    assert_equal "value", metadata.fetch("customField")
  end

  def test_metadata_fetch_preserves_explicit_false_values
    metadata = {"customerType" => false, "referenceId" => false}

    assert_equal false, BetterAuth::Stripe::Metadata.metadata_fetch(metadata, "customerType")
    assert_equal false, BetterAuth::Stripe::Metadata.subscription_get(metadata).fetch(:referenceId)
  end
end

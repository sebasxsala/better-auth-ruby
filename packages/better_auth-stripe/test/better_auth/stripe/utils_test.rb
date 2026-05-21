# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthStripeUtilsTest < Minitest::Test
  def test_escape_search_value_matches_upstream
    assert_equal 'test\"value', BetterAuth::Stripe::Utils.escape_search('test"value')
    assert_equal "simple", BetterAuth::Stripe::Utils.escape_search("simple")
    assert_equal '\"a\" and \"b\"', BetterAuth::Stripe::Utils.escape_search('"a" and "b"')
  end

  def test_active_or_trialing_matches_upstream_statuses
    assert BetterAuth::Stripe::Utils.active_or_trialing?({"status" => "active"})
    assert BetterAuth::Stripe::Utils.active_or_trialing?({"status" => "trialing"})
    refute BetterAuth::Stripe::Utils.active_or_trialing?({"status" => "canceled"})
  end

  def test_pending_cancel_checks_database_subscription
    assert BetterAuth::Stripe::Utils.pending_cancel?({"cancelAtPeriodEnd" => true})
    assert BetterAuth::Stripe::Utils.pending_cancel?({"cancelAt" => Time.now})
    refute BetterAuth::Stripe::Utils.pending_cancel?({})
  end

  def test_fetch_preserves_explicit_false_values_from_string_keyed_stripe_objects
    subscription = {
      "status" => "active",
      "cancel_at_period_end" => false,
      "items" => {
        "data" => [
          {
            "current_period_start" => 1_700_000_000,
            "current_period_end" => 1_700_086_400,
            "price" => {"recurring" => {"interval" => "month"}}
          }
        ]
      }
    }

    assert_equal false, BetterAuth::Stripe::Utils.fetch(subscription, "cancel_at_period_end")
    assert_equal false, BetterAuth::Stripe::Utils.subscription_state(subscription, compact: false).fetch(:cancelAtPeriodEnd)
  end

  def test_resolve_plan_item_matches_single_item_by_price_id
    result = BetterAuth::Stripe::Utils.resolve_plan_item(config_with_price_ids, subscription_items([{price: {id: "price_starter", lookup_key: nil}}]))

    assert_equal "price_starter", result.fetch(:item).fetch(:price).fetch(:id)
    assert_equal "starter", result.fetch(:plan).fetch(:name)
  end

  def test_resolve_plan_item_returns_nil_for_empty_items
    assert_nil BetterAuth::Stripe::Utils.resolve_plan_item(config_with_price_ids, subscription_items([]))
  end

  def test_resolve_plan_item_returns_item_without_plan_for_unmatched_single_item
    result = BetterAuth::Stripe::Utils.resolve_plan_item(config_with_price_ids, subscription_items([{price: {id: "price_unknown", lookup_key: nil}}]))

    assert_equal "price_unknown", result.fetch(:item).fetch(:price).fetch(:id)
    assert_nil result.fetch(:plan)
  end

  def test_resolve_plan_item_matches_multi_item_by_lookup_key
    config = {
      subscription: {
        enabled: true,
        plans: [
          {name: "starter", lookup_key: "lookup_starter"},
          {name: "premium", lookup_key: "lookup_premium"}
        ]
      }
    }
    result = BetterAuth::Stripe::Utils.resolve_plan_item(
      config,
      subscription_items([
        {price: {id: "price_seat", lookup_key: nil}},
        {price: {id: "price_foo", lookup_key: "lookup_premium"}}
      ])
    )

    assert_equal "price_foo", result.fetch(:item).fetch(:price).fetch(:id)
    assert_equal "premium", result.fetch(:plan).fetch(:name)
  end

  def test_types_expose_customer_types_and_authorization_actions
    assert_includes BetterAuth::Stripe::Types::CUSTOMER_TYPES, "user"
    assert_includes BetterAuth::Stripe::Types::CUSTOMER_TYPES, "organization"
    assert_includes BetterAuth::Stripe::Types::AUTHORIZE_REFERENCE_ACTIONS, "upgrade-subscription"
  end

  private

  def config_with_price_ids
    {
      subscription: {
        enabled: true,
        plans: [
          {name: "starter", price_id: "price_starter"},
          {name: "premium", price_id: "price_premium"}
        ]
      }
    }
  end

  def subscription_items(items)
    {items: {data: items}}
  end
end

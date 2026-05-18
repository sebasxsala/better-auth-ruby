# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthStripeRoutesUpgradeSubscriptionTest < Minitest::Test
  def test_route_registry_only_includes_webhook_when_subscriptions_disabled
    endpoints = BetterAuth::Stripe::Routes.endpoints({})

    assert_equal [:stripe_webhook], endpoints.keys
  end

  def test_route_registry_includes_upgrade_subscription_when_enabled
    endpoints = BetterAuth::Stripe::Routes.endpoints(subscription: {enabled: true, plans: []})

    assert_equal "/subscription/upgrade", endpoints.fetch(:upgrade_subscription).path
    assert_equal ["POST"], endpoints.fetch(:upgrade_subscription).methods
    assert_equal "upgradeSubscription", endpoints.fetch(:upgrade_subscription).metadata.fetch(:openapi).fetch(:operationId)
    assert_equal "cancelSubscription", endpoints.fetch(:cancel_subscription).metadata.fetch(:openapi).fetch(:operationId)
    assert_equal "cancelSubscriptionCallback", endpoints.fetch(:cancel_subscription_callback).metadata.fetch(:openapi).fetch(:operationId)
    assert_equal "restoreSubscription", endpoints.fetch(:restore_subscription).metadata.fetch(:openapi).fetch(:operationId)
    assert_equal "listActiveSubscriptions", endpoints.fetch(:list_active_subscriptions).metadata.fetch(:openapi).fetch(:operationId)
    assert_equal "subscriptionSuccess", endpoints.fetch(:subscription_success).metadata.fetch(:openapi).fetch(:operationId)
    assert_equal "createBillingPortal", endpoints.fetch(:create_billing_portal).metadata.fetch(:openapi).fetch(:operationId)
  end
end

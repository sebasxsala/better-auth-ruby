# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsStripeTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_creates_customer_on_sign_up_and_subscription_checkout
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: true)

    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "billing@example.com", password: "password123", name: "Billing User"},
      as_response: true
    )
    cookie = cookie_header(headers.fetch("set-cookie"))
    user = auth.context.internal_adapter.find_user_by_email("billing@example.com")[:user]
    assert_match(/\Acus_/, user.fetch("stripeCustomerId"))
    assert_equal 1, stripe.customers.created.length

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "pro", successUrl: "http://localhost:3000/success", cancelUrl: "http://localhost:3000/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "plan", value: "pro"}])
    assert_equal user.fetch("id"), subscription.fetch("referenceId")
    assert_equal "incomplete", subscription.fetch("status")
    assert_nil subscription["stripeSubscriptionId"]
  end

  def test_metadata_helpers_protect_internal_fields_and_preserve_custom_keys
    customer = BetterAuth::Plugins.stripe_customer_metadata_set(
      {userId: "real", customerType: "user"},
      {userId: "fake", customField: "value"}
    )

    assert_equal "real", customer.fetch("userId")
    assert_equal "user", customer.fetch("customerType")
    assert_equal "value", customer.fetch("customField")
    assert_equal({userId: "real", organizationId: nil, customerType: "user"}, BetterAuth::Plugins.stripe_customer_metadata_get(customer))

    subscription = BetterAuth::Plugins.stripe_subscription_metadata_set(
      {userId: "u1", subscriptionId: "s1", referenceId: "r1"},
      {subscriptionId: "fake", customField: "value"}
    )

    assert_equal "s1", subscription.fetch("subscriptionId")
    assert_equal "value", subscription.fetch("customField")
    assert_equal({userId: "u1", subscriptionId: "s1", referenceId: "r1"}, BetterAuth::Plugins.stripe_subscription_metadata_get(subscription))
  end

  def test_metadata_helpers_drop_unsafe_keys
    customer = BetterAuth::Plugins.stripe_customer_metadata_set(
      {userId: "real", customerType: "user"},
      {"__proto__" => "polluted", "constructor" => "polluted", "prototype" => "polluted", "safe" => "kept"}
    )

    refute customer.key?("__proto__")
    refute customer.key?("constructor")
    refute customer.key?("prototype")
    assert_equal "kept", customer.fetch("safe")

    subscription = BetterAuth::Plugins.stripe_subscription_metadata_set(
      {userId: "u1", subscriptionId: "s1", referenceId: "r1"},
      {"__proto__" => "polluted", "constructor" => "polluted", "prototype" => "polluted", "safe" => "kept"}
    )

    refute subscription.key?("__proto__")
    refute subscription.key?("constructor")
    refute subscription.key?("prototype")
    assert_equal "kept", subscription.fetch("safe")
  end

  def test_subscription_schema_includes_upstream_schedule_and_interval_fields
    plugin = BetterAuth::Plugins.stripe(subscription: {enabled: true, plans: []})
    fields = plugin.schema.fetch(:subscription).fetch(:fields)

    assert_equal({type: "string", required: false}, fields.fetch(:billing_interval))
    assert_equal({type: "string", required: false}, fields.fetch(:stripe_schedule_id))
  end

  def test_customer_create_params_and_callback_receive_upstream_shape
    stripe = FakeStripeClient.new
    payloads = []
    auth = build_auth(
      stripe_client: stripe,
      create_customer_on_sign_up: true,
      get_customer_create_params: ->(user, _ctx) { {phone: "+1234567890", metadata: {customField: "customValue", userId: "fake"}} },
      on_customer_create: ->(payload, _ctx) { payloads << payload }
    )

    auth.api.sign_up_email(
      body: {email: "customer-callback@example.com", password: "password123", name: "Customer Callback"},
      as_response: true
    )

    user = auth.context.internal_adapter.find_user_by_email("customer-callback@example.com")[:user]
    created = stripe.customers.created.fetch(0)
    assert_equal "+1234567890", created.fetch(:phone)
    assert_equal "customValue", created.fetch("metadata").fetch("customField")
    assert_equal user.fetch("id"), created.fetch("metadata").fetch("userId")
    assert_equal "user", created.fetch("metadata").fetch("customerType")
    assert_equal 1, payloads.length
    assert_equal created, payloads.fetch(0).fetch(:stripeCustomer)
    assert_equal created, payloads.fetch(0).fetch(:stripe_customer)
    assert_equal created.fetch("id"), payloads.fetch(0).fetch(:user).fetch("stripeCustomerId")
  end

  def test_create_customer_on_sign_up_falls_back_to_customer_list_when_search_unavailable
    stripe = FakeStripeClient.new
    stripe.customers.search_error = RuntimeError.new("search unavailable")
    stripe.customers.list_data = [{"id" => "cus_existing", "email" => "fallback@example.com", "metadata" => {"customerType" => "user"}}]
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: true)

    auth.api.sign_up_email(
      body: {email: "fallback@example.com", password: "password123", name: "Fallback User"},
      as_response: true
    )

    user = auth.context.internal_adapter.find_user_by_email("fallback@example.com")[:user]
    assert_equal "cus_existing", user.fetch("stripeCustomerId")
    assert_empty stripe.customers.created
    assert_equal({email: "fallback@example.com", limit: 100}, stripe.customers.list_calls.fetch(0))
  end

  def test_create_customer_on_sign_up_does_not_block_sign_up_when_stripe_fails
    stripe = FakeStripeClient.new
    stripe.customers.search_error = RuntimeError.new("search unavailable")
    stripe.customers.create_error = RuntimeError.new("stripe unavailable")
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: true)

    status, = auth.api.sign_up_email(
      body: {email: "tolerant-signup@example.com", password: "password123", name: "Tolerant User"},
      as_response: true
    )

    user = auth.context.internal_adapter.find_user_by_email("tolerant-signup@example.com")[:user]
    assert_equal 200, status
    assert_equal "tolerant-signup@example.com", user.fetch("email")
    assert_nil user["stripeCustomerId"]
  end

  def test_upgrade_falls_back_to_customer_list_when_search_unavailable
    stripe = FakeStripeClient.new
    stripe.customers.search_error = RuntimeError.new("search unavailable")
    stripe.customers.list_data = [{"id" => "cus_upgrade_existing", "email" => "fallback-upgrade@example.com", "metadata" => {"customerType" => "user"}}]
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: false)
    cookie = sign_up_cookie(auth, email: "fallback-upgrade@example.com")

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "pro", successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    assert_equal "cus_upgrade_existing", auth.context.internal_adapter.find_user_by_id(user.fetch("id")).fetch("stripeCustomerId")
    assert_empty stripe.customers.created
    assert_equal({email: "fallback-upgrade@example.com", limit: 100}, stripe.customers.list_calls.fetch(0))
  end

  def test_upgrade_rejects_invalid_customer_type
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "invalid-customer-type@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(
        headers: {"cookie" => cookie},
        body: {plan: "pro", customerType: "workspace", successUrl: "/success", cancelUrl: "/cancel"}
      )
    end

    assert_equal "Customer type must be either user or organization", error.message
    assert_empty stripe.customers.created
  end

  def test_checkout_session_params_merge_options_metadata_and_lookup_keys
    stripe = FakeStripeClient.new
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [{name: "lookup", lookup_key: "lookup_monthly"}],
        get_checkout_session_params: lambda do |_data, _request, _ctx|
          {
            params: {
              allow_promotion_codes: true,
              metadata: {customField: "customValue", referenceId: "attacker"},
              subscription_data: {metadata: {subscriptionField: "subscriptionValue"}}
            },
            options: {idempotency_key: "checkout-lookup"}
          }
        end
      }
    )
    cookie = sign_up_cookie(auth, email: "lookup@example.com")

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "lookup", successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    params = stripe.checkout.created.fetch(0)
    assert_equal "price_lookup_123", params.fetch(:line_items).fetch(0).fetch(:price)
    assert_equal true, params.fetch(:allow_promotion_codes)
    assert_equal "customValue", params.fetch(:metadata).fetch("customField")
    refute_equal "attacker", params.fetch(:metadata).fetch("referenceId")
    assert_equal "subscriptionValue", params.fetch(:subscription_data).fetch(:metadata).fetch("subscriptionField")
    assert_equal "checkout-lookup", stripe.checkout.created_options.fetch(0).fetch(:idempotency_key)
  end

  def test_upgrade_rejects_plan_when_price_id_cannot_be_resolved
    stripe = FakeStripeClient.new
    stripe.prices.list_result = {"data" => []}
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [{name: "missing-price", lookup_key: "missing_lookup"}]
      }
    )
    cookie = sign_up_cookie(auth, email: "missing-price@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(
        headers: {"cookie" => cookie},
        body: {plan: "missing-price", successUrl: "/success", cancelUrl: "/cancel"}
      )
    end

    assert_equal "Price ID not found for the selected plan", error.message
    assert_empty stripe.checkout.created
  end

  def test_lists_cancels_restores_and_opens_billing_portal
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth)
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_test",
        stripeSubscriptionId: "sub_test",
        status: "active",
        periodStart: Time.now,
        periodEnd: Time.now + 3600
      }
    )

    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_test")
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_test", customer: "cus_test", price_id: "price_pro")]

    listed = auth.api.list_active_subscriptions(headers: {"cookie" => cookie})
    assert_equal [subscription.fetch("id")], listed.map { |item| item.fetch("id") }

    canceled = auth.api.cancel_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_test", returnUrl: "http://localhost:3000/settings"})
    assert_equal "https://stripe.test/portal", canceled.fetch(:url)
    auth.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {cancelAtPeriodEnd: true})

    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_test", customer: "cus_test", price_id: "price_pro", cancel_at_period_end: true)]
    restored = auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_test"})
    assert_equal "sub_test", restored.fetch(:id)
    assert_equal false, auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}]).fetch("cancelAtPeriodEnd")

    portal = auth.api.create_billing_portal(headers: {"cookie" => cookie}, body: {returnUrl: "http://localhost:3000/settings"})
    assert_equal "https://stripe.test/portal", portal.fetch(:url)
  end

  def test_list_active_subscriptions_returns_annual_price_for_yearly_subscription
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "annual-list@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_annual",
        stripeSubscriptionId: "sub_annual",
        status: "active",
        billingInterval: "year"
      }
    )

    listed = auth.api.list_active_subscriptions(headers: {"cookie" => cookie})

    assert_equal [subscription.fetch("id")], listed.map { |item| item.fetch("id") }
    assert_equal "price_pro_year", listed.fetch(0).fetch("priceId")
  end

  def test_metered_checkout_line_item_omits_quantity
    stripe = FakeStripeClient.new
    stripe.prices.retrieve_data["price_metered"] = {"id" => "price_metered", "recurring" => {"usage_type" => "metered"}}
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [{name: "metered", price_id: "price_metered"}]
      }
    )
    cookie = sign_up_cookie(auth, email: "metered@example.com")

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "metered", successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    line_item = stripe.checkout.created.fetch(0).fetch(:line_items).fetch(0)
    assert_equal "price_metered", line_item.fetch(:price)
    refute line_item.key?(:quantity)
  end

  def test_metered_billing_portal_update_item_omits_quantity
    stripe = FakeStripeClient.new
    stripe.prices.retrieve_data["price_metered"] = {"id" => "price_metered", "recurring" => {"usage_type" => "metered"}}
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [
          {name: "basic", price_id: "price_basic"},
          {name: "metered", price_id: "price_metered"}
        ]
      }
    )
    cookie = sign_up_cookie(auth, email: "metered-portal@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_metered_portal")
    auth.context.adapter.create(
      model: "subscription",
      data: {plan: "basic", referenceId: user.fetch("id"), stripeCustomerId: "cus_metered_portal", stripeSubscriptionId: "sub_metered_portal", status: "active", seats: 1, periodEnd: Time.now + 86_400}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_metered_portal", customer: "cus_metered_portal", price_id: "price_basic")]

    portal = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "metered", seats: 5, successUrl: "/success", cancelUrl: "/cancel", returnUrl: "/billing"}
    )

    assert_equal "https://stripe.test/portal", portal.fetch(:url)
    item = stripe.billing_portal.created.fetch(0).dig(:flow_data, :subscription_update_confirm, :items).fetch(0)
    assert_equal "price_metered", item.fetch(:price)
    assert_equal "si_sub_metered_portal", item.fetch(:id)
    refute item.key?(:quantity)
  end

  def test_schedules_plan_change_at_period_end_and_restore_releases_schedule
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "schedule@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_schedule")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "basic", referenceId: user.fetch("id"), stripeCustomerId: "cus_schedule", stripeSubscriptionId: "sub_schedule", status: "active", seats: 1, periodEnd: Time.now + 86_400}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_schedule", customer: "cus_schedule", price_id: "price_basic", status: "active")]

    result = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "pro", scheduleAtPeriodEnd: true, successUrl: "/success", cancelUrl: "/cancel", returnUrl: "/billing"}
    )

    assert_equal "http://localhost:3000/api/auth/billing", result.fetch(:url)
    assert_equal({from_subscription: "sub_schedule"}, stripe.subscription_schedules.created.fetch(0))
    schedule_update = stripe.subscription_schedules.updated.fetch(0)
    assert_equal "sched_1", schedule_update.fetch(:id)
    assert_equal "release", schedule_update.fetch(:params).fetch(:end_behavior)
    assert_equal "price_pro", schedule_update.fetch(:params).fetch(:phases).fetch(1).fetch(:items).fetch(0).fetch(:price)
    scheduled = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "sched_1", scheduled.fetch("stripeScheduleId")

    restored = auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_schedule"})

    assert_equal "sched_1", restored.fetch("id")
    assert_equal ["sched_1"], stripe.subscription_schedules.released
    cleared = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_nil cleared["stripeScheduleId"]
  end

  def test_webhook_verifies_signature_and_updates_subscription
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: "user-1", stripeSubscriptionId: "sub_test", status: "incomplete"}
    )

    event = {
      type: "customer.subscription.updated",
      data: {
        object: {
          id: "sub_test",
          status: "active",
          current_period_start: 1_700_000_000,
          current_period_end: 1_700_086_400,
          cancel_at_period_end: false,
          items: {data: [{quantity: 1, current_period_start: 1_700_000_000, current_period_end: 1_700_086_400, price: {id: "price_pro"}}]}
        }
      }
    }

    result = auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: event)

    assert_equal({success: true}, result)
    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "active", updated.fetch("status")
  end

  def test_rack_webhook_verification_uses_raw_request_body
    stripe = FakeStripeClient.new
    stripe.webhooks_adapter = RawBodyWebhookVerifier.new(
      expected_payload: JSON.generate({"type" => "invoice.paid"}),
      event: {"type" => "invoice.paid"}
    )
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")

    status, _headers, body = auth.call(
      rack_env(
        "POST",
        "/api/auth/stripe/webhook",
        raw_body: JSON.generate({"type" => "invoice.paid"}),
        headers: {"HTTP_STRIPE_SIGNATURE" => "valid"}
      )
    )

    assert_equal 200, status
    assert_equal({"success" => true}, JSON.parse(body.join))
    assert_equal JSON.generate({"type" => "invoice.paid"}), stripe.webhooks_adapter.payloads.fetch(0)
  end

  def test_webhook_creates_subscription_from_created_event_metadata
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    event = {
      type: "customer.subscription.created",
      data: {
        object: {
          id: "sub_created",
          customer: "cus_created",
          status: "active",
          current_period_start: 1_700_000_000,
          current_period_end: 1_700_086_400,
          cancel_at_period_end: false,
          items: {data: [{quantity: 1, current_period_start: 1_700_000_000, current_period_end: 1_700_086_400, price: {id: "price_pro"}}]},
          metadata: {plan: "pro", referenceId: "user-created", customerType: "user"}
        }
      }
    }

    result = auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: event)

    assert_equal({success: true}, result)
    created = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_created"}])
    assert_equal "pro", created.fetch("plan")
    assert_equal "user-created", created.fetch("referenceId")
    assert_equal "cus_created", created.fetch("stripeCustomerId")
    assert_equal "active", created.fetch("status")
  end

  def test_upgrade_protects_internal_metadata_applies_seats_and_prevents_trial_abuse
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "trial@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    existing = auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "basic",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_trial",
        stripeSubscriptionId: "sub_trial_old",
        status: "canceled",
        trialStart: Time.now - 86_400,
        trialEnd: Time.now - 3_600,
        seats: 1
      }
    )
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_trial")

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {
        plan: "pro",
        seats: 3,
        metadata: {userId: "attacker", subscriptionId: existing.fetch("id"), referenceId: "other", note: "kept"},
        successUrl: "/success",
        cancelUrl: "/cancel"
      }
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    params = stripe.checkout.created.last
    assert_equal "price_pro", params.fetch(:line_items).first.fetch(:price)
    assert_equal 3, params.fetch(:line_items).first.fetch(:quantity)
    refute params.fetch(:subscription_data).key?(:trial_period_days)
    metadata = params.fetch(:subscription_data).fetch(:metadata)
    refute_equal "attacker", metadata.fetch("userId")
    refute_equal existing.fetch("id"), metadata.fetch("subscriptionId")
    refute_equal "other", metadata.fetch("referenceId")
    assert_equal "kept", metadata.fetch("note")

    new_subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "status", value: "incomplete"}])
    assert_equal 3, new_subscription.fetch("seats")

    auth.context.adapter.update(
      model: "subscription",
      where: [{field: "id", value: new_subscription.fetch("id")}],
      update: {status: "active", stripeSubscriptionId: "sub_active", periodEnd: Time.now + 86_400}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_active", customer: "cus_trial", price_id: "price_pro", quantity: 3)]
    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", seats: 3, successUrl: "/success", cancelUrl: "/cancel"})
    end
    assert_equal "You're already subscribed to this plan", error.message

    portal = auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", seats: 5, successUrl: "/success", cancelUrl: "/cancel", returnUrl: "/billing"})
    assert_equal "https://stripe.test/portal", portal.fetch(:url)
    assert_equal 5, stripe.billing_portal.created.last.dig(:flow_data, :subscription_update_confirm, :items).first.fetch(:quantity)
  end

  def test_reference_authorization_blocks_cross_reference_operations
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "owner@example.com")
    other_subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: "other-user", stripeCustomerId: "cus_other", stripeSubscriptionId: "sub_other", status: "active"}
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.cancel_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_other", returnUrl: "/billing"})
    end
    assert_equal "Subscription not found", error.message

    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", referenceId: "other-user", successUrl: "/success", cancelUrl: "/cancel"})
    end
    assert_equal "Reference id is not allowed", error.message
    assert_equal "active", auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: other_subscription.fetch("id")}]).fetch("status")
  end

  def test_webhook_event_matrix_and_callbacks
    events = []
    stripe = FakeStripeClient.new
    stripe.subscriptions.retrieve_data["sub_checkout"] = stripe_subscription(
      id: "sub_checkout",
      price_id: "price_pro",
      status: "trialing",
      quantity: 4,
      trial_start: 1_700_000_000,
      trial_end: 1_700_086_400
    )
    auth = build_auth(
      stripe_client: stripe,
      stripe_webhook_secret: "whsec_test",
      on_event: ->(event) { events << [:event, event[:type] || event["type"]] },
      subscription: subscription_options.merge(
        plans: [
          {name: "basic", price_id: "price_basic"},
          {name: "pro", price_id: "price_pro", annual_discount_price_id: "price_pro_year", limits: {projects: 10}, free_trial: {days: 14, on_trial_start: ->(subscription) { events << [:trial_start, subscription.fetch("id")] }}}
        ],
        on_subscription_complete: ->(data, _ctx) { events << [:complete, data.fetch(:subscription).fetch("status")] },
        on_subscription_created: ->(data) { events << [:created, data.fetch(:subscription).fetch("referenceId")] },
        on_subscription_update: ->(data) { events << [:update, data.fetch(:subscription).fetch("status")] },
        on_subscription_cancel: ->(data) { events << [:cancel, data.fetch(:subscription).fetch("id")] },
        on_subscription_deleted: ->(data) { events << [:deleted, data.fetch(:subscription).fetch("id")] }
      )
    )
    user = create_user(auth, email: "webhook@example.com", stripeCustomerId: "cus_webhook")
    incomplete = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_webhook", status: "incomplete"}
    )

    checkout_event = {
      type: "checkout.session.completed",
      data: {object: {mode: "subscription", subscription: "sub_checkout", customer: "cus_webhook", client_reference_id: user.fetch("id"), metadata: {subscriptionId: incomplete.fetch("id"), referenceId: user.fetch("id")}}}
    }
    assert_equal({success: true}, auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: checkout_event))
    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: incomplete.fetch("id")}])
    assert_equal "trialing", updated.fetch("status")
    assert_equal 4, updated.fetch("seats")
    assert_equal "sub_checkout", updated.fetch("stripeSubscriptionId")

    created_event = {
      type: "customer.subscription.created",
      data: {object: stripe_subscription(id: "sub_dashboard", customer: "cus_webhook", price_id: "price_pro", status: "active", quantity: 2)}
    }
    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: created_event)
    created = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_dashboard"}])
    assert_equal user.fetch("id"), created.fetch("referenceId")
    assert_equal 2, created.fetch("seats")

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: created_event)
    assert_equal 1, auth.context.adapter.find_many(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_dashboard"}]).length

    update_event = {
      type: "customer.subscription.updated",
      data: {object: stripe_subscription(id: "sub_dashboard", customer: "cus_webhook", price_id: "price_basic", status: "active", quantity: 7, cancel_at_period_end: true, canceled_at: 1_700_000_100)}
    }
    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: update_event)
    changed = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: created.fetch("id")}])
    assert_equal "basic", changed.fetch("plan")
    assert_equal 7, changed.fetch("seats")
    assert_equal true, changed.fetch("cancelAtPeriodEnd")

    deleted_event = {
      type: "customer.subscription.deleted",
      data: {object: stripe_subscription(id: "sub_dashboard", customer: "cus_webhook", price_id: "price_basic", status: "canceled", ended_at: 1_700_000_200)}
    }
    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: deleted_event)
    deleted = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: created.fetch("id")}])
    assert_equal "canceled", deleted.fetch("status")
    assert deleted.fetch("endedAt")

    assert_includes events, [:complete, "trialing"]
    assert_includes events, [:trial_start, incomplete.fetch("id")]
    assert_includes events, [:created, user.fetch("id")]
    assert_includes events, [:update, "active"]
    assert_includes events, [:cancel, created.fetch("id")]
    assert_includes events, [:deleted, created.fetch("id")]
    assert_equal 5, events.count { |event| event.first == :event }
  end

  def test_subscription_success_cancel_callback_restore_and_webhook_errors
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    cookie = sign_up_cookie(auth, email: "states@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_states")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_states", stripeSubscriptionId: "sub_states", status: "incomplete"}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_states", customer: "cus_states", price_id: "price_pro", status: "active", quantity: 2)]
    stripe.checkout.retrieve_data["cs_states"] = {"id" => "cs_states", "metadata" => {"subscriptionId" => subscription.fetch("id")}}

    status, headers, = auth.api.subscription_success(headers: {"cookie" => cookie}, query: {callbackURL: "/done", checkoutSessionId: "cs_states"}, as_response: true)
    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth/done", headers.fetch("location")
    synced = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "active", synced.fetch("status")
    assert_equal 2, synced.fetch("seats")

    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_states", customer: "cus_states", price_id: "price_pro", status: "active", cancel_at_period_end: true, canceled_at: 1_700_000_111)]
    status, headers, = auth.api.cancel_subscription_callback(headers: {"cookie" => cookie}, query: {callbackURL: "/billing", subscriptionId: subscription.fetch("id")}, as_response: true)
    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth/billing", headers.fetch("location")
    pending = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal true, pending.fetch("cancelAtPeriodEnd")
    assert pending.fetch("canceledAt")

    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_states", customer: "cus_states", price_id: "price_pro", status: "active", cancel_at: 1_700_010_000)]
    stripe.subscriptions.update_result = stripe_subscription(id: "sub_states", customer: "cus_states", price_id: "price_pro", status: "active")
    restored = auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_states"})
    assert_equal "sub_states", restored.fetch("id")
    restored_record = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal false, restored_record.fetch("cancelAtPeriodEnd")
    assert_nil restored_record.fetch("cancelAt")
    assert_nil restored_record.fetch("canceledAt")
    assert_equal({cancel_at: ""}, stripe.subscriptions.updated.last.fetch(:params))

    assert_raises(BetterAuth::APIError) { auth.api.stripe_webhook(headers: {}, body: {type: "invoice.paid"}) }

    stripe.webhooks.async = true
    assert_equal({success: true}, auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "invoice.paid"}))
    assert_equal ["payload", "valid", "whsec_test"], stripe.webhooks.constructed_async_args
  end

  def test_webhook_prefers_construct_event_async_when_available
    stripe = FakeStripeClient.new
    stripe.webhooks.async_event = {type: "invoice.paid"}
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")

    result = auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "invoice.paid"})

    assert_equal({success: true}, result)
    assert_equal ["payload", "valid", "whsec_test"], stripe.webhooks.constructed_async_args
    assert_nil stripe.webhooks.constructed_sync_args
  end

  def test_webhook_processing_errors_are_logged_without_failing_response
    stripe = FakeStripeClient.new
    auth = build_auth(
      stripe_client: stripe,
      stripe_webhook_secret: "whsec_test",
      on_event: ->(_event) { raise "processing failed" }
    )

    assert_equal({success: true}, auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "invoice.paid"}))
  end

  def test_webhook_rejects_missing_signature
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.stripe_webhook(headers: {}, body: {type: "customer.subscription.updated"})
    end

    assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("STRIPE_SIGNATURE_NOT_FOUND"), error.message
  end

  def test_webhook_rejects_missing_secret
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: nil)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "customer.subscription.updated"})
    end

    assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("STRIPE_WEBHOOK_SECRET_NOT_FOUND"), error.message
  end

  def test_webhook_rejects_client_without_construct_event
    auth = build_auth(stripe_client: Object.new, stripe_webhook_secret: "whsec_test")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "invoice.paid"})
    end

    assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT"), error.message
  end

  def test_webhook_rejects_null_constructed_event
    stripe = FakeStripeClient.new
    stripe.webhooks.async_event = false
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "customer.subscription.updated"})
    end

    assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT"), error.message
  end

  def test_subscription_created_hook_skips_when_customer_reference_is_missing
    stripe = FakeStripeClient.new
    stripe.webhooks.async_event = {
      type: "customer.subscription.created",
      data: {
        object: stripe_subscription(
          id: "sub_missing_reference",
          customer: "cus_missing_reference",
          metadata: {}
        )
      }
    }
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: "{}")

    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_missing_reference"}])
    assert_nil subscription
  end

  def test_subscription_success_uses_checkout_session_metadata_and_replaces_placeholder
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "checkout-success@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_success")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_success", status: "incomplete"}
    )
    stripe.checkout.retrieve_data["cs_success"] = {"id" => "cs_success", "metadata" => {"subscriptionId" => subscription.fetch("id")}}
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_success", customer: "cus_success", price_id: "price_pro", status: "active", quantity: 2)]

    status, headers, = auth.api.subscription_success(
      headers: {"cookie" => cookie},
      query: {callbackURL: "/done/{CHECKOUT_SESSION_ID}", checkoutSessionId: "cs_success"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth/done/cs_success", headers.fetch("location")
    synced = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "active", synced.fetch("status")
    assert_equal "sub_success", synced.fetch("stripeSubscriptionId")
  end

  def test_subscription_webhook_syncs_interval_schedule_and_clears_stale_cancel_fields
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: "user-interval",
        stripeCustomerId: "cus_interval",
        stripeSubscriptionId: "sub_interval",
        status: "active",
        cancelAt: Time.at(1_700_010_000),
        canceledAt: Time.at(1_700_000_000),
        endedAt: Time.at(1_700_020_000),
        stripeScheduleId: "sub_sched_old"
      }
    )

    event = {
      type: "customer.subscription.updated",
      data: {
        object: stripe_subscription(
          id: "sub_interval",
          customer: "cus_interval",
          price_id: "price_pro_year",
          status: "active",
          cancel_at_period_end: false,
          cancel_at: nil,
          canceled_at: nil,
          ended_at: nil,
          schedule: "sub_sched_new",
          interval: "year"
        )
      }
    }

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: event)

    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "year", updated.fetch("billingInterval")
    assert_equal "sub_sched_new", updated.fetch("stripeScheduleId")
    assert_nil updated["cancelAt"]
    assert_nil updated["canceledAt"]
    assert_nil updated["endedAt"]
  end

  def test_subscription_update_resolves_plan_item_from_multi_item_subscription
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "basic", referenceId: "user-multi-item", stripeCustomerId: "cus_multi", stripeSubscriptionId: "sub_multi", status: "active", seats: 1}
    )
    event = {
      type: "customer.subscription.updated",
      data: {
        object: stripe_subscription(
          id: "sub_multi",
          customer: "cus_multi",
          price_id: "price_addon",
          status: "active",
          quantity: 99,
          extra_items: [
            {
              id: "si_plan_sub_multi",
              quantity: 3,
              current_period_start: 1_700_000_000,
              current_period_end: 1_700_086_400,
              price: {id: "price_pro", lookup_key: nil, recurring: {interval: "month"}}
            }
          ]
        )
      }
    }

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: event)

    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "pro", updated.fetch("plan")
    assert_equal 3, updated.fetch("seats")
  end

  def test_subscription_update_invokes_trial_end_and_expired_callbacks
    stripe = FakeStripeClient.new
    callbacks = []
    auth = build_auth(
      stripe_client: stripe,
      stripe_webhook_secret: "whsec_test",
      subscription: subscription_options.merge(
        plans: [
          {
            name: "pro",
            price_id: "price_pro",
            free_trial: {
              days: 14,
              on_trial_end: ->(payload, _ctx = nil) { callbacks << [:end, payload.fetch(:subscription).fetch("id")] },
              on_trial_expired: ->(subscription, _ctx = nil) { callbacks << [:expired, subscription.fetch("id")] }
            }
          }
        ]
      )
    )
    ended_subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: "user-trial-end", stripeCustomerId: "cus_trial_end", stripeSubscriptionId: "sub_trial_end", status: "trialing"}
    )
    expired_subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: "user-trial-expired", stripeCustomerId: "cus_trial_expired", stripeSubscriptionId: "sub_trial_expired", status: "trialing"}
    )

    auth.api.stripe_webhook(
      headers: {"stripe-signature" => "valid"},
      body: {type: "customer.subscription.updated", data: {object: stripe_subscription(id: "sub_trial_end", customer: "cus_trial_end", price_id: "price_pro", status: "active")}}
    )
    auth.api.stripe_webhook(
      headers: {"stripe-signature" => "valid"},
      body: {type: "customer.subscription.updated", data: {object: stripe_subscription(id: "sub_trial_expired", customer: "cus_trial_expired", price_id: "price_pro", status: "incomplete_expired")}}
    )

    assert_includes callbacks, [:end, ended_subscription.fetch("id")]
    assert_includes callbacks, [:expired, expired_subscription.fetch("id")]
  end

  def test_builds_official_stripe_client_adapter_from_api_key
    plugin = BetterAuth::Plugins.stripe(stripe_api_key: "sk_test_123")

    client = BetterAuth::Plugins.stripe_client(plugin.options)

    assert_instance_of BetterAuth::Stripe::ClientAdapter, client
    assert client.respond_to?(:customers)
    assert_same client, BetterAuth::Plugins.stripe_client(plugin.options)
  end

  def test_builds_official_stripe_client_adapter_from_env_secret
    previous_secret = ENV["STRIPE_SECRET_KEY"]
    ENV["STRIPE_SECRET_KEY"] = "sk_test_env"
    plugin = BetterAuth::Plugins.stripe

    client = BetterAuth::Plugins.stripe_client(plugin.options)

    assert_instance_of BetterAuth::Stripe::ClientAdapter, client
  ensure
    previous_secret ? ENV["STRIPE_SECRET_KEY"] = previous_secret : ENV.delete("STRIPE_SECRET_KEY")
  end

  def test_missing_client_and_api_key_raise_helpful_error
    previous_secret = ENV.delete("STRIPE_SECRET_KEY")
    plugin = BetterAuth::Plugins.stripe

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.stripe_client(plugin.options)
    end

    assert_includes error.message, "Stripe client is required"
  ensure
    ENV["STRIPE_SECRET_KEY"] = previous_secret if previous_secret
  end

  def test_utility_helpers_match_upstream_search_escaping_and_plan_item_resolution
    assert_equal 'test\"value', BetterAuth::Plugins.stripe_escape_search('test"value')
    assert_equal "simple", BetterAuth::Plugins.stripe_escape_search("simple")
    assert_equal '\"a\" and \"b\"', BetterAuth::Plugins.stripe_escape_search('"a" and "b"')

    config = {
      subscription: {
        enabled: true,
        plans: [
          {name: "starter", price_id: "price_starter"},
          {name: "premium", price_id: "price_premium"}
        ]
      }
    }

    single = stripe_subscription(id: "sub_single", price_id: "price_starter")
    resolved = BetterAuth::Plugins.stripe_resolve_plan_item(config, single)
    assert_equal "price_starter", resolved.fetch(:item).fetch(:price).fetch(:id)
    assert_equal "starter", resolved.fetch(:plan).fetch(:name)

    empty = {items: {data: []}}
    assert_nil BetterAuth::Plugins.stripe_resolve_plan_item(config, empty)

    unmatched_single = stripe_subscription(id: "sub_unknown", price_id: "price_unknown")
    resolved = BetterAuth::Plugins.stripe_resolve_plan_item(config, unmatched_single)
    assert_equal "price_unknown", resolved.fetch(:item).fetch(:price).fetch(:id)
    assert_nil resolved.fetch(:plan)

    multi = stripe_subscription(
      id: "sub_multi_resolve",
      price_id: "price_seat_addon",
      extra_items: [{id: "si_plan", price: {id: "price_starter", lookup_key: nil}}]
    )
    resolved = BetterAuth::Plugins.stripe_resolve_plan_item(config, multi)
    assert_equal "price_starter", resolved.fetch(:item).fetch(:price).fetch(:id)
    assert_equal "starter", resolved.fetch(:plan).fetch(:name)

    no_match_multi = stripe_subscription(
      id: "sub_multi_unknown",
      price_id: "price_unknown_1",
      extra_items: [{id: "si_unknown", price: {id: "price_unknown_2", lookup_key: nil}}]
    )
    assert_nil BetterAuth::Plugins.stripe_resolve_plan_item(config, no_match_multi)

    lookup_config = {subscription: {enabled: true, plans: [{name: "premium", lookup_key: "lookup_premium"}]}}
    lookup_subscription = stripe_subscription(
      id: "sub_lookup_resolve",
      price_id: "price_seat",
      extra_items: [{id: "si_lookup", price: {id: "price_lookup", lookup_key: "lookup_premium"}}]
    )
    resolved = BetterAuth::Plugins.stripe_resolve_plan_item(lookup_config, lookup_subscription)
    assert_equal "price_lookup", resolved.fetch(:item).fetch(:price).fetch(:id)
    assert_equal "premium", resolved.fetch(:plan).fetch(:name)
  end

  def test_cross_user_subscription_id_operations_reject_upgrade_cancel_and_restore
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "cross-user@example.com")
    other = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: "other-user", stripeCustomerId: "cus_other", stripeSubscriptionId: "sub_other", status: "active", cancelAtPeriodEnd: true}
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "basic", subscriptionId: "sub_other", successUrl: "/success", cancelUrl: "/cancel"})
    end
    assert_equal "Subscription not found", error.message

    error = assert_raises(BetterAuth::APIError) do
      auth.api.cancel_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_other", returnUrl: "/billing"})
    end
    assert_equal "Subscription not found", error.message

    error = assert_raises(BetterAuth::APIError) do
      auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_other"})
    end
    assert_equal "Subscription not found", error.message
    assert_equal "active", auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: other.fetch("id")}]).fetch("status")
  end

  def test_billing_interval_is_listed_and_annual_checkout_webhook_stores_year
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    cookie = sign_up_cookie(auth, email: "annual-webhook@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_annual_webhook")
    listed_subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_annual_webhook", stripeSubscriptionId: "sub_annual_list", status: "active", billingInterval: "year"}
    )

    listed = auth.api.list_active_subscriptions(headers: {"cookie" => cookie})
    assert_equal listed_subscription.fetch("id"), listed.fetch(0).fetch("id")
    assert_equal "year", listed.fetch(0).fetch("billingInterval")
    assert_equal "price_pro_year", listed.fetch(0).fetch("priceId")

    incomplete = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_annual_webhook", status: "incomplete"}
    )
    stripe.subscriptions.retrieve_data["sub_checkout_year"] = stripe_subscription(
      id: "sub_checkout_year",
      customer: "cus_annual_webhook",
      price_id: "price_pro_year",
      status: "active",
      interval: "year"
    )
    auth.api.stripe_webhook(
      headers: {"stripe-signature" => "valid"},
      body: {
        type: "checkout.session.completed",
        data: {object: {mode: "subscription", subscription: "sub_checkout_year", customer: "cus_annual_webhook", client_reference_id: user.fetch("id"), metadata: {subscriptionId: incomplete.fetch("id"), referenceId: user.fetch("id")}}}
      }
    )

    synced = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: incomplete.fetch("id")}])
    assert_equal "year", synced.fetch("billingInterval")
  end

  def test_created_webhook_skips_duplicates_missing_reference_and_unknown_plan
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    user = create_user(auth, email: "created-skip@example.com", stripeCustomerId: "cus_created_skip")
    existing = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_created_skip", stripeSubscriptionId: "sub_existing_skip", status: "active"}
    )

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "customer.subscription.created", data: {object: stripe_subscription(id: "sub_no_reference", customer: "cus_missing_reference", price_id: "price_pro")}})
    assert_nil auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_no_reference"}])

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "customer.subscription.created", data: {object: stripe_subscription(id: "sub_unknown_plan", customer: "cus_created_skip", price_id: "price_unknown")}})
    assert_nil auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_unknown_plan"}])

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "customer.subscription.created", data: {object: stripe_subscription(id: "sub_existing_skip", customer: "cus_created_skip", price_id: "price_pro")}})
    assert_equal [existing.fetch("id")], auth.context.adapter.find_many(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_existing_skip"}]).map { |entry| entry.fetch("id") }
  end

  def test_user_customer_update_and_nested_customer_create_params_match_upstream
    stripe = FakeStripeClient.new
    auth = build_auth(
      stripe_client: stripe,
      create_customer_on_sign_up: true,
      get_customer_create_params: ->(_user, _ctx) {
        {
          address: {line1: "Custom Line", country: "US"},
          metadata: {customField: "custom", userId: "attacker"}
        }
      }
    )

    sign_up_cookie(auth, email: "nested-customer@example.com")
    created = stripe.customers.created.fetch(0)
    assert_equal "Custom Line", created.fetch(:address).fetch(:line1)
    assert_equal "US", created.fetch(:address).fetch(:country)
    assert_equal "custom", created.fetch("metadata").fetch("customField")
    refute_equal "attacker", created.fetch("metadata").fetch("userId")

    user = auth.context.internal_adapter.find_user_by_email("nested-customer@example.com")[:user]
    stripe.customers.retrieve_data[user.fetch("stripeCustomerId")] = {"id" => user.fetch("stripeCustomerId"), "email" => "nested-customer@example.com", "deleted" => false}
    auth.context.internal_adapter.update_user(user.fetch("id"), email: "renamed-customer@example.com")
    assert_equal({id: user.fetch("stripeCustomerId"), params: {email: "renamed-customer@example.com"}}, stripe.customers.updated.last)
  end

  def test_webhook_rejects_missing_secret_null_event_and_supports_sync_construct_event
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: nil)
    error = assert_raises(BetterAuth::APIError) do
      auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "invoice.paid"})
    end
    assert_equal "Stripe webhook secret not found", error.message

    stripe = FakeStripeClient.new
    stripe.webhooks.async_event = false
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    error = assert_raises(BetterAuth::APIError) do
      auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "invoice.paid"})
    end
    assert_equal "Failed to construct Stripe event", error.message

    stripe = FakeStripeClient.new
    sync_webhooks = Class.new do
      attr_reader :constructed_sync_args

      def construct_event(payload, signature, secret)
        @constructed_sync_args = ["payload", signature, secret]
        payload
      end
    end.new
    stripe.webhooks_adapter = sync_webhooks
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    assert_equal({success: true}, auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "invoice.paid"}))
    assert_equal ["payload", "valid", "whsec_test"], sync_webhooks.constructed_sync_args
  end

  def test_restore_rejects_when_subscription_has_no_pending_cancel_or_schedule
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "restore-reject@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_restore_reject")
    auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_restore_reject", stripeSubscriptionId: "sub_restore_reject", status: "active"}
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_restore_reject"})
    end
    assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_PENDING_CHANGE"), error.message
  end

  def test_cancel_fallback_syncs_when_stripe_reports_already_canceled
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "cancel-fallback@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_cancel_fallback")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_cancel_fallback", stripeSubscriptionId: "sub_cancel_fallback", status: "active"}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_cancel_fallback", customer: "cus_cancel_fallback", price_id: "price_pro")]
    stripe.billing_portal.create_error = RuntimeError.new("already set to be canceled")
    stripe.subscriptions.retrieve_data["sub_cancel_fallback"] = stripe_subscription(id: "sub_cancel_fallback", customer: "cus_cancel_fallback", price_id: "price_pro", cancel_at_period_end: true)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.cancel_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_cancel_fallback", returnUrl: "/billing"})
    end

    assert_equal "already set to be canceled", error.message
    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal true, updated.fetch("cancelAtPeriodEnd")
  end

  def test_cancel_route_syncs_when_stripe_reports_already_canceled
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "cancel-sync-route@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_cancel_route",
        stripeSubscriptionId: "sub_cancel_route",
        status: "active"
      }
    )
    stripe.subscriptions.list_data = [
      stripe_subscription(id: "sub_cancel_route", customer: "cus_cancel_route", cancel_at_period_end: true)
    ]
    stripe.subscriptions.retrieve_data["sub_cancel_route"] = stripe_subscription(id: "sub_cancel_route", customer: "cus_cancel_route", cancel_at_period_end: true)
    stripe.billing_portal.create_error = RuntimeError.new("already set to be canceled")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.cancel_subscription(
        headers: {"cookie" => cookie},
        body: {subscriptionId: "sub_cancel_route", returnUrl: "/account"}
      )
    end

    assert_includes error.message, "already set to be canceled"
    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal true, updated.fetch("cancelAtPeriodEnd")
  end

  def test_restore_route_clears_cancel_at_period_end
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "restore-period-route@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_restore_period",
        stripeSubscriptionId: "sub_restore_period",
        status: "active",
        cancelAtPeriodEnd: true
      }
    )
    stripe.subscriptions.list_data = [
      stripe_subscription(id: "sub_restore_period", customer: "cus_restore_period", cancel_at_period_end: true)
    ]

    auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_restore_period"})

    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_restore_period"}])
    assert_equal false, updated.fetch("cancelAtPeriodEnd")
    assert_equal({cancel_at_period_end: false}, stripe.subscriptions.updated.fetch(0).fetch(:params))
  end

  def test_restore_route_releases_pending_schedule
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "restore-schedule-route@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_restore_schedule",
        stripeSubscriptionId: "sub_restore_schedule",
        status: "active",
        stripeScheduleId: "sched_restore_route"
      }
    )
    stripe.subscription_schedules.retrieve_data["sched_restore_route"] = {"id" => "sched_restore_route", "status" => "active"}

    auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_restore_schedule"})

    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_restore_schedule"}])
    assert_nil updated["stripeScheduleId"]
    assert_equal "sched_restore_route", stripe.subscription_schedules.released.fetch(0)
  end

  def test_list_route_returns_limits_and_annual_price_id
    stripe = FakeStripeClient.new
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [{name: "pro", price_id: "price_pro_month", annual_discount_price_id: "price_pro_year", limits: {"projects" => 10}}]
      }
    )
    cookie = sign_up_cookie(auth, email: "list-limits-route@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_list_limits",
        stripeSubscriptionId: "sub_list_limits",
        status: "active",
        billingInterval: "year"
      }
    )

    subscriptions = auth.api.list_active_subscriptions(headers: {"cookie" => cookie})

    assert_equal "price_pro_year", subscriptions.fetch(0).fetch("priceId")
    assert_equal({"projects" => 10}, subscriptions.fetch(0).fetch("limits"))
  end

  def test_success_route_replaces_checkout_session_placeholder
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "success-placeholder-route@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_success_placeholder",
        status: "incomplete"
      }
    )
    stripe.checkout.retrieve_data["cs_success_placeholder"] = {
      "id" => "cs_success_placeholder",
      "metadata" => {"subscriptionId" => subscription.fetch("id")}
    }
    stripe.subscriptions.list_data = [
      stripe_subscription(id: "sub_success_placeholder", customer: "cus_success_placeholder")
    ]

    response = auth.api.subscription_success(
      headers: {"cookie" => cookie},
      query: {
        callbackURL: "/done?session={CHECKOUT_SESSION_ID}",
        checkoutSessionId: "cs_success_placeholder"
      },
      as_response: true
    )

    assert_equal 302, response.status
    assert_includes response.headers.fetch("location"), "session=cs_success_placeholder"
  end

  def test_user_reference_authorization_branches_match_upstream
    stripe = FakeStripeClient.new
    auth = build_auth(
      stripe_client: stripe,
      subscription: subscription_options.merge(authorize_reference: ->(data, _ctx) { data.fetch(:reference_id) == "allowed-reference" })
    )
    cookie = sign_up_cookie(auth, email: "reference-branches@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]

    assert_equal "https://stripe.test/checkout", auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", successUrl: "/success", cancelUrl: "/cancel"}).fetch(:url)
    assert_equal "https://stripe.test/checkout", auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", referenceId: user.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"}).fetch(:url)
    assert_equal "https://stripe.test/checkout", auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "basic", referenceId: "allowed-reference", successUrl: "/success", cancelUrl: "/cancel"}).fetch(:url)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "basic", referenceId: "blocked-reference", successUrl: "/success", cancelUrl: "/cancel"})
    end
    assert_equal "Unauthorized access", error.message

    auth_without_authorizer = build_auth(stripe_client: FakeStripeClient.new)
    cookie_without_authorizer = sign_up_cookie(auth_without_authorizer, email: "reference-no-authorizer@example.com")
    error = assert_raises(BetterAuth::APIError) do
      auth_without_authorizer.api.upgrade_subscription(headers: {"cookie" => cookie_without_authorizer}, body: {plan: "pro", referenceId: "other-reference", successUrl: "/success", cancelUrl: "/cancel"})
    end
    assert_equal "Reference id is not allowed", error.message
  end

  def test_schedule_release_and_line_item_replacement_parity
    stripe = FakeStripeClient.new
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [
          {name: "basic", price_id: "price_basic", line_items: [{price: "price_meter_old"}]},
          {name: "pro", price_id: "price_pro", line_items: [{price: "price_meter_new"}]},
          {name: "enterprise", price_id: "price_enterprise", line_items: [{price: "price_meter_new"}, {price: "price_extra"}]}
        ]
      }
    )
    cookie = sign_up_cookie(auth, email: "line-items@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_line_items")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "basic", referenceId: user.fetch("id"), stripeCustomerId: "cus_line_items", stripeSubscriptionId: "sub_line_items", status: "active", seats: 1, periodEnd: Time.now + 86_400, stripeScheduleId: "sched_plugin"}
    )
    stripe.subscription_schedules.retrieve_data["sched_plugin"] = {"id" => "sched_plugin", "status" => "active", "metadata" => {"source" => "@better-auth/stripe"}}
    stripe.subscriptions.list_data = [
      stripe_subscription(
        id: "sub_line_items",
        customer: "cus_line_items",
        price_id: "price_basic",
        schedule: "sched_plugin",
        extra_items: [{id: "si_meter_old", quantity: 1, price: {id: "price_meter_old"}}]
      )
    ]
    stripe.subscription_schedules.list_data = [
      {"id" => "sched_plugin", "subscription" => "sub_line_items", "status" => "active", "metadata" => {"source" => "@better-auth/stripe"}}
    ]

    result = auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", returnUrl: "/billing", successUrl: "/success", cancelUrl: "/cancel"})
    assert_equal "http://localhost:3000/api/auth/billing", result.fetch(:url)
    assert_includes stripe.subscription_schedules.released, "sched_plugin"
    update_items = stripe.subscriptions.updated.last.fetch(:params).fetch(:items)
    assert_includes update_items, {id: "si_sub_line_items", price: "price_pro", quantity: 1}
    assert_includes update_items, {id: "si_meter_old", deleted: true}
    assert_includes update_items, {price: "price_meter_new"}

    auth.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {plan: "pro", stripeScheduleId: "sched_external"})
    stripe.subscription_schedules.retrieve_data["sched_external"] = {"id" => "sched_external", "status" => "active", "metadata" => {"source" => "dashboard"}}
    stripe.subscription_schedules.list_data = [
      {"id" => "sched_external", "subscription" => "sub_line_items", "status" => "active", "metadata" => {"source" => "dashboard"}}
    ]
    stripe.subscriptions.updated.clear
    auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "enterprise", returnUrl: "/billing", successUrl: "/success", cancelUrl: "/cancel"})
    refute_includes stripe.subscription_schedules.released, "sched_external"
  end

  def test_subscription_success_redirect_branches_and_checkout_retrieve_failure
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "success-branches@example.com")

    status, headers, = auth.api.subscription_success(headers: {"cookie" => cookie}, query: {callbackURL: "/done"}, as_response: true)
    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth/done", headers.fetch("location")

    stripe.checkout.retrieve_error = RuntimeError.new("checkout unavailable")
    status, headers, = auth.api.subscription_success(headers: {"cookie" => cookie}, query: {callbackURL: "/done", checkoutSessionId: "cs_missing"}, as_response: true)
    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth/done", headers.fetch("location")
  end

  def test_metered_prices_omit_quantity_for_direct_and_scheduled_upgrades_but_licensed_keeps_quantity
    stripe = FakeStripeClient.new
    stripe.prices.retrieve_data["price_metered"] = {"id" => "price_metered", "recurring" => {"usage_type" => "metered"}}
    stripe.prices.retrieve_data["price_licensed"] = {"id" => "price_licensed", "recurring" => {"usage_type" => "licensed"}}
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [
          {name: "basic", price_id: "price_basic"},
          {name: "metered", price_id: "price_metered"},
          {name: "licensed", price_id: "price_licensed"}
        ]
      }
    )
    cookie = sign_up_cookie(auth, email: "metered-direct@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_metered_direct")
    auth.context.adapter.create(
      model: "subscription",
      data: {plan: "basic", referenceId: user.fetch("id"), stripeCustomerId: "cus_metered_direct", stripeSubscriptionId: "sub_metered_direct", status: "active", seats: 5, periodEnd: Time.now + 86_400}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_metered_direct", customer: "cus_metered_direct", price_id: "price_basic", quantity: 5)]

    auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "metered", seats: 5, returnUrl: "/billing", successUrl: "/success", cancelUrl: "/cancel"})
    item = stripe.billing_portal.created.last.dig(:flow_data, :subscription_update_confirm, :items).fetch(0)
    assert_equal "price_metered", item.fetch(:price)
    refute item.key?(:quantity)

    licensed_cookie = sign_up_cookie(auth, email: "licensed-checkout@example.com")
    checkout = auth.api.upgrade_subscription(headers: {"cookie" => licensed_cookie}, body: {plan: "licensed", seats: 4, successUrl: "/success", cancelUrl: "/cancel"})
    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    assert_equal 4, stripe.checkout.created.last.fetch(:line_items).fetch(0).fetch(:quantity)

    auth.context.adapter.update(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_metered_direct"}], update: {plan: "basic"})
    auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "metered", scheduleAtPeriodEnd: true, seats: 5, returnUrl: "/billing", successUrl: "/success", cancelUrl: "/cancel"})
    scheduled_item = stripe.subscription_schedules.updated.last.fetch(:params).fetch(:phases).fetch(1).fetch(:items).fetch(0)
    assert_equal "price_metered", scheduled_item.fetch(:price)
    refute scheduled_item.key?(:quantity)
  end

  def test_flexible_limits_types_are_preserved_in_subscription_list
    limits = {
      maxUsers: 100,
      maxProjects: 10,
      features: ["analytics", "api", "webhooks"],
      supportedMethods: ["GET", "POST", "PUT", "DELETE"],
      rateLimit: {requests: 1000, window: 3600},
      permissions: {admin: true, read: true, write: false},
      quotas: {storage: 50, bandwidth: [100, "GB"]}
    }
    auth = build_auth(
      stripe_client: FakeStripeClient.new,
      subscription: {
        enabled: true,
        plans: [{name: "flexible", price_id: "price_flexible", limits: limits}]
      }
    )
    cookie = sign_up_cookie(auth, email: "limits@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.adapter.create(
      model: "subscription",
      data: {plan: "flexible", referenceId: user.fetch("id"), stripeCustomerId: "cus_limits", stripeSubscriptionId: "sub_limits", status: "active"}
    )

    listed_limits = auth.api.list_active_subscriptions(headers: {"cookie" => cookie}).fetch(0).fetch("limits")

    assert_equal 100, listed_limits.fetch(:maxUsers)
    assert_equal 10, listed_limits.fetch(:maxProjects)
    assert_equal ["analytics", "api", "webhooks"], listed_limits.fetch(:features)
    assert_equal ["GET", "POST", "PUT", "DELETE"], listed_limits.fetch(:supportedMethods)
    assert_equal 1000, listed_limits.fetch(:rateLimit).fetch(:requests)
    assert_equal true, listed_limits.fetch(:permissions).fetch(:admin)
    assert_equal 50, listed_limits.fetch(:quotas).fetch(:storage)
    assert_equal [100, "GB"], listed_limits.fetch(:quotas).fetch(:bandwidth)
  end

  def test_duplicate_customer_prevention_and_user_organization_collision_search
    stripe = FakeStripeClient.new
    stripe.customers.search_data = [{"id" => "cus_existing_user", "email" => "existing@example.com", "metadata" => {"customerType" => "user"}}]
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: true)

    sign_up_cookie(auth, email: "existing@example.com")
    user = auth.context.internal_adapter.find_user_by_email("existing@example.com")[:user]

    assert_equal "cus_existing_user", user.fetch("stripeCustomerId")
    assert_empty stripe.customers.created
    assert_equal 'email:"existing@example.com" AND -metadata["customerType"]:"organization"', stripe.customers.search_calls.fetch(0).fetch(:query)

    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: true)
    cookie = sign_up_cookie(auth, email: "new-customer@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]

    assert_equal 1, stripe.customers.created.length
    assert_match(/\Acus_/, user.fetch("stripeCustomerId"))
    assert_equal 'email:"new-customer@example.com" AND -metadata["customerType"]:"organization"', stripe.customers.search_calls.fetch(0).fetch(:query)

    stripe = FakeStripeClient.new
    stripe.customers.search_data = []
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: true)
    sign_up_cookie(auth, email: "shared@example.com")
    shared_user = auth.context.internal_adapter.find_user_by_email("shared@example.com")[:user]

    assert_equal 1, stripe.customers.created.length
    refute_equal "cus_org_123", shared_user.fetch("stripeCustomerId")
    assert_equal 'email:"shared@example.com" AND -metadata["customerType"]:"organization"', stripe.customers.search_calls.fetch(0).fetch(:query)

    stripe = FakeStripeClient.new
    stripe.customers.search_data = [{"id" => "cus_existing_user_same_email", "email" => "both@example.com", "metadata" => {"customerType" => "user"}}]
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: true)
    sign_up_cookie(auth, email: "both@example.com")
    both_user = auth.context.internal_adapter.find_user_by_email("both@example.com")[:user]

    assert_equal "cus_existing_user_same_email", both_user.fetch("stripeCustomerId")
    assert_empty stripe.customers.created
  end

  def test_custom_reference_billing_portal_and_upgrade_do_not_mutate_personal_subscription
    stripe = FakeStripeClient.new
    auth = build_auth(
      stripe_client: stripe,
      subscription: subscription_options.merge(authorize_reference: ->(_data, _ctx) { true })
    )
    cookie = sign_up_cookie(auth, email: "custom-reference@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    personal = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "basic", referenceId: user.fetch("id"), stripeCustomerId: "cus_personal", stripeSubscriptionId: "sub_personal", status: "active", seats: 1}
    )
    custom = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "basic", referenceId: "workspace-1", stripeCustomerId: "cus_workspace", stripeSubscriptionId: "sub_workspace", status: "active", seats: 1}
    )
    stripe.subscriptions.list_data = [
      stripe_subscription(id: "sub_personal", customer: "cus_personal", price_id: "price_basic"),
      stripe_subscription(id: "sub_workspace", customer: "cus_workspace", price_id: "price_basic")
    ]

    portal = auth.api.create_billing_portal(headers: {"cookie" => cookie}, body: {referenceId: "workspace-1", returnUrl: "/billing"})
    assert_equal "https://stripe.test/portal", portal.fetch(:url)
    assert_equal "cus_workspace", stripe.billing_portal.created.last.fetch(:customer)

    upgrade = auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", referenceId: "workspace-1", returnUrl: "/billing", successUrl: "/success", cancelUrl: "/cancel"})
    assert_equal "https://stripe.test/portal", upgrade.fetch(:url)

    assert_equal "basic", auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: personal.fetch("id")}]).fetch("plan")
    assert_equal "basic", auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: custom.fetch("id")}]).fetch("plan")
    assert_equal "sub_workspace", stripe.billing_portal.created.last.dig(:flow_data, :subscription_update_confirm, :subscription)
  end

  def test_signup_and_upgrade_only_create_one_customer
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: true)
    cookie = sign_up_cookie(auth, email: "one-customer@example.com")

    assert_equal 1, stripe.customers.created.length

    checkout = auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", successUrl: "/success", cancelUrl: "/cancel"})

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    assert_equal 1, stripe.customers.created.length
  end

  def test_stripe_routes_reject_untrusted_redirect_urls
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "untrusted-stripe-urls@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_untrusted_urls")
    auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_untrusted_urls",
        stripeSubscriptionId: "sub_untrusted_urls",
        status: "active",
        periodEnd: Time.now + 3600
      }
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_untrusted_urls", customer: "cus_untrusted_urls", price_id: "price_pro")]

    assert_untrusted_stripe_url do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", successUrl: "https://evil.example/success", cancelUrl: "/cancel"})
    end
    assert_untrusted_stripe_url do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", successUrl: "/success", cancelUrl: "https://evil.example/cancel"})
    end
    assert_untrusted_stripe_url do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "basic", successUrl: "/success", cancelUrl: "/cancel", returnUrl: "https://evil.example/billing"})
    end
    assert_untrusted_stripe_url do
      auth.api.create_billing_portal(headers: {"cookie" => cookie}, body: {returnUrl: "https://evil.example/portal"})
    end
    assert_untrusted_stripe_url do
      auth.api.cancel_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_untrusted_urls", returnUrl: "https://evil.example/cancel"})
    end
    assert_untrusted_stripe_url do
      auth.api.subscription_success(headers: {"cookie" => cookie}, query: {callbackURL: "https://evil.example/success"})
    end
    assert_untrusted_stripe_url do
      auth.api.cancel_subscription_callback(headers: {"cookie" => cookie}, query: {callbackURL: "https://evil.example/cancel", subscriptionId: "sub_untrusted_urls"})
    end

    assert_empty stripe.billing_portal.created
  end

  def test_subscription_webhooks_are_ignored_when_subscriptions_disabled
    stripe = FakeStripeClient.new
    stripe.webhooks.async_event = {
      type: "customer.subscription.created",
      data: {object: stripe_subscription(id: "sub_disabled", customer: "cus_disabled", price_id: "price_pro")}
    }
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test", subscription: {enabled: false, plans: []})
    create_user(auth, email: "disabled-webhook@example.com", stripeCustomerId: "cus_disabled")

    assert_equal({success: true}, auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: "{}"))
    assert_empty auth.context.adapter.find_many(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_disabled"}])
  end

  def test_valid_webhook_processing_errors_do_not_fail_response
    stripe = FakeStripeClient.new
    auth = build_auth(
      stripe_client: stripe,
      stripe_webhook_secret: "whsec_test",
      on_event: ->(_event) { raise "handler failed" }
    )

    assert_equal({success: true}, auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "invoice.paid"}))
  end

  def test_success_and_cancel_callbacks_do_not_mutate_another_users_subscription
    stripe = FakeStripeClient.new
    callbacks = []
    auth = build_auth(
      stripe_client: stripe,
      subscription: subscription_options.merge(on_subscription_cancel: ->(data) { callbacks << data })
    )
    owner_cookie = sign_up_cookie(auth, email: "callback-owner@example.com")
    owner = auth.api.get_session(headers: {"cookie" => owner_cookie})[:user]
    intruder_cookie = sign_up_cookie(auth, email: "callback-intruder@example.com")
    owner_subscription = auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: owner.fetch("id"),
        stripeCustomerId: "cus_owner_callback",
        stripeSubscriptionId: "sub_owner_callback",
        status: "incomplete",
        seats: 1
      }
    )
    stripe.subscriptions.list_data = [
      stripe_subscription(id: "sub_owner_callback", customer: "cus_owner_callback", price_id: "price_pro", cancel_at_period_end: true, canceled_at: 1_700_000_100)
    ]

    status, _headers, = auth.api.subscription_success(headers: {"cookie" => intruder_cookie}, query: {callbackURL: "/done", subscriptionId: owner_subscription.fetch("id")}, as_response: true)
    assert_equal 302, status
    unchanged = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: owner_subscription.fetch("id")}])
    assert_equal "incomplete", unchanged.fetch("status")
    assert_nil unchanged["periodStart"]

    status, _headers, = auth.api.cancel_subscription_callback(headers: {"cookie" => intruder_cookie}, query: {callbackURL: "/done", subscriptionId: owner_subscription.fetch("id")}, as_response: true)
    assert_equal 302, status
    unchanged = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: owner_subscription.fetch("id")}])
    refute unchanged["cancelAtPeriodEnd"]
    assert_empty callbacks
  end

  def test_restore_updates_matching_stripe_subscription
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "restore-match@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_restore_match",
        stripeSubscriptionId: "sub_restore_target",
        status: "active",
        cancelAtPeriodEnd: true,
        periodEnd: Time.now + 86_400
      }
    )
    stripe.subscriptions.list_data = [
      stripe_subscription(id: "sub_restore_other", customer: "cus_restore_match", price_id: "price_pro", cancel_at_period_end: true),
      stripe_subscription(id: "sub_restore_target", customer: "cus_restore_match", price_id: "price_pro", cancel_at_period_end: true)
    ]

    auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_restore_target"})
    assert_equal "sub_restore_target", stripe.subscriptions.updated.last.fetch(:id)
  end

  def test_restore_uses_pending_change_error_when_no_cancel_or_schedule
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "restore-no-pending@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_no_pending", stripeSubscriptionId: "sub_no_pending", status: "active"}
    )

    error = assert_raises(BetterAuth::APIError) { auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_no_pending"}) }
    assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_PENDING_CHANGE"), error.message
  end

  def test_stale_local_active_subscription_does_not_block_checkout_recovery
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "stale-active@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_stale_active")
    auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_stale_active", stripeSubscriptionId: "sub_stale_missing", status: "active", seats: 1, periodEnd: Time.now + 86_400}
    )
    stripe.subscriptions.list_data = []

    checkout = auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", successUrl: "/success", cancelUrl: "/cancel"})
    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
  end

  def test_direct_and_scheduled_upgrades_do_not_duplicate_existing_new_line_items
    stripe = FakeStripeClient.new
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [
          {name: "basic", price_id: "price_basic_base", line_items: [{price: "price_basic_events"}]},
          {name: "premium", price_id: "price_premium_base", line_items: [{price: "price_premium_events"}, {price: "price_premium_security"}]}
        ]
      }
    )
    cookie = sign_up_cookie(auth, email: "duplicate-line-items@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_duplicate_lines")
    auth.context.adapter.create(
      model: "subscription",
      data: {plan: "basic", referenceId: user.fetch("id"), stripeCustomerId: "cus_duplicate_lines", stripeSubscriptionId: "sub_duplicate_lines", status: "active", seats: 1, periodEnd: Time.now + 86_400}
    )
    current_items = [
      {id: "si_basic_base", quantity: 1, price: {id: "price_basic_base"}},
      {id: "si_basic_events", quantity: nil, price: {id: "price_basic_events"}},
      {id: "si_existing_security", quantity: nil, price: {id: "price_premium_security"}}
    ]
    stripe.subscriptions.list_data = [
      stripe_subscription(id: "sub_duplicate_lines", customer: "cus_duplicate_lines", price_id: "price_basic_base", extra_items: current_items.drop(1))
    ]

    auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "premium", successUrl: "/success", cancelUrl: "/cancel", returnUrl: "/billing"})
    direct_items = stripe.subscriptions.updated.last.fetch(:params).fetch(:items)
    assert_empty direct_items.select { |item| !item[:id] && item[:price] == "price_premium_security" }

    auth.context.adapter.update(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_duplicate_lines"}], update: {plan: "basic"})
    stripe.subscription_schedules.create_result = {
      "id" => "sched_duplicate_lines",
      "status" => "active",
      "phases" => [
        {
          "start_date" => 1_700_000_000,
          "end_date" => 1_700_086_400,
          "items" => [
            {"price" => {"id" => "price_basic_base"}, "quantity" => 1},
            {"price" => {"id" => "price_basic_events"}, "quantity" => nil},
            {"price" => {"id" => "price_premium_security"}, "quantity" => nil}
          ]
        }
      ]
    }

    auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "premium", scheduleAtPeriodEnd: true, successUrl: "/success", cancelUrl: "/cancel", returnUrl: "/billing"})
    scheduled_items = stripe.subscription_schedules.updated.last.fetch(:params).fetch(:phases).fetch(1).fetch(:items)
    assert_equal 1, scheduled_items.count { |item| item[:price] == "price_premium_security" }
  end

  private

  def build_auth(options = {})
    plugin_options = {
      subscription: subscription_options
    }.merge(options)
    plugin_options[:subscription] = subscription_options.merge(plugin_options[:subscription] || {}) if plugin_options[:subscription].is_a?(Hash)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.stripe(plugin_options)
      ]
    )
  end

  def subscription_options
    {
      enabled: true,
      plans: [
        {name: "basic", price_id: "price_basic"},
        {name: "pro", price_id: "price_pro", annual_discount_price_id: "price_pro_year", limits: {projects: 10}, free_trial: {days: 14}}
      ]
    }
  end

  def sign_up_cookie(auth, email: "billing@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Billing User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def create_user(auth, data = {})
    auth.context.internal_adapter.create_user({email: "user-#{SecureRandom.hex(4)}@example.com", name: "User", emailVerified: true}.merge(data.transform_keys(&:to_s)))
  end

  def stripe_subscription(id:, customer: "cus_test", price_id: "price_pro", lookup_key: nil, status: "active", quantity: 1, current_period_start: 1_700_000_000, current_period_end: 1_700_086_400, cancel_at_period_end: false, cancel_at: nil, canceled_at: nil, ended_at: nil, trial_start: nil, trial_end: nil, metadata: {}, schedule: nil, interval: nil, extra_items: [])
    {
      id: id,
      customer: customer,
      status: status,
      schedule: schedule,
      cancel_at_period_end: cancel_at_period_end,
      cancel_at: cancel_at,
      canceled_at: canceled_at,
      ended_at: ended_at,
      trial_start: trial_start,
      trial_end: trial_end,
      metadata: metadata,
      items: {
        data: [
          {
            id: "si_#{id}",
            quantity: quantity,
            current_period_start: current_period_start,
            current_period_end: current_period_end,
            price: {id: price_id, lookup_key: lookup_key, recurring: {interval: interval}}
          }
        ] + extra_items
      }
    }
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def assert_untrusted_stripe_url
    error = assert_raises(BetterAuth::APIError) { yield }
    assert_equal 403, error.status_code
    assert_includes error.message, "Invalid"
  end

  def rack_env(method, path, raw_body:, headers: {})
    path_info, query_string = path.split("?", 2)
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path_info,
      "QUERY_STRING" => query_string || "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(raw_body),
      "CONTENT_TYPE" => "application/json",
      "CONTENT_LENGTH" => raw_body.bytesize.to_s
    }.merge(headers)
  end

  class RawBodyWebhookVerifier
    attr_reader :payloads

    def initialize(expected_payload:, event:)
      @expected_payload = expected_payload
      @event = event
      @payloads = []
    end

    def construct_event_async(payload, signature, secret)
      payloads << payload
      raise "expected raw body string" unless payload.is_a?(String)
      raise "payload changed" unless payload == @expected_payload
      raise "invalid signature" unless signature == "valid" && secret == "whsec_test"

      @event
    end
  end

  class FakeStripeClient
    attr_reader :customers, :checkout, :billing_portal, :subscriptions, :prices, :subscription_schedules
    attr_accessor :webhooks_adapter

    def initialize
      @customers = Customers.new
      @checkout = Checkout.new
      @billing_portal = BillingPortal.new
      @subscriptions = Subscriptions.new
      @webhooks = Webhooks.new
      @prices = Prices.new
      @subscription_schedules = SubscriptionSchedules.new
    end

    def webhooks
      webhooks_adapter || @webhooks
    end

    class Customers
      attr_accessor :search_error, :search_data, :list_data, :create_error
      attr_reader :created, :list_calls, :search_calls, :retrieve_data, :updated

      def initialize
        @created = []
        @list_calls = []
        @search_calls = []
        @list_data = []
        @retrieve_data = {}
        @updated = []
      end

      def create(params)
        raise create_error if create_error

        metadata = params[:metadata] || params["metadata"] || {}
        customer = {
          "id" => "cus_#{created.length + 1}",
          "email" => params[:email],
          "name" => params[:name],
          "metadata" => metadata,
          :metadata => metadata
        }.merge(params.except(:email, :name, :metadata))
        created << customer
        customer
      end

      def search(query:, **params)
        search_calls << {query: query}.merge(params)
        raise search_error if search_error

        {"data" => search_data || []}
      end

      def list(**params)
        list_calls << params
        data = list_data.select do |customer|
          params[:email].nil? || (customer[:email] || customer["email"]) == params[:email]
        end
        {"data" => data}
      end

      def retrieve(id)
        retrieve_data[id] || {"id" => id, "deleted" => false, "name" => "Billing User"}
      end

      def update(id, params)
        updated << {id: id, params: params}
        {"id" => id}.merge(params.transform_keys(&:to_s))
      end
    end

    class Checkout
      attr_accessor :retrieve_data, :retrieve_error
      attr_reader :created, :created_options

      def initialize
        @created = []
        @created_options = []
        @retrieve_data = {}
      end

      def sessions
        self
      end

      def create(params, options = nil)
        created << params
        created_options << (options || {})
        {"id" => "cs_test", "url" => "https://stripe.test/checkout", "subscription" => "checkout-subscription", "customer" => "cus_checkout"}
      end

      def retrieve(id)
        raise retrieve_error if retrieve_error

        retrieve_data[id]
      end
    end

    class Prices
      attr_accessor :list_result
      attr_reader :list_calls
      attr_reader :retrieve_data

      def initialize
        @list_calls = []
        @retrieve_data = {}
      end

      def list(params)
        list_calls << params
        list_result || {"data" => [{"id" => "price_lookup_123"}]}
      end

      def retrieve(id)
        retrieve_data[id] || {"id" => id, "recurring" => {"usage_type" => "licensed"}}
      end
    end

    class BillingPortal
      attr_accessor :create_error
      attr_reader :created

      def initialize
        @created = []
      end

      def sessions
        self
      end

      def create(params)
        raise create_error if create_error

        created << params
        {"url" => "https://stripe.test/portal"}
      end
    end

    class SubscriptionSchedules
      attr_accessor :list_data, :create_result
      attr_reader :created, :updated, :released, :retrieve_data

      def initialize
        @created = []
        @updated = []
        @released = []
        @retrieve_data = {}
        @list_data = []
      end

      def create(params)
        created << params
        create_result || {
          "id" => "sched_1",
          "status" => "active",
          "phases" => [
            {
              "start_date" => 1_700_000_000,
              "end_date" => 1_700_086_400,
              "items" => [{"price" => "price_basic", "quantity" => 1}]
            }
          ]
        }
      end

      def update(id, params)
        updated << {id: id, params: params}
        {"id" => id}.merge(params.transform_keys(&:to_s))
      end

      def retrieve(id)
        retrieve_data[id] || {"id" => id, "status" => "active"}
      end

      def release(id)
        released << id
        {"id" => id, "status" => "released"}
      end

      def list(**_params)
        {"data" => list_data}
      end
    end

    class Subscriptions
      attr_accessor :list_data, :update_result, :update_error
      attr_reader :updated, :retrieve_data

      def initialize
        @list_data = []
        @retrieve_data = {}
        @updated = []
      end

      def update(id, params = {})
        raise update_error if update_error

        updated << {id: id, params: params}
        update_result || {"id" => id, "status" => params[:cancel_at_period_end] ? "canceled" : "active"}
      end

      def retrieve(id)
        retrieve_data[id] || {"id" => id, "status" => "active"}
      end

      def list(**params)
        data = list_data.select do |subscription|
          params[:customer].nil? || (subscription[:customer] || subscription["customer"]) == params[:customer]
        end
        {"data" => data}
      end
    end

    class Webhooks
      attr_accessor :async, :async_event
      attr_reader :constructed_async_args, :constructed_sync_args

      def construct_event(payload, signature, secret)
        @constructed_sync_args = ["payload", signature, secret]
        raise "invalid signature" unless signature == "valid" && secret == "whsec_test"

        payload
      end

      def construct_event_async(payload, signature, secret)
        @constructed_async_args = ["payload", signature, secret]
        raise "invalid signature" unless signature == "valid" && secret == "whsec_test"

        return nil if async_event == false

        async_event || payload
      end
    end
  end
end

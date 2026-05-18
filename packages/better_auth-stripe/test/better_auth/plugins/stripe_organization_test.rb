# frozen_string_literal: true

require_relative "stripe_test"

class BetterAuthPluginsStripeOrganizationTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_organization_customer_schema_rejects_missing_organization
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.stripe(
          stripe_client: BetterAuthPluginsStripeTest::FakeStripeClient.new,
          organization: {enabled: true},
          subscription: {enabled: true, plans: [{name: "team", price_id: "price_team"}], authorize_reference: ->(_data, _ctx) { true }}
        )
      ]
    )

    assert auth.context.schema.fetch("organization").fetch(:fields).key?("stripeCustomerId")
    cookie = sign_up_cookie(auth, "guard@example.com")
    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "team", customerType: "organization", referenceId: "org-1", successUrl: "http://localhost:3000/s", cancelUrl: "http://localhost:3000/c"})
    end
    assert_equal 400, error.status_code
    assert_equal "Organization not found", error.message
  end

  def test_organization_subscription_flow_uses_active_org_and_authorize_reference
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    authorizations = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          stripe_webhook_secret: "whsec_test",
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team"}],
            authorize_reference: ->(data, _ctx) {
              authorizations << [data.fetch(:reference_id), data.fetch(:action)]
              data.fetch(:reference_id) != "blocked-org"
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "org-owner@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Acme", slug: "acme"})
    auth.api.set_active_organization(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id")})
    session_cookie = cookie_header(auth.api.set_active_organization(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id")}, as_response: true)[1].fetch("set-cookie"))

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => session_cookie},
      body: {plan: "team", customerType: "organization", seats: 8, successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    updated_org = auth.context.adapter.find_one(model: "organization", where: [{field: "id", value: organization.fetch("id")}])
    assert_match(/\Acus_/, updated_org.fetch("stripeCustomerId"))
    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "referenceId", value: organization.fetch("id")}])
    assert_equal "team", subscription.fetch("plan")
    assert_equal 8, subscription.fetch("seats")
    assert_equal updated_org.fetch("stripeCustomerId"), subscription.fetch("stripeCustomerId")

    auth.context.adapter.update(
      model: "subscription",
      where: [{field: "id", value: subscription.fetch("id")}],
      update: {status: "active", stripeSubscriptionId: "sub_team"}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_team", customer: updated_org.fetch("stripeCustomerId"), price_id: "price_team")]

    portal = auth.api.create_billing_portal(headers: {"cookie" => session_cookie}, body: {customerType: "organization", returnUrl: "/billing"})
    assert_equal "https://stripe.test/portal", portal.fetch(:url)

    list = auth.api.list_active_subscriptions(headers: {"cookie" => session_cookie}, query: {customerType: "organization"})
    assert_equal [subscription.fetch("id")], list.map { |entry| entry.fetch("id") }

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_active_subscriptions(headers: {"cookie" => session_cookie}, query: {customerType: "organization", referenceId: "blocked-org"})
    end
    assert_equal "Unauthorized access", error.message
    assert_includes authorizations, [organization.fetch("id"), "upgrade-subscription"]
    assert_includes authorizations, [organization.fetch("id"), "billing-portal"]
    assert_includes authorizations, [organization.fetch("id"), "list-subscription"]
  end

  def test_organization_checkout_uses_seat_price_line_items_and_member_count
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = build_seat_auth(stripe)
    cookie = sign_up_cookie(auth, "seat-checkout@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Seat Checkout", slug: "seat-checkout"})

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "team", customerType: "organization", referenceId: organization.fetch("id"), seats: 10, successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    params = stripe.checkout.created.fetch(0)
    assert_equal [
      {price: "price_team", quantity: 1},
      {price: "price_team_seat", quantity: 1},
      {price: "price_metered_events"}
    ], params.fetch(:line_items)
    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "referenceId", value: organization.fetch("id")}])
    assert_equal 1, subscription.fetch("seats")
  end

  def test_organization_member_removal_syncs_seat_quantity
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = build_seat_auth(stripe, proration_behavior: "none")
    owner_cookie = sign_up_cookie(auth, "seat-remove-owner@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Seat Remove", slug: "seat-remove"})
    member_user = auth.context.internal_adapter.create_user(email: "seat-remove-member@example.com", name: "Member", emailVerified: true)
    member = auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), userId: member_user.fetch("id"), role: "member"})
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_seat_remove"})
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "team", referenceId: organization.fetch("id"), stripeCustomerId: "cus_seat_remove", stripeSubscriptionId: "sub_seat_remove", status: "active", seats: 2}
    )
    stripe.subscriptions.retrieve_data["sub_seat_remove"] = stripe_subscription(
      id: "sub_seat_remove",
      customer: "cus_seat_remove",
      price_id: "price_team",
      extra_items: [{id: "si_seat", quantity: 2, price: {id: "price_team_seat"}}]
    )

    auth.api.remove_member(headers: {"cookie" => owner_cookie}, body: {memberId: member.fetch("id")})

    update = stripe.subscriptions.updated.fetch(0)
    assert_equal "sub_seat_remove", update.fetch(:id)
    assert_equal [{id: "si_seat", quantity: 1}], update.fetch(:params).fetch(:items)
    assert_equal "none", update.fetch(:params).fetch(:proration_behavior)
    updated_subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal 1, updated_subscription.fetch("seats")
  end

  def test_accepting_invitation_syncs_seat_quantity
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = build_seat_auth(stripe)
    owner_cookie = sign_up_cookie(auth, "seat-invite-owner@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Seat Invite", slug: "seat-invite"})
    invited_cookie = sign_up_cookie(auth, "seat-invite-member@example.com")
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_seat_invite"})
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "team", referenceId: organization.fetch("id"), stripeCustomerId: "cus_seat_invite", stripeSubscriptionId: "sub_seat_invite", status: "active", seats: 1}
    )
    stripe.subscriptions.retrieve_data["sub_seat_invite"] = stripe_subscription(
      id: "sub_seat_invite",
      customer: "cus_seat_invite",
      price_id: "price_team",
      extra_items: [{id: "si_invite_seat", quantity: 1, price: {id: "price_team_seat"}}]
    )
    invitation = auth.context.adapter.create(
      model: "invitation",
      data: {organizationId: organization.fetch("id"), email: "seat-invite-member@example.com", role: "member", status: "pending", expiresAt: Time.now + 3600, inviterId: auth.api.get_session(headers: {"cookie" => owner_cookie})[:user].fetch("id")}
    )

    auth.api.accept_invitation(headers: {"cookie" => invited_cookie}, body: {invitationId: invitation.fetch("id")})

    update = stripe.subscriptions.updated.fetch(0)
    assert_equal [{id: "si_invite_seat", quantity: 2}], update.fetch(:params).fetch(:items)
    updated_subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal 2, updated_subscription.fetch("seats")
  end

  def test_sync_seats_uses_custom_proration_behavior
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = build_seat_auth(stripe, proration_behavior: "always_invoice")
    cookie = sign_up_cookie(auth, "seat-proration@example.com")
    organization = auth.api.create_organization(
      headers: {"cookie" => cookie},
      body: {name: "Seat Proration Org", slug: "seat-proration-org"}
    )
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_seat_proration"})
    auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "team",
        referenceId: organization.fetch("id"),
        stripeCustomerId: "cus_seat_proration",
        stripeSubscriptionId: "sub_seat_proration",
        status: "active"
      }
    )
    stripe.subscriptions.retrieve_data["sub_seat_proration"] = stripe_subscription(
      id: "sub_seat_proration",
      customer: "cus_seat_proration",
      quantity: 1,
      extra_items: [{id: "si_proration_seat", quantity: 1, price: {id: "price_team_seat"}}]
    )
    member_user = auth.context.internal_adapter.create_user(email: "seat-proration-member@example.com", name: "Member", emailVerified: true)

    auth.api.add_member(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id"), userId: member_user.fetch("id"), role: "member"})

    assert_equal "always_invoice", stripe.subscriptions.updated.fetch(0).fetch(:params).fetch(:proration_behavior)
  end

  def test_sync_seats_does_not_update_when_quantity_matches
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = build_seat_auth(stripe)
    cookie = sign_up_cookie(auth, "seat-noop@example.com")
    organization = auth.api.create_organization(
      headers: {"cookie" => cookie},
      body: {name: "Seat Noop Org", slug: "seat-noop-org"}
    )
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_seat_noop"})
    auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "team",
        referenceId: organization.fetch("id"),
        stripeCustomerId: "cus_seat_noop",
        stripeSubscriptionId: "sub_seat_noop",
        status: "active"
      }
    )
    current_member_count = auth.context.adapter.count(model: "member", where: [{field: "organizationId", value: organization.fetch("id")}])
    stripe.subscriptions.retrieve_data["sub_seat_noop"] = stripe_subscription(
      id: "sub_seat_noop",
      customer: "cus_seat_noop",
      quantity: current_member_count,
      extra_items: [{id: "si_noop_seat", quantity: current_member_count + 1, price: {id: "price_team_seat"}}]
    )
    member_user = auth.context.internal_adapter.create_user(email: "seat-noop-member@example.com", name: "Member", emailVerified: true)

    auth.api.add_member(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id"), userId: member_user.fetch("id"), role: "member"})

    assert_empty stripe.subscriptions.updated
  end

  def test_active_organization_upgrade_with_multiple_item_changes_uses_direct_subscription_update
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = build_multi_item_auth(stripe)
    cookie = sign_up_cookie(auth, "multi-upgrade@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Multi Upgrade", slug: "multi-upgrade"})
    member_user = auth.context.internal_adapter.create_user(email: "multi-member@example.com", name: "Member", emailVerified: true)
    auth.api.add_member(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id"), userId: member_user.fetch("id"), role: "member"})
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_multi_upgrade"})
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "team", referenceId: organization.fetch("id"), stripeCustomerId: "cus_multi_upgrade", stripeSubscriptionId: "sub_multi_upgrade", status: "active", seats: 2, periodEnd: Time.now + 86_400}
    )
    stripe.subscriptions.list_data = [
      stripe_subscription(
        id: "sub_multi_upgrade",
        customer: "cus_multi_upgrade",
        price_id: "price_team",
        extra_items: [
          {id: "si_old_seat", quantity: 2, price: {id: "price_team_seat"}},
          {id: "si_old_meter", price: {id: "price_old_meter"}}
        ]
      )
    ]

    result = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "enterprise", customerType: "organization", referenceId: organization.fetch("id"), returnUrl: "/billing", successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "http://localhost:3000/api/auth/billing", result.fetch(:url)
    assert_empty stripe.billing_portal.created
    update = stripe.subscriptions.updated.fetch(0)
    assert_equal "sub_multi_upgrade", update.fetch(:id)
    assert_equal "always_invoice", update.fetch(:params).fetch(:proration_behavior)
    items = update.fetch(:params).fetch(:items)
    assert_includes items, {id: "si_sub_multi_upgrade", price: "price_enterprise", quantity: 1}
    assert_includes items, {id: "si_old_seat", price: "price_enterprise_seat", quantity: 2}
    assert_includes items, {price: "price_new_meter"}
    updated_subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "enterprise", updated_subscription.fetch("plan")
    assert_equal 2, updated_subscription.fetch("seats")
  end

  def test_organization_customer_create_params_preserve_metadata_and_callback_shape
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    payloads = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {
            enabled: true,
            get_customer_create_params: ->(_org, _ctx) { {"email" => "billing@acme.test", "metadata" => {"organizationId" => "attacker", "customOrg" => "kept"}} },
            on_customer_create: ->(payload, _ctx) { payloads << payload }
          },
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team"}],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "org-metadata@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Metadata Org", slug: "metadata-org"})

    auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "team", customerType: "organization", referenceId: organization.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"}
    )

    created = stripe.customers.created.fetch(0)
    assert_equal "billing@acme.test", created.fetch("email")
    assert_equal organization.fetch("id"), created.fetch("metadata").fetch("organizationId")
    assert_equal "organization", created.fetch("metadata").fetch("customerType")
    assert_equal "kept", created.fetch("metadata").fetch("customOrg")
    assert_equal created, payloads.fetch(0).fetch(:stripeCustomer)
    assert_equal created, payloads.fetch(0).fetch(:stripe_customer)
    assert_equal organization.fetch("id"), payloads.fetch(0).fetch(:organization).fetch("id")
    assert_equal created.fetch("id"), payloads.fetch(0).fetch(:organization).fetch("stripeCustomerId")
  end

  def test_organization_customer_lookup_requires_organization_customer_type
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    org_customer_id = "cus_org_filtered"
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          stripe_webhook_secret: "whsec_test",
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team"}],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "org-customer-filter@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Filter Org", slug: "filter-org"})
    stripe.customers.search_data = [
      {"id" => "cus_wrong_user", "metadata" => {"organizationId" => organization.fetch("id"), "customerType" => "user"}}
    ]

    stripe.customers.define_singleton_method(:search) do |query:, **params|
      search_calls << {query: query}.merge(params)
      if query.include?(%(metadata["organizationId"]:"#{organization.fetch("id")})) && !query.include?(%(metadata["customerType"]:"organization"))
        {"data" => search_data}
      else
        {"data" => []}
      end
    end
    stripe.customers.define_singleton_method(:create) do |params|
      metadata = params[:metadata] || params["metadata"] || {}
      customer = {"id" => org_customer_id, "metadata" => metadata}.merge(params)
      created << customer
      customer
    end

    auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "team", customerType: "organization", referenceId: organization.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"}
    )

    updated_org = auth.context.adapter.find_one(model: "organization", where: [{field: "id", value: organization.fetch("id")}])
    assert_equal org_customer_id, updated_org.fetch("stripeCustomerId")
    assert_equal %(metadata["organizationId"]:"#{organization.fetch("id")}" AND metadata["customerType"]:"organization"), stripe.customers.search_calls.fetch(0).fetch(:query)
  end

  def test_organization_webhooks_and_delete_guard
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    deleted_callbacks = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          stripe_webhook_secret: "whsec_test",
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team"}],
            authorize_reference: ->(_data, _ctx) { true },
            on_subscription_deleted: ->(data) { deleted_callbacks << data.fetch(:subscription).fetch("id") }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "org-hooks@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Hooks", slug: "hooks"})
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_org_hooks"})

    created_event = {
      type: "customer.subscription.created",
      data: {object: stripe_subscription(id: "sub_org_created", customer: "cus_org_hooks", price_id: "price_team", status: "active")}
    }
    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: created_event)
    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_org_created"}])
    assert_equal organization.fetch("id"), subscription.fetch("referenceId")

    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_org_created", customer: "cus_org_hooks", price_id: "price_team", status: "active")]
    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_organization(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id")})
    end
    assert_equal "Cannot delete organization with active subscription", error.message

    deleted_event = {
      type: "customer.subscription.deleted",
      data: {object: stripe_subscription(id: "sub_org_created", customer: "cus_org_hooks", price_id: "price_team", status: "canceled", ended_at: 1_700_000_000)}
    }
    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: deleted_event)
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_org_created", customer: "cus_org_hooks", price_id: "price_team", status: "canceled")]
    assert_equal({status: true}, auth.api.delete_organization(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id")}))
    assert_equal [subscription.fetch("id")], deleted_callbacks
  end

  def test_organization_existing_customer_id_cancel_restore_and_cross_org_guards
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team"}],
            authorize_reference: ->(data, _ctx) { data.fetch(:reference_id) != "blocked-org" }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "org-existing-flow@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Existing Org", slug: "existing-org"})
    other_organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Other Org", slug: "other-org"})
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_existing_org"})

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "team", customerType: "organization", referenceId: organization.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"}
    )
    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    assert_empty stripe.customers.created
    assert_equal "cus_existing_org", stripe.checkout.created.fetch(0).fetch(:customer)

    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "referenceId", value: organization.fetch("id")}])
    auth.context.adapter.update(
      model: "subscription",
      where: [{field: "id", value: subscription.fetch("id")}],
      update: {status: "active", stripeSubscriptionId: "sub_org_existing"}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_org_existing", customer: "cus_existing_org", price_id: "price_team", status: "active")]

    cancel = auth.api.cancel_subscription(headers: {"cookie" => cookie}, body: {customerType: "organization", referenceId: organization.fetch("id"), subscriptionId: "sub_org_existing", returnUrl: "/billing"})
    assert_equal "https://stripe.test/portal", cancel.fetch(:url)

    auth.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {cancelAtPeriodEnd: true})
    stripe.subscriptions.update_result = stripe_subscription(id: "sub_org_existing", customer: "cus_existing_org", price_id: "price_team", status: "active")
    restored = auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {customerType: "organization", referenceId: organization.fetch("id"), subscriptionId: "sub_org_existing"})
    assert_equal "sub_org_existing", restored.fetch(:id)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.cancel_subscription(headers: {"cookie" => cookie}, body: {customerType: "organization", referenceId: other_organization.fetch("id"), subscriptionId: "sub_org_existing", returnUrl: "/billing"})
    end
    assert_equal "Subscription not found", error.message

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_active_subscriptions(headers: {"cookie" => cookie}, query: {customerType: "organization", referenceId: "blocked-org"})
    end
    assert_equal "Unauthorized access", error.message
  end

  def test_organization_authorize_reference_required_and_user_org_subscriptions_are_separate
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth_without_authorizer = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {enabled: true, plans: [{name: "team", price_id: "price_team"}]}
        )
      ]
    )
    cookie = sign_up_cookie(auth_without_authorizer, "org-authorizer-required@example.com")
    organization = auth_without_authorizer.api.create_organization(headers: {"cookie" => cookie}, body: {name: "No Authorizer", slug: "no-authorizer"})
    error = assert_raises(BetterAuth::APIError) do
      auth_without_authorizer.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "team", customerType: "organization", referenceId: organization.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"})
    end
    assert_equal "Organization subscriptions require authorizeReference callback to be configured", error.message

    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "pro", price_id: "price_pro"}, {name: "team", price_id: "price_team"}],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "separate-user-org@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Separate", slug: "separate"})

    auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", successUrl: "/success", cancelUrl: "/cancel"})
    auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "team", customerType: "organization", referenceId: organization.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"})

    user_subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "referenceId", value: user.fetch("id")}])
    organization_subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "referenceId", value: organization.fetch("id")}])
    refute_nil user_subscription
    refute_nil organization_subscription
    assert_equal "pro", user_subscription.fetch("plan")
    assert_equal "team", organization_subscription.fetch("plan")
  end

  def test_organization_webhook_update_cancel_callbacks_and_customer_errors
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    callbacks = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          stripe_webhook_secret: "whsec_test",
          organization: {
            enabled: true,
            get_customer_create_params: ->(org, _ctx) {
              raise "boom" if org.fetch("slug") == "broken-org"

              {metadata: {organizationId: "attacker"}}
            }
          },
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team", seat_price_id: "price_team_seat"}],
            authorize_reference: ->(_data, _ctx) { true },
            on_subscription_created: ->(data) { callbacks << [:created, data.fetch(:subscription).fetch("referenceId")] },
            on_subscription_update: ->(data) { callbacks << [:updated, data.fetch(:subscription).fetch("status")] },
            on_subscription_cancel: ->(data) { callbacks << [:cancel, data.fetch(:subscription).fetch("id")] },
            on_subscription_deleted: ->(data) { callbacks << [:deleted, data.fetch(:subscription).fetch("id")] }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "org-webhook-update@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Webhook Org", slug: "webhook-org"})
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_org_webhook"})

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "customer.subscription.created", data: {object: stripe_subscription(id: "sub_org_webhook", customer: "cus_org_webhook", price_id: "price_team", status: "active", extra_items: [{id: "si_org_seat", quantity: 3, price: {id: "price_team_seat"}}])}})
    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_org_webhook"}])
    assert_equal organization.fetch("id"), subscription.fetch("referenceId")
    assert_equal 3, subscription.fetch("seats")

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "customer.subscription.updated", data: {object: stripe_subscription(id: "sub_org_webhook", customer: "cus_org_webhook", price_id: "price_team", status: "active", cancel_at_period_end: true, canceled_at: 1_700_000_200, extra_items: [{id: "si_org_seat", quantity: 4, price: {id: "price_team_seat"}}])}})
    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal true, updated.fetch("cancelAtPeriodEnd")
    assert_equal 4, updated.fetch("seats")

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "customer.subscription.deleted", data: {object: stripe_subscription(id: "sub_org_webhook", customer: "cus_org_webhook", price_id: "price_team", status: "canceled", ended_at: 1_700_000_300)}})
    deleted = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "canceled", deleted.fetch("status")
    assert deleted.fetch("endedAt")
    assert_includes callbacks, [:created, organization.fetch("id")]
    assert_includes callbacks, [:updated, "active"]
    assert_includes callbacks, [:cancel, subscription.fetch("id")]
    assert_includes callbacks, [:deleted, subscription.fetch("id")]

    broken = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Broken Org", slug: "broken-org"})
    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "team", customerType: "organization", referenceId: broken.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"})
    end
    assert_equal "Unable to create customer", error.message

    stripe.customers.create_error = RuntimeError.new("stripe unavailable")
    failed = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Failed Customer", slug: "failed-customer"})
    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "team", customerType: "organization", referenceId: failed.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"})
    end
    assert_equal "Unable to create customer", error.message
  end

  def test_organization_name_sync_and_deletion_without_active_subscription
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team"}],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "org-name-sync@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Old Name", slug: "old-name"})
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_org_name"})
    stripe.customers.retrieve_data["cus_org_name"] = {"id" => "cus_org_name", "name" => "Old Name", "deleted" => false}

    auth.api.update_organization(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id"), data: {name: "New Name"}})
    assert_equal({id: "cus_org_name", params: {name: "New Name"}}, stripe.customers.updated.last)

    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_canceled", customer: "cus_org_name", price_id: "price_team", status: "canceled")]
    assert_equal({status: true}, auth.api.delete_organization(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id")}))
  end

  def test_seat_billing_checkout_edge_cases_and_webhook_seat_count
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          stripe_webhook_secret: "whsec_test",
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [
              {name: "team", price_id: "price_team", seat_price_id: "price_team_seat"},
              {name: "seat-only", price_id: "price_seat_only", seat_price_id: "price_seat_only"},
              {name: "same-seat", price_id: "price_same_seat", seat_price_id: "price_team_seat"}
            ],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "seat-edge@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Seat Edge", slug: "seat-edge"})
    member_user = auth.context.internal_adapter.create_user(email: "seat-edge-member@example.com", name: "Member", emailVerified: true)
    auth.api.add_member(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id"), userId: member_user.fetch("id"), role: "member"})

    auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "team", customerType: "organization", referenceId: organization.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"})
    line_items = stripe.checkout.created.last.fetch(:line_items)
    assert_equal [{price: "price_team", quantity: 1}, {price: "price_team_seat", quantity: 2}], line_items
    assert_equal 2, auth.context.adapter.find_one(model: "subscription", where: [{field: "referenceId", value: organization.fetch("id")}]).fetch("seats")

    other_org = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Seat Only", slug: "seat-only"})
    auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "seat-only", customerType: "organization", referenceId: other_org.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"})
    assert_equal [{price: "price_seat_only", quantity: 1}], stripe.checkout.created.last.fetch(:line_items)

    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_seat_edge"})
    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "referenceId", value: organization.fetch("id")}])
    auth.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {status: "active", stripeCustomerId: "cus_seat_edge", stripeSubscriptionId: "sub_seat_edge", plan: "team", seats: 2})
    stripe.subscriptions.list_data = [
      stripe_subscription(
        id: "sub_seat_edge",
        customer: "cus_seat_edge",
        price_id: "price_team",
        extra_items: [{id: "si_team_seat", quantity: 2, price: {id: "price_team_seat"}}]
      )
    ]

    auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "same-seat", customerType: "organization", referenceId: organization.fetch("id"), returnUrl: "/billing", successUrl: "/success", cancelUrl: "/cancel"})
    items = stripe.billing_portal.created.last.dig(:flow_data, :subscription_update_confirm, :items)
    assert_equal 1, items.length
    assert_equal "si_sub_seat_edge", items.fetch(0).fetch(:id)
    assert_equal "price_same_seat", items.fetch(0).fetch(:price)

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "customer.subscription.updated", data: {object: stripe_subscription(id: "sub_seat_edge", customer: "cus_seat_edge", price_id: "price_same_seat", status: "active", extra_items: [{id: "si_team_seat", quantity: 5, price: {id: "price_team_seat"}}])}})
    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_seat_edge"}])
    assert_equal 5, updated.fetch("seats")
  end

  def test_seat_only_plan_does_not_duplicate_base_price
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team_seat", seat_price_id: "price_team_seat"}],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "seat-only@example.com")
    organization = auth.api.create_organization(
      headers: {"cookie" => cookie},
      body: {name: "Seat Only Org", slug: "seat-only-org"}
    )

    auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {
        plan: "team",
        customerType: "organization",
        referenceId: organization.fetch("id"),
        successUrl: "/success",
        cancelUrl: "/cancel"
      }
    )

    line_items = stripe.checkout.created.fetch(0).fetch(:line_items)
    prices = line_items.map { |item| item.fetch(:price) }
    assert_equal prices.uniq, prices
  end

  def test_active_seat_only_upgrade_does_not_duplicate_subscription_item
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [
              {name: "starter", price_id: "price_starter_seat", seat_price_id: "price_starter_seat"},
              {name: "team", price_id: "price_team_seat", seat_price_id: "price_team_seat"}
            ],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "seat-only-active@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Seat Only Active", slug: "seat-only-active"})
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_seat_only_active"})
    auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "starter",
        referenceId: organization.fetch("id"),
        stripeCustomerId: "cus_seat_only_active",
        stripeSubscriptionId: "sub_seat_only_active",
        status: "active",
        seats: 1,
        periodEnd: Time.now + 86_400
      }
    )
    stripe.subscriptions.list_data = [
      stripe_subscription(id: "sub_seat_only_active", customer: "cus_seat_only_active", price_id: "price_starter_seat", quantity: 1)
    ]

    auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {
        plan: "team",
        customerType: "organization",
        referenceId: organization.fetch("id"),
        returnUrl: "/billing",
        successUrl: "/success",
        cancelUrl: "/cancel"
      }
    )

    items = stripe.subscriptions.updated.last.fetch(:params).fetch(:items)
    assert_equal 1, items.count { |item| item[:price] == "price_team_seat" }
  end

  def test_metered_seat_upgrade_keeps_quantity_only_for_seat_item
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    stripe.prices.retrieve_data["price_metered"] = {"id" => "price_metered", "recurring" => {"usage_type" => "metered"}}
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_metered", seat_price_id: "price_team_seat"}],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "metered-seat@example.com")
    organization = auth.api.create_organization(
      headers: {"cookie" => cookie},
      body: {name: "Metered Seat Org", slug: "metered-seat-org"}
    )

    auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {
        plan: "team",
        customerType: "organization",
        referenceId: organization.fetch("id"),
        successUrl: "/success",
        cancelUrl: "/cancel"
      }
    )

    line_items = stripe.checkout.created.fetch(0).fetch(:line_items)
    base_item = line_items.find { |item| item.fetch(:price) == "price_metered" }
    seat_item = line_items.find { |item| item.fetch(:price) == "price_team_seat" }
    refute base_item.key?(:quantity)
    assert_operator seat_item.fetch(:quantity), :>=, 1
  end

  def test_organization_reference_requires_reference_id_or_active_organization_id
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: BetterAuthPluginsStripeTest::FakeStripeClient.new,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team"}],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "missing-org-reference@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "team", customerType: "organization", successUrl: "/success", cancelUrl: "/cancel"})
    end

    assert_equal "Reference ID is required. Provide referenceId or set activeOrganizationId in session", error.message
  end

  private

  def build_seat_auth(stripe, proration_behavior: nil)
    plan = {
      name: "team",
      price_id: "price_team",
      seat_price_id: "price_team_seat",
      line_items: [{price: "price_metered_events"}]
    }
    plan[:proration_behavior] = proration_behavior if proration_behavior
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [plan],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
  end

  def build_multi_item_auth(stripe)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [
              {name: "team", price_id: "price_team", seat_price_id: "price_team_seat", line_items: [{price: "price_old_meter"}]},
              {name: "enterprise", price_id: "price_enterprise", seat_price_id: "price_enterprise_seat", line_items: [{price: "price_new_meter"}], proration_behavior: "always_invoice"}
            ],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
  end

  def sign_up_cookie(auth, email)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Org Owner"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def stripe_subscription(id:, customer: "cus_test", price_id: "price_team", lookup_key: nil, status: "active", quantity: 1, current_period_start: 1_700_000_000, current_period_end: 1_700_086_400, cancel_at_period_end: false, cancel_at: nil, canceled_at: nil, ended_at: nil, trial_start: nil, trial_end: nil, metadata: {}, extra_items: [])
    {
      id: id,
      customer: customer,
      status: status,
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
            price: {id: price_id, lookup_key: lookup_key}
          }
        ] + extra_items
      }
    }
  end
end

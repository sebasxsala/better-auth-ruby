# frozen_string_literal: true

module BetterAuth
  module Plugins
    singleton_class.remove_method(:stripe) if singleton_class.method_defined?(:stripe)
    remove_method(:stripe) if method_defined?(:stripe) || private_method_defined?(:stripe)
    remove_const(:STRIPE_ERROR_CODES) if const_defined?(:STRIPE_ERROR_CODES, false)

    module_function

    STRIPE_ERROR_CODES = BetterAuth::Stripe::ERROR_CODES
    STRIPE_UNSAFE_METADATA_KEYS = BetterAuth::Stripe::Metadata::UNSAFE_KEYS

    def stripe(options = {})
      BetterAuth::Stripe::PluginFactory.build(options)
    end

    def stripe_schema(config)
      BetterAuth::Stripe::Schema.schema(config)
    end

    def stripe_endpoints(config)
      BetterAuth::Stripe::Routes.endpoints(config)
    end

    def stripe_database_hooks(config)
      BetterAuth::Stripe::PluginFactory.database_hooks(config)
    end

    def stripe_organization_hooks(config)
      BetterAuth::Stripe::OrganizationHooks.hooks(config)
    end

    def stripe_upgrade_subscription_endpoint(config)
      BetterAuth::Stripe::Routes::UpgradeSubscription.endpoint(config)
    end

    def stripe_cancel_subscription_endpoint(config)
      BetterAuth::Stripe::Routes::CancelSubscription.endpoint(config)
    end

    def stripe_restore_subscription_endpoint(config)
      BetterAuth::Stripe::Routes::RestoreSubscription.endpoint(config)
    end

    def stripe_list_subscriptions_endpoint(config)
      BetterAuth::Stripe::Routes::ListActiveSubscriptions.endpoint(config)
    end

    def stripe_billing_portal_endpoint(config)
      BetterAuth::Stripe::Routes::CreateBillingPortal.endpoint(config)
    end

    def stripe_cancel_callback_endpoint(config)
      BetterAuth::Stripe::Routes::CancelSubscriptionCallback.endpoint(config)
    end

    def stripe_success_endpoint(config)
      BetterAuth::Stripe::Routes::SubscriptionSuccess.endpoint(config)
    end

    def stripe_webhook_endpoint(config)
      BetterAuth::Stripe::Routes::StripeWebhook.endpoint(config)
    end

    def stripe_handle_event(ctx, event)
      BetterAuth::Stripe::Hooks.handle_event(ctx, event)
    end

    def stripe_on_checkout_completed(ctx, event)
      BetterAuth::Stripe::Hooks.on_checkout_completed(ctx, event)
    end

    def stripe_on_subscription_created(ctx, event)
      BetterAuth::Stripe::Hooks.on_subscription_created(ctx, event)
    end

    def stripe_on_subscription_updated(ctx, event)
      BetterAuth::Stripe::Hooks.on_subscription_updated(ctx, event)
    end

    def stripe_on_subscription_deleted(ctx, event)
      BetterAuth::Stripe::Hooks.on_subscription_deleted(ctx, event)
    end

    def stripe_create_customer(config, ctx, user, metadata = nil)
      customer = stripe_find_or_create_user_customer(config, user, metadata, ctx)
      id = stripe_id(customer)
      ctx.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: id)
      id
    end

    def stripe_find_or_create_user_customer(config, user, metadata = nil, ctx = nil)
      customer = stripe_find_user_customer(config, user["email"])
      if customer
        stripe_notify_customer_created(config, customer, user, ctx)
        return customer
      end

      raw_extra = config[:get_customer_create_params]&.call(user, ctx) || {}
      extra_metadata = stripe_fetch(raw_extra, "metadata")
      extra = normalize_hash(raw_extra)
      params = stripe_deep_merge(
        extra,
        email: user["email"],
        name: user["name"],
        metadata: stripe_customer_metadata_set({userId: user["id"], customerType: "user"}, metadata, extra_metadata)
      )
      params[:metadata] = stripe_customer_metadata_set({userId: user["id"], customerType: "user"}, metadata, extra_metadata)
      customer = stripe_client(config).customers.create(params)
      stripe_notify_customer_created(config, customer, user, ctx)
      customer
    end

    def stripe_organization_customer(config, ctx, organization_id, metadata = nil)
      raise APIError.new("BAD_REQUEST", message: "Organization integration requires the organization plugin") unless config.dig(:organization, :enabled)

      org = ctx.context.adapter.find_one(model: "organization", where: [{field: "id", value: organization_id}])
      raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("ORGANIZATION_NOT_FOUND")) unless org
      return org["stripeCustomerId"] if org["stripeCustomerId"]

      customer = stripe_find_organization_customer(config, org["id"])
      unless customer
        raw_extra = config.dig(:organization, :get_customer_create_params)&.call(org, ctx) || {}
        extra_metadata = stripe_fetch(raw_extra, "metadata")
        extra = normalize_hash(raw_extra)
        params = stripe_deep_merge(
          extra,
          name: org["name"],
          metadata: stripe_customer_metadata_set({organizationId: org["id"], customerType: "organization"}, metadata, extra_metadata)
        )
        params[:metadata] = stripe_customer_metadata_set({organizationId: org["id"], customerType: "organization"}, metadata, extra_metadata)
        customer = stripe_client(config).customers.create(params)
        config.dig(:organization, :on_customer_create)&.call({stripeCustomer: customer, stripe_customer: customer, organization: org.merge("stripeCustomerId" => stripe_id(customer))}, ctx)
      end
      ctx.context.adapter.update(model: "organization", where: [{field: "id", value: org.fetch("id")}], update: {stripeCustomerId: stripe_id(customer)})
      stripe_id(customer)
    rescue APIError
      raise
    rescue
      raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("UNABLE_TO_CREATE_CUSTOMER"))
    end

    def stripe_client(config)
      injected = config[:stripe_client] || config[:client]
      return injected if injected
      return config[:_stripe_client_adapter] if config[:_stripe_client_adapter]

      api_key = config[:stripe_api_key] || ENV["STRIPE_SECRET_KEY"]
      raise APIError.new("INTERNAL_SERVER_ERROR", message: "Stripe client is required") if api_key.to_s.empty?

      config[:_stripe_client_adapter] = BetterAuth::Stripe::ClientAdapter.new(api_key)
    end

    def stripe_id(object)
      BetterAuth::Stripe::Utils.id(object)
    end

    def stripe_fetch(object, key)
      BetterAuth::Stripe::Utils.fetch(object, key)
    end

    def stripe_time(value)
      BetterAuth::Stripe::Utils.time(value)
    end

    def stripe_subscription_options(config)
      BetterAuth::Stripe::Utils.subscription_options(config)
    end

    def stripe_plans(config)
      BetterAuth::Stripe::Utils.plans(config)
    end

    def stripe_plan_by_name(config, name)
      BetterAuth::Stripe::Utils.plan_by_name(config, name)
    end

    def stripe_plan_by_price_info(config, price_id, lookup_key = nil)
      BetterAuth::Stripe::Utils.plan_by_price_info(config, price_id, lookup_key)
    end

    def stripe_price_id(config, plan, annual = false)
      BetterAuth::Stripe::Utils.price_id(config, plan, annual)
    end

    def stripe_resolve_lookup(config, lookup_key)
      BetterAuth::Stripe::Utils.resolve_lookup(config, lookup_key)
    end

    def stripe_reference_id!(ctx, session, customer_type, explicit_reference_id, config)
      BetterAuth::Stripe::Middleware.reference_id!(ctx, session, customer_type, explicit_reference_id, config)
    end

    def stripe_authorize_reference!(ctx, session, reference_id, action, customer_type, subscription_options, explicit: false)
      BetterAuth::Stripe::Middleware.authorize_reference!(ctx, session, reference_id, action, customer_type, subscription_options, explicit: explicit)
    end

    def stripe_customer_type!(source)
      BetterAuth::Stripe::Middleware.customer_type!(source)
    end

    def stripe_find_user_customer(config, email)
      customers = stripe_client(config).customers
      begin
        existing = customers.search(query: "email:\"#{stripe_escape_search(email)}\" AND -metadata[\"customerType\"]:\"organization\"", limit: 1)
        Array(stripe_fetch(existing, "data")).first
      rescue
        listed = customers.list(email: email, limit: 100)
        Array(stripe_fetch(listed, "data")).find do |customer|
          stripe_metadata_fetch(stripe_fetch(customer, "metadata") || {}, "customerType") != "organization"
        end
      end
    end

    def stripe_find_organization_customer(config, organization_id)
      customers = stripe_client(config).customers
      begin
        existing = customers.search(query: "metadata[\"organizationId\"]:\"#{stripe_escape_search(organization_id)}\" AND metadata[\"customerType\"]:\"organization\"", limit: 1)
        Array(stripe_fetch(existing, "data")).first
      rescue
        listed = customers.list(limit: 100)
        Array(stripe_fetch(listed, "data")).find do |customer|
          metadata = stripe_fetch(customer, "metadata") || {}
          stripe_metadata_fetch(metadata, "organizationId") == organization_id &&
            stripe_metadata_fetch(metadata, "customerType") == "organization"
        end
      end
    end

    def stripe_find_subscription_for_action(ctx, reference_id, subscription_id, active_only:)
      subscription = if subscription_id
        ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: subscription_id}])
      else
        ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}]).find { |entry| !active_only || stripe_active_or_trialing?(entry) }
      end
      return nil if subscription_id && subscription && subscription["referenceId"] != reference_id

      subscription
    end

    def stripe_active_subscription(ctx, reference_id)
      ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}]).find { |entry| stripe_active_or_trialing?(entry) }
    end

    def stripe_active_subscriptions(config, customer_id)
      result = stripe_client(config).subscriptions.list(customer: customer_id)
      Array(stripe_fetch(result, "data")).select { |entry| stripe_active_or_trialing?(entry) }
    end

    def stripe_active_or_trialing?(subscription)
      BetterAuth::Stripe::Utils.active_or_trialing?(subscription)
    end

    def stripe_pending_cancel?(subscription)
      BetterAuth::Stripe::Utils.pending_cancel?(subscription)
    end

    def stripe_stripe_pending_cancel?(subscription)
      BetterAuth::Stripe::Utils.stripe_pending_cancel?(subscription)
    end

    def stripe_subscription_item(subscription)
      BetterAuth::Stripe::Utils.subscription_item(subscription)
    end

    def stripe_resolve_plan_item(config, subscription)
      BetterAuth::Stripe::Utils.resolve_plan_item(config, subscription)
    end

    def stripe_resolve_quantity(subscription, plan_item, plan = nil)
      BetterAuth::Stripe::Utils.resolve_quantity(subscription, plan_item, plan)
    end

    def stripe_line_item(config, price_id, quantity)
      BetterAuth::Stripe::Utils.line_item(config, price_id, quantity)
    end

    def stripe_checkout_line_items(config, plan, price_id, quantity, auto_managed_seats, seat_only_plan)
      BetterAuth::Stripe::Utils.checkout_line_items(config, plan, price_id, quantity, auto_managed_seats, seat_only_plan)
    end

    def stripe_plan_line_items(plan)
      BetterAuth::Stripe::Utils.plan_line_items(plan)
    end

    def stripe_line_item_delta(old_plan, plan)
      delta = Hash.new(0)
      stripe_plan_line_items(old_plan || {}).each do |item|
        price = stripe_fetch(item, "price")
        delta[price] -= 1 if price
      end
      stripe_plan_line_items(plan || {}).each do |item|
        price = stripe_fetch(item, "price")
        delta[price] += 1 if price
      end
      delta.delete_if { |_price, count| count == 0 }
    end

    def stripe_remove_quota(line_item_delta)
      line_item_delta.each_with_object({}) do |(price, delta), result|
        result[price] = -delta if delta.negative?
      end
    end

    def stripe_consume_positive_delta(line_item_delta, price)
      delta = line_item_delta[price]
      return unless delta&.positive?

      (delta == 1) ? line_item_delta.delete(price) : line_item_delta[price] = delta - 1
    end

    def stripe_schedule_plan_change(ctx, config, active_stripe, db_subscription, plan, price_id, quantity, seat_only_plan, body)
      schedule = stripe_client(config).subscription_schedules.create(from_subscription: stripe_fetch(active_stripe, "id"))
      current_phase = Array(stripe_fetch(schedule, "phases")).first || {}
      current_items = Array(stripe_fetch(current_phase, "items"))
      active_item = stripe_resolve_plan_item(config, active_stripe)&.fetch(:item, nil) || stripe_subscription_item(active_stripe)
      active_price_id = stripe_fetch(stripe_fetch(active_item || {}, "price") || {}, "id")
      active_price_present = current_items.any? do |item|
        item_price = stripe_fetch(item, "price")
        item_price = stripe_fetch(item_price, "id") if item_price.is_a?(Hash)
        item_price == active_price_id
      end
      old_plan = db_subscription && stripe_plan_by_name(config, db_subscription["plan"])
      line_item_delta = stripe_line_item_delta(old_plan, plan)
      remove_quota = stripe_remove_quota(line_item_delta)
      price_map = {}
      if plan[:seat_price_id] && old_plan && old_plan[:seat_price_id] && old_plan[:seat_price_id] != plan[:seat_price_id]
        price_map[old_plan[:seat_price_id]] = {price: plan[:seat_price_id], quantity: quantity}
      end
      new_items = current_items.filter_map do |item|
        item_price = stripe_fetch(item, "price")
        item_price = stripe_fetch(item_price, "id") if item_price.is_a?(Hash)
        quota = remove_quota[item_price].to_i
        if quota.positive?
          remove_quota[item_price] = quota - 1
          next nil
        end

        replacement = price_map[item_price]
        if replacement
          next {price: replacement[:price], quantity: replacement[:quantity] || stripe_fetch(item, "quantity")}.compact
        end

        if item_price == active_price_id
          next nil if seat_only_plan

          stripe_line_item(config, price_id, plan[:seat_price_id] ? 1 : quantity)
        else
          stripe_consume_positive_delta(line_item_delta, item_price)
          {price: item_price, quantity: stripe_fetch(item, "quantity")}.compact
        end
      end
      new_items << stripe_line_item(config, price_id, plan[:seat_price_id] ? 1 : quantity) unless active_price_present || seat_only_plan
      new_items << {price: plan[:seat_price_id], quantity: quantity} if plan[:seat_price_id] && !new_items.any? { |item| item[:price] == plan[:seat_price_id] }
      line_item_delta.each do |price, delta|
        delta.times { new_items << {price: price} } if delta.positive?
      end

      stripe_client(config).subscription_schedules.update(
        stripe_fetch(schedule, "id"),
        metadata: {source: "@better-auth/stripe"},
        end_behavior: "release",
        phases: [
          {
            items: current_items.map do |item|
              item_price = stripe_fetch(item, "price")
              item_price = stripe_fetch(item_price, "id") if item_price.is_a?(Hash)
              {price: item_price, quantity: stripe_fetch(item, "quantity")}.compact
            end,
            start_date: stripe_fetch(current_phase, "start_date"),
            end_date: stripe_fetch(current_phase, "end_date")
          },
          {
            items: new_items,
            start_date: stripe_fetch(current_phase, "end_date"),
            proration_behavior: "none"
          }
        ]
      )
      if db_subscription
        ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: db_subscription.fetch("id")}], update: {stripeScheduleId: stripe_fetch(schedule, "id")})
      end
      stripe_url(ctx, body[:return_url] || "/")
    end

    def stripe_release_plugin_schedule(ctx, config, customer_id, active_stripe, db_subscription)
      return unless stripe_schedule_id(active_stripe)
      return unless stripe_client(config).respond_to?(:subscription_schedules)

      schedules = stripe_client(config).subscription_schedules.list(customer: customer_id)
      active_subscription_id = stripe_fetch(active_stripe, "id")
      existing = Array(stripe_fetch(schedules, "data")).find do |schedule|
        subscription = stripe_fetch(schedule, "subscription")
        schedule_subscription_id = subscription.is_a?(Hash) ? stripe_id(subscription) : subscription
        metadata = stripe_fetch(schedule, "metadata") || {}
        schedule_subscription_id == active_subscription_id &&
          stripe_fetch(schedule, "status") == "active" &&
          stripe_metadata_fetch(metadata, "source") == "@better-auth/stripe"
      end
      return unless existing

      stripe_client(config).subscription_schedules.release(stripe_id(existing))
      if db_subscription
        ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: db_subscription.fetch("id")}], update: {stripeScheduleId: nil})
      end
    end

    def stripe_direct_subscription_update?(old_plan, plan, auto_managed_seats)
      BetterAuth::Stripe::Utils.direct_subscription_update?(old_plan, plan, auto_managed_seats)
    end

    def stripe_update_active_subscription_items(ctx, config, active_stripe, db_subscription, old_plan, plan, price_id, quantity, seat_only_plan, body)
      active_item = stripe_resolve_plan_item(config, active_stripe)&.fetch(:item, nil) || stripe_subscription_item(active_stripe)
      active_price_id = stripe_fetch(stripe_fetch(active_item || {}, "price") || {}, "id")
      line_item_delta = stripe_line_item_delta(old_plan, plan)
      remove_quota = stripe_remove_quota(line_item_delta)
      price_map = {}
      if plan[:seat_price_id] && old_plan && old_plan[:seat_price_id] && old_plan[:seat_price_id] != plan[:seat_price_id]
        price_map[old_plan[:seat_price_id]] = {price: plan[:seat_price_id], quantity: quantity}
      end
      items = []
      Array(stripe_fetch(stripe_fetch(active_stripe, "items") || {}, "data")).each do |item|
        item_price = stripe_fetch(stripe_fetch(item, "price") || {}, "id")
        quota = remove_quota[item_price].to_i
        if quota.positive?
          remove_quota[item_price] = quota - 1
          items << {id: stripe_fetch(item, "id"), deleted: true}
        elsif price_map[item_price]
          replacement = price_map[item_price]
          items << {id: stripe_fetch(item, "id"), price: replacement[:price], quantity: replacement[:quantity]}
        elsif item_price == active_price_id
          items << stripe_line_item(config, price_id, plan[:seat_price_id] ? 1 : quantity).merge(id: stripe_fetch(item, "id")) unless seat_only_plan
        else
          stripe_consume_positive_delta(line_item_delta, item_price)
        end
      end
      items << {price: plan[:seat_price_id], quantity: quantity} if plan[:seat_price_id] && !items.any? { |item| item[:price] == plan[:seat_price_id] || item[:id] && item[:price] == plan[:seat_price_id] }
      line_item_delta.each do |price, delta|
        delta.times { items << {price: price} } if delta.positive?
      end
      stripe_client(config).subscriptions.update(stripe_fetch(active_stripe, "id"), items: items, proration_behavior: plan[:proration_behavior] || "create_prorations")
      if db_subscription
        ctx.context.adapter.update(
          model: "subscription",
          where: [{field: "id", value: db_subscription.fetch("id")}],
          update: {plan: plan[:name].to_s.downcase, seats: quantity, limits: plan[:limits], stripeScheduleId: nil}
        )
      end
      stripe_url(ctx, body[:return_url] || "/")
    end

    def stripe_sync_organization_seats(config, data, ctx)
      BetterAuth::Stripe::OrganizationHooks.sync_seats(config, data, ctx)
    end

    def stripe_metered_price?(config, price_id, lookup_key = nil)
      BetterAuth::Stripe::Utils.metered_price?(config, price_id, lookup_key)
    end

    def stripe_resolve_stripe_price(config, price_id, lookup_key = nil)
      BetterAuth::Stripe::Utils.resolve_stripe_price(config, price_id, lookup_key)
    end

    def stripe_subscription_state(subscription, include_status: true, compact: true)
      BetterAuth::Stripe::Utils.subscription_state(subscription, include_status: include_status, compact: compact)
    end

    def stripe_schedule_id(subscription)
      BetterAuth::Stripe::Utils.schedule_id(subscription)
    end

    def stripe_reference_by_customer(ctx, config, customer_id)
      BetterAuth::Stripe::Middleware.reference_by_customer(ctx, config, customer_id)
    end

    def stripe_metadata(internal, *user_metadata)
      BetterAuth::Stripe::Metadata.merge(internal, *user_metadata)
    end

    def stripe_customer_metadata_set(internal_fields, *user_metadata)
      BetterAuth::Stripe::Metadata.customer_set(internal_fields, *user_metadata)
    end

    def stripe_customer_metadata_get(metadata)
      BetterAuth::Stripe::Metadata.customer_get(metadata)
    end

    def stripe_subscription_metadata_set(internal_fields, *user_metadata)
      BetterAuth::Stripe::Metadata.subscription_set(internal_fields, *user_metadata)
    end

    def stripe_subscription_metadata_get(metadata)
      BetterAuth::Stripe::Metadata.subscription_get(metadata)
    end

    def stripe_notify_customer_created(config, customer, user, ctx)
      config[:on_customer_create]&.call(
        {
          stripeCustomer: customer,
          stripe_customer: customer,
          user: user.merge("stripeCustomerId" => stripe_id(customer))
        },
        ctx
      )
    end

    def stripe_metadata_key(key)
      BetterAuth::Stripe::Metadata.metadata_key(key)
    end

    def stripe_metadata_fetch(metadata, key)
      BetterAuth::Stripe::Metadata.metadata_fetch(metadata, key)
    end

    def stripe_deep_merge(base, override)
      BetterAuth::Stripe::Metadata.deep_merge(base, override)
    end

    def stripe_redirect?(body)
      BetterAuth::Stripe::Utils.redirect?(body)
    end

    def stripe_stringify_keys(value)
      BetterAuth::Stripe::Metadata.stringify_keys(value)
    end

    def stripe_url(ctx, url)
      BetterAuth::Stripe::Utils.url(ctx, url)
    end

    def stripe_escape_search(value)
      BetterAuth::Stripe::Utils.escape_search(value)
    end
  end
end

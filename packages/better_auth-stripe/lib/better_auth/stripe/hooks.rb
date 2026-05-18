# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Hooks
      module_function

      def handle_event(ctx, event)
        event = BetterAuth::Plugins.normalize_hash(event)
        type = event[:type].to_s
        case type
        when "checkout.session.completed"
          on_checkout_completed(ctx, event)
        when "customer.subscription.created"
          on_subscription_created(ctx, event)
        when "customer.subscription.updated"
          on_subscription_updated(ctx, event)
        when "customer.subscription.deleted"
          on_subscription_deleted(ctx, event)
        end
        config = stripe_config(ctx)
        config[:on_event]&.call(event)
      end

      def on_checkout_completed(ctx, event)
        config = stripe_config(ctx)
        object = BetterAuth::Plugins.normalize_hash(event.dig(:data, :object) || {})
        return if object[:mode] == "setup" || !config.dig(:subscription, :enabled)

        stripe_subscription = BetterAuth::Stripe::Utils.client(config).subscriptions.retrieve(object[:subscription])
        resolved = BetterAuth::Stripe::Utils.resolve_plan_item(config, stripe_subscription)
        return unless resolved

        item = resolved.fetch(:item)
        plan = resolved.fetch(:plan)
        metadata = BetterAuth::Plugins.normalize_hash(object[:metadata] || {})
        reference_id = object[:client_reference_id] || metadata[:reference_id]
        subscription_id = metadata[:subscription_id]
        return unless plan && reference_id && subscription_id

        update = BetterAuth::Stripe::Utils.subscription_state(stripe_subscription, include_status: true).merge(
          plan: plan[:name].to_s.downcase,
          stripeSubscriptionId: object[:subscription],
          seats: BetterAuth::Stripe::Utils.resolve_quantity(stripe_subscription, item, plan),
          trialStart: BetterAuth::Stripe::Utils.time(BetterAuth::Stripe::Utils.fetch(stripe_subscription, "trial_start")),
          trialEnd: BetterAuth::Stripe::Utils.time(BetterAuth::Stripe::Utils.fetch(stripe_subscription, "trial_end"))
        ).compact
        db_subscription = ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription_id}], update: update)
        plan.dig(:free_trial, :on_trial_start)&.call(db_subscription) if db_subscription && update[:trialStart]
        callback = config.dig(:subscription, :on_subscription_complete)
        callback&.call({event: event, subscription: db_subscription, stripeSubscription: stripe_subscription, stripe_subscription: stripe_subscription, plan: plan}, ctx)
      end

      def on_subscription_created(ctx, event)
        config = stripe_config(ctx)
        return unless config.dig(:subscription, :enabled)

        object = BetterAuth::Plugins.normalize_hash(event.dig(:data, :object) || {})
        customer_id = object[:customer].to_s
        return if customer_id.empty?

        metadata = BetterAuth::Plugins.normalize_hash(object[:metadata] || {})
        existing = if metadata[:subscription_id]
          ctx.context.adapter.find_one(model: "subscription", where: [{field: "id", value: metadata[:subscription_id]}])
        else
          ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: object[:id]}])
        end
        return if existing

        reference = BetterAuth::Stripe::Middleware.reference_by_customer(ctx, config, customer_id) || ((metadata[:reference_id] && metadata[:plan]) ? {reference_id: metadata[:reference_id], customer_type: metadata[:customer_type] || "user"} : nil)
        return unless reference

        resolved = BetterAuth::Stripe::Utils.resolve_plan_item(config, object)
        return unless resolved

        item = resolved.fetch(:item)
        plan = resolved[:plan] || (metadata[:plan] && BetterAuth::Stripe::Utils.plan_by_name(config, metadata[:plan]))
        return unless plan

        created = ctx.context.adapter.create(
          model: "subscription",
          data: BetterAuth::Stripe::Utils.subscription_state(object, include_status: true).merge(
            referenceId: reference.fetch(:reference_id),
            stripeCustomerId: customer_id,
            stripeSubscriptionId: object[:id],
            plan: plan[:name].to_s.downcase,
            seats: BetterAuth::Stripe::Utils.resolve_quantity(object, item, plan),
            limits: plan[:limits]
          ).compact
        )
        config.dig(:subscription, :on_subscription_created)&.call({event: event, subscription: created, stripeSubscription: object, stripe_subscription: object, plan: plan})
      end

      def on_subscription_updated(ctx, event)
        config = stripe_config(ctx)
        return unless config.dig(:subscription, :enabled)

        object = BetterAuth::Plugins.normalize_hash(event.dig(:data, :object) || {})
        resolved = BetterAuth::Stripe::Utils.resolve_plan_item(config, object)
        return unless resolved

        item = resolved.fetch(:item)
        metadata = BetterAuth::Plugins.normalize_hash(object[:metadata] || {})
        subscription = if metadata[:subscription_id]
          ctx.context.adapter.find_one(model: "subscription", where: [{field: "id", value: metadata[:subscription_id]}])
        else
          ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: object[:id]}])
        end
        unless subscription
          candidates = ctx.context.adapter.find_many(model: "subscription", where: [{field: "stripeCustomerId", value: object[:customer]}])
          subscription = if candidates.length > 1
            candidates.find { |entry| BetterAuth::Stripe::Utils.active_or_trialing?(entry) }
          else
            candidates.first
          end
        end
        return unless subscription

        plan = resolved[:plan]
        was_pending = BetterAuth::Stripe::Utils.pending_cancel?(subscription)
        update = BetterAuth::Stripe::Utils.subscription_state(object, include_status: true, compact: false).merge(
          stripeSubscriptionId: object[:id],
          seats: BetterAuth::Stripe::Utils.resolve_quantity(object, item, plan)
        )
        update[:plan] = plan[:name].to_s.downcase if plan
        update[:limits] = plan[:limits] if plan&.key?(:limits)
        updated = ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: update)
        if object[:status] == "active" && BetterAuth::Stripe::Utils.stripe_pending_cancel?(object) && !was_pending
          config.dig(:subscription, :on_subscription_cancel)&.call({event: event, subscription: subscription, stripeSubscription: object, stripe_subscription: object, cancellationDetails: object[:cancellation_details], cancellation_details: object[:cancellation_details]})
        end
        config.dig(:subscription, :on_subscription_update)&.call({event: event, subscription: updated || subscription})
        if plan && subscription["status"] == "trialing" && object[:status] == "active"
          plan.dig(:free_trial, :on_trial_end)&.call({subscription: subscription}, ctx)
        end
        if plan && subscription["status"] == "trialing" && object[:status] == "incomplete_expired"
          plan.dig(:free_trial, :on_trial_expired)&.call(subscription, ctx)
        end
      end

      def on_subscription_deleted(ctx, event)
        config = stripe_config(ctx)
        return unless config.dig(:subscription, :enabled)

        object = BetterAuth::Plugins.normalize_hash(event.dig(:data, :object) || {})
        subscription = ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: object[:id]}])
        return unless subscription

        ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: BetterAuth::Stripe::Utils.subscription_state(object, include_status: false, compact: false).merge(status: "canceled", stripeScheduleId: nil))
        config.dig(:subscription, :on_subscription_deleted)&.call({event: event, subscription: subscription, stripeSubscription: object, stripe_subscription: object})
      end

      def stripe_config(ctx)
        ctx.context.options.plugins.find { |plugin| plugin.id == "stripe" }&.options || {}
      end
    end
  end
end

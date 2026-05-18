# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Routes
      module RestoreSubscription
        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/subscription/restore", method: "POST", metadata: {openapi: {operationId: "restoreSubscription"}}) do |ctx|
            session = BetterAuth::Routes.current_session(ctx)
            body = BetterAuth::Plugins.normalize_hash(ctx.body)
            customer_type = BetterAuth::Plugins.stripe_customer_type!(body)
            reference_id = BetterAuth::Plugins.stripe_reference_id!(ctx, session, customer_type, body[:reference_id], config)
            BetterAuth::Plugins.stripe_authorize_reference!(ctx, session, reference_id, "restore-subscription", customer_type, BetterAuth::Plugins.stripe_subscription_options(config), explicit: body.key?(:reference_id))
            subscription = BetterAuth::Plugins.stripe_find_subscription_for_action(ctx, reference_id, body[:subscription_id], active_only: false)
            raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) unless subscription && subscription["stripeCustomerId"]
            raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_ACTIVE")) unless BetterAuth::Plugins.stripe_active_or_trialing?(subscription)

            if subscription["stripeScheduleId"]
              schedule = BetterAuth::Plugins.stripe_client(config).subscription_schedules.retrieve(subscription["stripeScheduleId"])
              if BetterAuth::Plugins.stripe_fetch(schedule, "status") == "active"
                schedule = BetterAuth::Plugins.stripe_client(config).subscription_schedules.release(subscription["stripeScheduleId"])
              end
              ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {stripeScheduleId: nil})
              next ctx.json(BetterAuth::Plugins.stripe_stringify_keys(schedule))
            end

            raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_PENDING_CHANGE")) unless BetterAuth::Plugins.stripe_pending_cancel?(subscription)

            active = BetterAuth::Plugins.stripe_active_subscriptions(config, subscription["stripeCustomerId"]).find do |entry|
              BetterAuth::Plugins.stripe_fetch(entry, "id") == subscription["stripeSubscriptionId"]
            end
            raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) unless active

            update_params = if BetterAuth::Plugins.stripe_fetch(active, "cancel_at")
              {cancel_at: ""}
            elsif BetterAuth::Plugins.stripe_fetch(active, "cancel_at_period_end")
              {cancel_at_period_end: false}
            else
              {}
            end
            restored = BetterAuth::Plugins.stripe_client(config).subscriptions.update(BetterAuth::Plugins.stripe_fetch(active, "id"), update_params)
            ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {cancelAtPeriodEnd: false, cancelAt: nil, canceledAt: nil})
            ctx.json(BetterAuth::Plugins.stripe_stringify_keys(restored))
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Routes
      module CancelSubscriptionCallback
        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/subscription/cancel/callback", method: "GET", metadata: {openapi: {operationId: "cancelSubscriptionCallback"}}) do |ctx|
            query = BetterAuth::Plugins.normalize_hash(ctx.query)
            callback = query[:callback_url] || "/"
            BetterAuth::Stripe::Middleware.validate_trusted_url!(ctx, callback, "callbackURL")
            unless query[:subscription_id]
              raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback))
            end
            session = BetterAuth::Routes.current_session(ctx, allow_nil: true)
            raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback)) unless session

            subscription = ctx.context.adapter.find_one(model: "subscription", where: [{field: "id", value: query[:subscription_id]}])
            raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback)) if subscription && !BetterAuth::Stripe::Middleware.authorized_subscription?(ctx, session, subscription, "cancel-subscription", config || {})
            if subscription && !BetterAuth::Plugins.stripe_pending_cancel?(subscription) && subscription["stripeCustomerId"]
              current = BetterAuth::Plugins.stripe_active_subscriptions(config || {}, subscription["stripeCustomerId"]).find { |entry| BetterAuth::Plugins.stripe_fetch(entry, "id") == subscription["stripeSubscriptionId"] }
              if current && BetterAuth::Plugins.stripe_stripe_pending_cancel?(current)
                ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: BetterAuth::Plugins.stripe_subscription_state(current, include_status: true))
                BetterAuth::Plugins.stripe_subscription_options(config || {})[:on_subscription_cancel]&.call({subscription: subscription, stripeSubscription: current, stripe_subscription: current, cancellationDetails: BetterAuth::Plugins.stripe_fetch(current, "cancellation_details"), cancellation_details: BetterAuth::Plugins.stripe_fetch(current, "cancellation_details"), event: nil})
              end
            end
            raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback))
          end
        end
      end
    end
  end
end

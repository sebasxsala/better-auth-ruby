# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Routes
      module SubscriptionSuccess
        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/subscription/success", method: "GET", metadata: {openapi: {operationId: "subscriptionSuccess"}}) do |ctx|
            query = BetterAuth::Plugins.normalize_hash(ctx.query)
            callback = query[:callback_url] || "/"
            BetterAuth::Stripe::Middleware.validate_trusted_url!(ctx, callback, "callbackURL")
            checkout_session_id = query[:checkout_session_id]
            subscription_id = nil
            if checkout_session_id
              callback = callback.to_s.gsub("{CHECKOUT_SESSION_ID}", checkout_session_id.to_s)
              checkout_session = begin
                BetterAuth::Plugins.stripe_client(config || {}).checkout.sessions.retrieve(checkout_session_id)
              rescue
                nil
              end
              raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback)) unless checkout_session

              metadata = BetterAuth::Plugins.normalize_hash(BetterAuth::Plugins.stripe_fetch(checkout_session || {}, "metadata") || {})
              subscription_id = metadata[:subscription_id]
            end

            unless subscription_id
              raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback))
            end
            session = BetterAuth::Routes.current_session(ctx, allow_nil: true)
            raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback)) unless session

            subscription = ctx.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription_id}])
            raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback)) unless subscription
            raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback)) unless BetterAuth::Stripe::Middleware.authorized_subscription?(ctx, session, subscription, "subscription-success", config || {})
            raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback)) if BetterAuth::Plugins.stripe_active_or_trialing?(subscription)

            customer_id = subscription["stripeCustomerId"] || session.fetch(:user)["stripeCustomerId"]
            raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback)) unless customer_id

            stripe_subscription = BetterAuth::Plugins.stripe_active_subscriptions(config || {}, customer_id).first
            if stripe_subscription
              resolved = BetterAuth::Plugins.stripe_resolve_plan_item(config || {}, stripe_subscription)
              item = resolved&.fetch(:item, nil)
              plan = resolved&.fetch(:plan, nil)
              if item && plan
                ctx.context.adapter.update(
                  model: "subscription",
                  where: [{field: "id", value: subscription.fetch("id")}],
                  update: BetterAuth::Plugins.stripe_subscription_state(stripe_subscription, include_status: true, compact: false).merge(
                    plan: plan[:name].to_s.downcase,
                    seats: BetterAuth::Plugins.stripe_resolve_quantity(stripe_subscription, item, plan),
                    stripeSubscriptionId: BetterAuth::Plugins.stripe_fetch(stripe_subscription, "id")
                  )
                )
              end
            end
            raise ctx.redirect(BetterAuth::Plugins.stripe_url(ctx, callback))
          end
        end
      end
    end
  end
end

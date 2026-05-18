# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Routes
      module CancelSubscription
        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/subscription/cancel", method: "POST", metadata: {openapi: {operationId: "cancelSubscription"}}) do |ctx|
            session = BetterAuth::Routes.current_session(ctx)
            body = BetterAuth::Plugins.normalize_hash(ctx.body)
            BetterAuth::Stripe::Middleware.validate_trusted_urls!(ctx, body, return_url: "returnUrl")
            customer_type = BetterAuth::Plugins.stripe_customer_type!(body)
            reference_id = BetterAuth::Plugins.stripe_reference_id!(ctx, session, customer_type, body[:reference_id], config)
            BetterAuth::Plugins.stripe_authorize_reference!(ctx, session, reference_id, "cancel-subscription", customer_type, BetterAuth::Plugins.stripe_subscription_options(config), explicit: body.key?(:reference_id))
            subscription = BetterAuth::Plugins.stripe_find_subscription_for_action(ctx, reference_id, body[:subscription_id], active_only: true)
            raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) unless subscription && subscription["stripeCustomerId"]

            active = BetterAuth::Plugins.stripe_active_subscriptions(config, subscription["stripeCustomerId"])
            if active.empty?
              ctx.context.adapter.delete_many(model: "subscription", where: [{field: "referenceId", value: reference_id}])
              raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND"))
            end
            stripe_subscription = active.find { |entry| BetterAuth::Plugins.stripe_fetch(entry, "id") == subscription["stripeSubscriptionId"] }
            raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) unless stripe_subscription

            portal = BetterAuth::Plugins.stripe_client(config).billing_portal.sessions.create(
              customer: subscription["stripeCustomerId"],
              return_url: BetterAuth::Plugins.stripe_url(ctx, "#{ctx.context.base_url}/subscription/cancel/callback?callbackURL=#{Rack::Utils.escape(body[:return_url] || "/")}&subscriptionId=#{Rack::Utils.escape(subscription.fetch("id"))}"),
              flow_data: {type: "subscription_cancel", subscription_cancel: {subscription: BetterAuth::Plugins.stripe_fetch(stripe_subscription, "id")}}
            )
            ctx.json(BetterAuth::Plugins.stripe_stringify_keys(portal).merge(redirect: BetterAuth::Plugins.stripe_redirect?(body)))
          rescue BetterAuth::APIError
            raise
          rescue => error
            if error.message.include?("already set to be canceled") && subscription && !BetterAuth::Plugins.stripe_pending_cancel?(subscription)
              stripe_sub = BetterAuth::Plugins.stripe_client(config).subscriptions.retrieve(subscription["stripeSubscriptionId"])
              ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: BetterAuth::Plugins.stripe_subscription_state(stripe_sub, include_status: false))
            end
            raise BetterAuth::APIError.new("BAD_REQUEST", message: error.message)
          end
        end
      end
    end
  end
end

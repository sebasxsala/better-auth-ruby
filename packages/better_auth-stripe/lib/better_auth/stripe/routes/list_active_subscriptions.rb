# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Routes
      module ListActiveSubscriptions
        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/subscription/list", method: "GET", metadata: {openapi: {operationId: "listActiveSubscriptions"}}) do |ctx|
            session = BetterAuth::Routes.current_session(ctx)
            query = BetterAuth::Plugins.normalize_hash(ctx.query)
            customer_type = BetterAuth::Plugins.stripe_customer_type!(query)
            reference_id = BetterAuth::Plugins.stripe_reference_id!(ctx, session, customer_type, query[:reference_id], config)
            BetterAuth::Plugins.stripe_authorize_reference!(ctx, session, reference_id, "list-subscription", customer_type, BetterAuth::Plugins.stripe_subscription_options(config), explicit: query.key?(:reference_id))
            plans = BetterAuth::Plugins.stripe_plans(config)
            subscriptions = ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}]).select { |entry| BetterAuth::Plugins.stripe_active_or_trialing?(entry) }
            ctx.json(subscriptions.map do |entry|
              plan = plans.find { |item| item[:name].to_s.downcase == entry["plan"].to_s.downcase }
              price_id = if entry["billingInterval"] == "year"
                plan&.fetch(:annual_discount_price_id, nil) || plan&.fetch(:price_id, nil)
              else
                plan&.fetch(:price_id, nil)
              end
              entry.merge("limits" => plan&.fetch(:limits, nil), "priceId" => price_id)
            end)
          end
        end
      end
    end
  end
end

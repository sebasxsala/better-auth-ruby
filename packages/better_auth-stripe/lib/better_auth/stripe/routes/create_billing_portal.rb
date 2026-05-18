# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Routes
      module CreateBillingPortal
        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/subscription/billing-portal", method: "POST", metadata: {openapi: {operationId: "createBillingPortal"}}) do |ctx|
            session = BetterAuth::Routes.current_session(ctx)
            body = BetterAuth::Plugins.normalize_hash(ctx.body)
            BetterAuth::Stripe::Middleware.validate_trusted_urls!(ctx, body, return_url: "returnUrl")
            customer_type = BetterAuth::Plugins.stripe_customer_type!(body)
            reference_id = BetterAuth::Plugins.stripe_reference_id!(ctx, session, customer_type, body[:reference_id], config)
            BetterAuth::Plugins.stripe_authorize_reference!(ctx, session, reference_id, "billing-portal", customer_type, BetterAuth::Plugins.stripe_subscription_options(config), explicit: body.key?(:reference_id))
            customer_id = if customer_type == "organization"
              org = ctx.context.adapter.find_one(model: "organization", where: [{field: "id", value: reference_id}])
              org&.fetch("stripeCustomerId", nil) || BetterAuth::Plugins.stripe_active_subscription(ctx, reference_id)&.fetch("stripeCustomerId", nil)
            else
              session.fetch(:user)["stripeCustomerId"] || BetterAuth::Plugins.stripe_active_subscription(ctx, reference_id)&.fetch("stripeCustomerId", nil)
            end
            raise BetterAuth::APIError.new("NOT_FOUND", message: BetterAuth::Stripe::ERROR_CODES.fetch("CUSTOMER_NOT_FOUND")) unless customer_id

            portal = BetterAuth::Plugins.stripe_client(config).billing_portal.sessions.create(customer: customer_id, return_url: BetterAuth::Plugins.stripe_url(ctx, body[:return_url] || "/"), locale: body[:locale])
            ctx.json(BetterAuth::Plugins.stripe_stringify_keys(portal).merge(redirect: BetterAuth::Plugins.stripe_redirect?(body)))
          rescue BetterAuth::APIError
            raise
          rescue
            raise BetterAuth::APIError.new("INTERNAL_SERVER_ERROR", message: BetterAuth::Stripe::ERROR_CODES.fetch("UNABLE_TO_CREATE_BILLING_PORTAL"))
          end
        end
      end
    end
  end
end

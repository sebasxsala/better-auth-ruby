# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Routes
      module UpgradeSubscription
        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/subscription/upgrade", method: "POST", metadata: {openapi: {operationId: "upgradeSubscription"}}) do |ctx|
            session = BetterAuth::Routes.current_session(ctx)
            body = BetterAuth::Plugins.normalize_hash(ctx.body)
            BetterAuth::Stripe::Middleware.validate_trusted_urls!(ctx, body, success_url: "successUrl", cancel_url: "cancelUrl", return_url: "returnUrl")
            subscription_options = BetterAuth::Plugins.stripe_subscription_options(config)
            customer_type = BetterAuth::Plugins.stripe_customer_type!(body)
            reference_id = BetterAuth::Plugins.stripe_reference_id!(ctx, session, customer_type, body[:reference_id], config)
            BetterAuth::Plugins.stripe_authorize_reference!(ctx, session, reference_id, "upgrade-subscription", customer_type, subscription_options, explicit: body.key?(:reference_id))

            user = session.fetch(:user)
            if subscription_options[:require_email_verification] && !user["emailVerified"]
              raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("EMAIL_VERIFICATION_REQUIRED"))
            end

            plan = BetterAuth::Plugins.stripe_plan_by_name(config, body[:plan])
            raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_PLAN_NOT_FOUND")) unless plan

            subscription_to_update = nil
            if body[:subscription_id]
              subscription_to_update = ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: body[:subscription_id]}])
              raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) unless subscription_to_update && subscription_to_update["referenceId"] == reference_id
            end

            subscriptions = subscription_to_update ? [subscription_to_update] : ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}])
            reference_customer_id = subscriptions.find { |entry| entry["stripeCustomerId"] }&.fetch("stripeCustomerId", nil)
            customer_id = if customer_type == "organization"
              subscription_to_update&.fetch("stripeCustomerId", nil) || reference_customer_id || BetterAuth::Plugins.stripe_organization_customer(config, ctx, reference_id, body[:metadata])
            else
              subscription_to_update&.fetch("stripeCustomerId", nil) || reference_customer_id || user["stripeCustomerId"] || BetterAuth::Plugins.stripe_create_customer(config, ctx, user, body[:metadata])
            end

            active_or_trialing = subscriptions.find { |entry| BetterAuth::Plugins.stripe_active_or_trialing?(entry) }
            active_stripe_subscriptions = BetterAuth::Plugins.stripe_active_subscriptions(config, customer_id)
            active_stripe = active_stripe_subscriptions.find do |entry|
              if subscription_to_update&.fetch("stripeSubscriptionId", nil) || body[:subscription_id]
                BetterAuth::Plugins.stripe_fetch(entry, "id") == subscription_to_update&.fetch("stripeSubscriptionId", nil) || BetterAuth::Plugins.stripe_fetch(entry, "id") == body[:subscription_id]
              elsif active_or_trialing && active_or_trialing["stripeSubscriptionId"]
                BetterAuth::Plugins.stripe_fetch(entry, "id") == active_or_trialing["stripeSubscriptionId"]
              else
                false
              end
            end

            price_id = BetterAuth::Plugins.stripe_price_id(config, plan, body[:annual])
            raise BetterAuth::APIError.new("BAD_REQUEST", message: "Price ID not found for the selected plan") if price_id.to_s.empty?
            auto_managed_seats = !!(plan[:seat_price_id] && customer_type == "organization")
            member_count = auto_managed_seats ? ctx.context.adapter.count(model: "member", where: [{field: "organizationId", value: reference_id}]) : 0
            requested_seats = auto_managed_seats ? member_count : (body[:seats] || 1)
            seat_only_plan = auto_managed_seats && plan[:seat_price_id] == price_id

            active_resolved = active_stripe && BetterAuth::Plugins.stripe_resolve_plan_item(config, active_stripe)
            active_stripe_item = active_resolved&.fetch(:item, nil) || BetterAuth::Plugins.stripe_subscription_item(active_stripe || {})
            stripe_price_id_value = BetterAuth::Plugins.stripe_fetch(BetterAuth::Plugins.stripe_fetch(active_stripe_item || {}, "price") || {}, "id")
            same_plan = active_or_trialing && active_or_trialing["plan"].to_s.downcase == body[:plan].to_s.downcase
            same_seats = auto_managed_seats || (active_or_trialing && active_or_trialing["seats"].to_i == requested_seats.to_i)
            same_price = !!active_stripe && stripe_price_id_value == price_id
            valid_period = !active_or_trialing || !active_or_trialing["periodEnd"] || active_or_trialing["periodEnd"] > Time.now
            if active_or_trialing&.fetch("status", nil) == "active" && same_plan && same_seats && same_price && valid_period
              raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("ALREADY_SUBSCRIBED_PLAN"))
            end

            if active_stripe
              BetterAuth::Plugins.stripe_release_plugin_schedule(ctx, config, customer_id, active_stripe, active_or_trialing || subscription_to_update)

              if body[:schedule_at_period_end]
                url = BetterAuth::Plugins.stripe_schedule_plan_change(ctx, config, active_stripe, active_or_trialing, plan, price_id, requested_seats, seat_only_plan, body)
                next ctx.json({url: url, redirect: BetterAuth::Plugins.stripe_redirect?(body)})
              end

              old_plan = active_or_trialing && BetterAuth::Plugins.stripe_plan_by_name(config, active_or_trialing["plan"])
              if BetterAuth::Plugins.stripe_direct_subscription_update?(old_plan, plan, auto_managed_seats)
                url = BetterAuth::Plugins.stripe_update_active_subscription_items(ctx, config, active_stripe, active_or_trialing, old_plan, plan, price_id, requested_seats, seat_only_plan, body)
                next ctx.json({url: url, redirect: BetterAuth::Plugins.stripe_redirect?(body)})
              end

              portal = BetterAuth::Plugins.stripe_client(config).billing_portal.sessions.create(
                customer: customer_id,
                return_url: BetterAuth::Plugins.stripe_url(ctx, body[:return_url] || "/"),
                flow_data: {
                  type: "subscription_update_confirm",
                  after_completion: {type: "redirect", redirect: {return_url: BetterAuth::Plugins.stripe_url(ctx, body[:return_url] || "/")}},
                  subscription_update_confirm: {
                    subscription: BetterAuth::Plugins.stripe_fetch(active_stripe, "id"),
                    items: [BetterAuth::Plugins.stripe_line_item(config, price_id, requested_seats).merge(id: BetterAuth::Plugins.stripe_fetch(active_stripe_item || {}, "id"))]
                  }
                }
              )
              next ctx.json(BetterAuth::Plugins.stripe_stringify_keys(portal).merge(redirect: BetterAuth::Plugins.stripe_redirect?(body)))
            end

            incomplete = subscriptions.find { |entry| entry["status"] == "incomplete" }
            subscription = active_or_trialing || incomplete
            if subscription
              update = {plan: plan[:name].to_s.downcase, seats: requested_seats}
              subscription = ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: update) || subscription.merge(update.transform_keys { |key| BetterAuth::Schema.storage_key(key) })
            else
              subscription = ctx.context.adapter.create(
                model: "subscription",
                data: {plan: plan[:name].to_s.downcase, referenceId: reference_id, stripeCustomerId: customer_id, status: "incomplete", seats: requested_seats, limits: plan[:limits]}
              )
            end

            has_ever_trialed = ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}]).any? do |entry|
              entry["trialStart"] || entry["trialEnd"] || entry["status"] == "trialing"
            end
            free_trial = (!has_ever_trialed && plan[:free_trial]) ? {trial_period_days: plan.dig(:free_trial, :days)} : {}
            checkout_customization = subscription_options[:get_checkout_session_params]&.call(
              {user: user, session: session.fetch(:session), plan: plan, subscription: subscription},
              ctx.request,
              ctx
            ) || {}
            custom_params = BetterAuth::Plugins.stripe_fetch(checkout_customization, "params") || {}
            custom_options = BetterAuth::Plugins.normalize_hash(BetterAuth::Plugins.stripe_fetch(checkout_customization, "options") || {})
            custom_subscription_data = BetterAuth::Plugins.stripe_fetch(custom_params, "subscription_data") || BetterAuth::Plugins.stripe_fetch(custom_params, "subscriptionData") || {}
            internal_metadata = {userId: user.fetch("id"), subscriptionId: subscription.fetch("id"), referenceId: reference_id}
            metadata = BetterAuth::Plugins.stripe_subscription_metadata_set(internal_metadata, body[:metadata], BetterAuth::Plugins.stripe_fetch(custom_params, "metadata"))
            subscription_metadata = BetterAuth::Plugins.stripe_subscription_metadata_set(internal_metadata, body[:metadata], BetterAuth::Plugins.stripe_fetch(custom_subscription_data, "metadata"))
            checkout_params = BetterAuth::Plugins.stripe_deep_merge(
              custom_params,
              customer: customer_id,
              customer_update: (customer_type == "user") ? {name: "auto", address: "auto"} : {address: "auto"},
              locale: body[:locale],
              success_url: BetterAuth::Plugins.stripe_url(ctx, "#{ctx.context.base_url}/subscription/success?callbackURL=#{Rack::Utils.escape(body[:success_url] || "/")}&checkoutSessionId={CHECKOUT_SESSION_ID}"),
              cancel_url: BetterAuth::Plugins.stripe_url(ctx, body[:cancel_url] || "/"),
              line_items: BetterAuth::Plugins.stripe_checkout_line_items(config, plan, price_id, requested_seats, auto_managed_seats, seat_only_plan),
              subscription_data: free_trial.merge(metadata: subscription_metadata),
              mode: "subscription",
              client_reference_id: reference_id,
              metadata: metadata
            )
            checkout_params[:metadata] = metadata
            checkout_params[:subscription_data] ||= {}
            checkout_params[:subscription_data][:metadata] = subscription_metadata
            checkout = BetterAuth::Plugins.stripe_client(config).checkout.sessions.create(checkout_params, custom_options.empty? ? nil : custom_options)
            ctx.json(BetterAuth::Plugins.stripe_stringify_keys(checkout).merge(redirect: BetterAuth::Plugins.stripe_redirect?(body)))
          end
        end
      end
    end
  end
end

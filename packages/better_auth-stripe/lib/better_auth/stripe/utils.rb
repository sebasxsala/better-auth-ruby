# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Utils
      module_function

      def client(config)
        BetterAuth::Plugins.stripe_client(config)
      end

      def id(object)
        fetch(object, "id")
      end

      def fetch(object, key)
        return nil unless object.respond_to?(:[])

        return object[key] if object.respond_to?(:key?) && object.key?(key)

        symbol_key = key.to_sym
        return object[symbol_key] if object.respond_to?(:key?) && object.key?(symbol_key)

        object[key] || object[symbol_key]
      end

      def time(value)
        return nil unless value

        Time.at(value.to_i)
      end

      def subscription_options(config)
        BetterAuth::Plugins.normalize_hash(config[:subscription] || {})
      end

      def plans(config)
        plans = subscription_options(config)[:plans] || []
        plans = plans.call if plans.respond_to?(:call)
        Array(plans).map do |plan|
          normalized = BetterAuth::Plugins.normalize_hash(plan)
          limits = fetch(plan, "limits")
          normalized[:limits] = limits if limits
          normalized
        end
      end

      def plan_by_name(config, name)
        plans(config).find { |plan| plan[:name].to_s.downcase == name.to_s.downcase }
      end

      def plan_by_price_info(config, price_id, lookup_key = nil)
        plans(config).find do |plan|
          plan[:price_id] == price_id || plan[:annual_discount_price_id] == price_id || (lookup_key && (plan[:lookup_key] == lookup_key || plan[:annual_discount_lookup_key] == lookup_key))
        end
      end

      def price_id(config, plan, annual = false)
        annual ? (plan[:annual_discount_price_id] || resolve_lookup(config, plan[:annual_discount_lookup_key])) : (plan[:price_id] || resolve_lookup(config, plan[:lookup_key]))
      end

      def resolve_lookup(config, lookup_key)
        return nil if lookup_key.to_s.empty?
        return nil unless client(config).respond_to?(:prices)

        prices = client(config).prices.list(lookup_keys: [lookup_key], active: true, limit: 1)
        fetch(Array(fetch(prices, "data")).first || {}, "id")
      end

      def active_or_trialing?(subscription)
        %w[active trialing].include?(fetch(subscription, "status").to_s)
      end

      def pending_cancel?(subscription)
        !!(fetch(subscription, "cancelAtPeriodEnd") || fetch(subscription, "cancelAt"))
      end

      def stripe_pending_cancel?(subscription)
        !!(fetch(subscription, "cancel_at_period_end") || fetch(subscription, "cancel_at"))
      end

      def subscription_item(subscription)
        Array(fetch(fetch(subscription, "items") || {}, "data")).first
      end

      def resolve_plan_item(config, subscription)
        items = Array(fetch(fetch(subscription, "items") || {}, "data"))
        first = items.first
        return nil unless first

        items.each do |item|
          price = fetch(item, "price") || {}
          plan = plan_by_price_info(config, fetch(price, "id"), fetch(price, "lookup_key"))
          return {item: item, plan: plan} if plan
        end
        {item: first, plan: nil} if items.length == 1
      end

      def resolve_quantity(subscription, plan_item, plan = nil)
        items = Array(fetch(fetch(subscription, "items") || {}, "data"))
        seat_price_id = plan && plan[:seat_price_id]
        seat_item = seat_price_id && items.find { |item| fetch(fetch(item, "price") || {}, "id") == seat_price_id }
        fetch(seat_item || plan_item, "quantity") || 1
      end

      def line_item(config, price_id, quantity)
        item = {price: price_id}
        item[:quantity] = quantity unless metered_price?(config, price_id)
        item
      end

      def checkout_line_items(config, plan, price_id, quantity, auto_managed_seats, seat_only_plan)
        items = []
        items << line_item(config, price_id, auto_managed_seats ? 1 : quantity) unless seat_only_plan
        items << {price: plan[:seat_price_id], quantity: quantity} if auto_managed_seats && plan[:seat_price_id]
        items.concat(plan_line_items(plan))
        items
      end

      def plan_line_items(plan)
        Array(plan[:line_items]).map do |item|
          item.is_a?(Hash) ? BetterAuth::Plugins.normalize_hash(item) : item
        end
      end

      def direct_subscription_update?(old_plan, plan, auto_managed_seats)
        return true if auto_managed_seats && old_plan && old_plan[:seat_price_id] != plan[:seat_price_id]

        plan_line_items(old_plan || {}).map { |item| item[:price] } != plan_line_items(plan).map { |item| item[:price] }
      end

      def metered_price?(config, price_id, lookup_key = nil)
        price = resolve_stripe_price(config, price_id, lookup_key)
        recurring = fetch(price || {}, "recurring") || {}
        fetch(recurring, "usage_type") == "metered"
      end

      def resolve_stripe_price(config, price_id, lookup_key = nil)
        return nil unless client(config).respond_to?(:prices)

        prices = client(config).prices
        if lookup_key
          result = prices.list(lookup_keys: [lookup_key], active: true, limit: 1)
          Array(fetch(result, "data")).first
        elsif price_id && prices.respond_to?(:retrieve)
          prices.retrieve(price_id)
        end
      rescue
        nil
      end

      def subscription_state(subscription, include_status: true, compact: true)
        item = subscription_item(subscription)
        price = fetch(item || {}, "price") || {}
        recurring = fetch(price, "recurring") || {}
        state = {
          periodStart: time(fetch(item || subscription, "current_period_start")),
          periodEnd: time(fetch(item || subscription, "current_period_end")),
          cancelAtPeriodEnd: fetch(subscription, "cancel_at_period_end"),
          cancelAt: time(fetch(subscription, "cancel_at")),
          canceledAt: time(fetch(subscription, "canceled_at")),
          endedAt: time(fetch(subscription, "ended_at")),
          trialStart: time(fetch(subscription, "trial_start")),
          trialEnd: time(fetch(subscription, "trial_end")),
          billingInterval: fetch(recurring, "interval"),
          stripeScheduleId: schedule_id(subscription)
        }
        state[:status] = fetch(subscription, "status") if include_status
        compact ? state.compact : state
      end

      def schedule_id(subscription)
        schedule = fetch(subscription, "schedule")
        return nil if schedule.nil?
        return schedule if schedule.is_a?(String)

        id(schedule) || schedule.to_s
      end

      def redirect?(body)
        body[:disable_redirect] != true
      end

      def url(ctx, url)
        return url if url.to_s.match?(/\A[a-zA-Z][a-zA-Z0-9+\-.]*:/)

        "#{ctx.context.base_url}#{url.to_s.start_with?("/") ? url : "/#{url}"}"
      end

      def escape_search(value)
        value.to_s.gsub("\"", "\\\"")
      end
    end
  end
end

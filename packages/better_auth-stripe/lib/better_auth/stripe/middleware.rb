# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Middleware
      module_function

      def reference_id!(_ctx, session, customer_type, explicit_reference_id, config)
        return explicit_reference_id || session.fetch(:user).fetch("id") unless customer_type == "organization"
        raise APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("ORGANIZATION_SUBSCRIPTION_NOT_ENABLED")) unless config.dig(:organization, :enabled)

        reference_id = explicit_reference_id || session.fetch(:session)["activeOrganizationId"]
        raise APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("ORGANIZATION_REFERENCE_ID_REQUIRED")) if reference_id.to_s.empty?

        reference_id
      end

      def authorize_reference!(ctx, session, reference_id, action, customer_type, subscription_options, explicit: false)
        callback = subscription_options[:authorize_reference]
        if customer_type == "organization"
          raise APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("AUTHORIZE_REFERENCE_REQUIRED")) unless callback
        elsif !explicit || reference_id == session.fetch(:user).fetch("id")
          return
        elsif !callback
          raise APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("REFERENCE_ID_NOT_ALLOWED"))
        end

        allowed = callback.call({user: session.fetch(:user), session: session.fetch(:session), referenceId: reference_id, reference_id: reference_id, action: action}, ctx)
        raise APIError.new("UNAUTHORIZED", message: BetterAuth::Stripe::ERROR_CODES.fetch("UNAUTHORIZED")) unless allowed
      end

      def customer_type!(source)
        body = BetterAuth::Plugins.normalize_hash(source || {})
        customer_type = (body[:customer_type] || "user").to_s
        raise APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("INVALID_CUSTOMER_TYPE")) unless BetterAuth::Stripe::Types::CUSTOMER_TYPES.include?(customer_type)

        customer_type
      end

      def reference_by_customer(ctx, config, customer_id)
        if config.dig(:organization, :enabled)
          org = ctx.context.adapter.find_one(model: "organization", where: [{field: "stripeCustomerId", value: customer_id}])
          return {customer_type: "organization", reference_id: org.fetch("id")} if org
        end
        user = ctx.context.adapter.find_one(model: "user", where: [{field: "stripeCustomerId", value: customer_id}])
        return {customer_type: "user", reference_id: user.fetch("id")} if user

        nil
      end

      def authorized_subscription?(ctx, session, subscription, action, config)
        reference_id = subscription && subscription["referenceId"]
        return false if reference_id.to_s.empty?
        return true if reference_id == session.fetch(:user).fetch("id")

        subscription_options = BetterAuth::Stripe::Utils.subscription_options(config)
        if config.dig(:organization, :enabled)
          org = ctx.context.adapter.find_one(model: "organization", where: [{field: "id", value: reference_id}])
          if org
            return false unless subscription_options[:authorize_reference]

            authorize_reference!(ctx, session, reference_id, action, "organization", subscription_options, explicit: true)
            return true
          end
        end

        authorize_reference!(ctx, session, reference_id, action, "user", subscription_options, explicit: true)
        true
      rescue BetterAuth::APIError
        false
      end

      def validate_trusted_url!(ctx, value, label)
        return if value.nil? || value.to_s.empty?

        validation_value = value.to_s.gsub("{CHECKOUT_SESSION_ID}", "checkout_session_id")
        return if ctx.context.trusted_origin?(validation_value, allow_relative_paths: true)

        raise APIError.new("FORBIDDEN", message: "Invalid #{label}")
      end

      def validate_trusted_urls!(ctx, source, mapping)
        body = BetterAuth::Plugins.normalize_hash(source || {})
        mapping.each do |key, label|
          validate_trusted_url!(ctx, body[key], label)
        end
      end
    end
  end
end

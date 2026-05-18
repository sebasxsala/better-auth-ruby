# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Routes
      module StripeWebhook
        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/stripe/webhook", method: "POST", metadata: {hide: true}, disable_body: true) do |ctx|
            signature = ctx.headers["stripe-signature"]
            raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("STRIPE_SIGNATURE_NOT_FOUND")) if signature.to_s.empty?

            raise BetterAuth::APIError.new("INTERNAL_SERVER_ERROR", message: BetterAuth::Stripe::ERROR_CODES.fetch("STRIPE_WEBHOOK_SECRET_NOT_FOUND")) if config[:stripe_webhook_secret].to_s.empty?

            payload = ctx.raw_body.to_s.empty? ? ctx.body : ctx.raw_body
            event = begin
              client = BetterAuth::Plugins.stripe_client(config)
              webhooks = client.webhooks if client.respond_to?(:webhooks)
              unless webhooks
                raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT"))
              end

              if webhooks.respond_to?(:construct_event_async)
                webhooks.construct_event_async(payload, signature, config[:stripe_webhook_secret])
              elsif webhooks.respond_to?(:construct_event)
                webhooks.construct_event(payload, signature, config[:stripe_webhook_secret])
              else
                raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT"))
              end
            rescue BetterAuth::APIError
              raise
            rescue
              raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT"))
            end
            raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT")) unless event
            begin
              BetterAuth::Plugins.stripe_handle_event(ctx, event)
            rescue => error
              logger = ctx.context.logger
              if logger.respond_to?(:error)
                logger.error("Stripe webhook failed. Error: #{error.message}")
              elsif logger.respond_to?(:call)
                logger.call(:error, "Stripe webhook failed. Error: #{error.message}")
              end
            end
            ctx.json({success: true})
          end
        end
      end
    end
  end
end

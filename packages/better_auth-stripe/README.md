# better_auth-stripe

Stripe subscription and customer plugin package for Better Auth Ruby.

## Installation

Add the gem and require the package before configuring the plugin:

```ruby
gem "better_auth-stripe"
```

```ruby
require "better_auth/stripe"

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: :memory,
  plugins: [
    BetterAuth::Plugins.stripe(
      stripe_api_key: ENV.fetch("STRIPE_SECRET_KEY"),
      stripe_webhook_secret: ENV.fetch("STRIPE_WEBHOOK_SECRET"),
      subscription: {
        enabled: true,
        plans: [
          { name: "pro", price_id: "price_monthly", annual_discount_price_id: "price_yearly" },
          { name: "team", price_id: "price_team", seat_price_id: "price_team_seat" }
        ]
      }
    )
  ]
)
```

## Subscription Options

Set `subscription: { enabled: true, plans: [...] }` to enable checkout, portal, restore, list, and webhook subscription handling. Plans support `name`, `price_id`, `lookup_key`, `annual_discount_price_id`, `annual_discount_lookup_key`, `limits`, `free_trial`, `seat_price_id`, `line_items`, and `proration_behavior`.

Organization subscriptions require `organization: { enabled: true }` and an `authorize_reference` callback. When a plan has `seat_price_id`, organization member changes sync the Stripe seat item quantity.

## Notes

This package depends on the official `stripe` gem. Keeping Stripe outside `better_auth` avoids installing Stripe SDK dependencies for applications that do not use billing.

Pass `stripe_client:` when you need a custom Stripe client, Stripe Connect behavior, or a test double.

## Subscriptions

Configure plans under `subscription: { enabled: true, plans: [...] }`. Ruby accepts upstream-equivalent plan keys including `price_id`, `annual_discount_price_id`, lookup-key variants, `limits`, `free_trial`, and `seat_price_id`.

For organization subscriptions, `seat_price_id` enables upstream-style seat billing. Checkout sends the base plan item with quantity `1` and a separate seat item whose quantity is the current organization member count. Webhooks read the seat item quantity back into the local `subscription.seats` field.

`scheduleAtPeriodEnd` / `schedule_at_period_end` on `/subscription/upgrade` creates a Stripe subscription schedule for active subscriptions, stores `stripeScheduleId`, and returns the configured `returnUrl` instead of opening the billing portal immediately.

Ruby also routes subscription-cancel billing portal returns through `/subscription/cancel/callback` so a missed webhook can still sync the local cancellation fields before redirecting to the configured callback URL.

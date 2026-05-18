# Stripe Server Security and Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `better_auth-stripe` server-only behavior against cross-account mutation risks and align the Ruby port with upstream Better Auth Stripe v1.6.9.

**Architecture:** Keep behavior inside the Stripe package. Prefer upstream-compatible route/hook semantics, small helper methods for authorization and line-item diffing, and focused regression tests around observable API behavior.

**Tech Stack:** Ruby, Minitest, BetterAuth endpoint/plugin APIs, vendored upstream Better Auth Stripe source.

---

### Task 1: Webhook Guards and Success Semantics

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/hooks.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/routes/stripe_webhook.rb`
- Test: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`

- [x] Add failing tests proving subscription webhooks are ignored when `subscription.enabled` is false.
- [x] Add failing test proving a valid signed webhook still returns `{success: true}` when downstream processing raises.
- [x] Add `subscription.enabled` guards to created/updated/deleted hook handlers.
- [x] Keep invalid signature/construction failures as request errors.

### Task 2: Callback Ownership

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/middleware.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/routes/subscription_success.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/routes/cancel_subscription_callback.rb`
- Test: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`

- [x] Add failing tests proving one user cannot update another user subscription through success or cancel callbacks.
- [x] Resolve `/subscription/success` subscription ids only from verified Checkout Session metadata.
- [x] Authorize callback subscription `referenceId` before any Stripe fetch, DB update, or cancellation callback.
- [x] Document the Ruby-only cancel callback route in the package README.

### Task 3: Restore and Upgrade State Fixes

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/routes/restore_subscription.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/routes/upgrade_subscription.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/error_codes.rb`
- Test: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`

- [x] Add failing test proving restore updates the matching Stripe subscription, not the first active subscription for the customer.
- [x] Add failing test proving stale local active rows do not trigger `ALREADY_SUBSCRIBED_PLAN` when Stripe has no active match.
- [x] Add `SUBSCRIPTION_NOT_PENDING_CHANGE` and use it when restore has no pending cancel or schedule.

### Task 4: Multi-Item Upgrade Parity

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/utils.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Test: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`
- Test: `packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb`

- [x] Add failing tests for immediate and scheduled duplicate line-item prevention.
- [x] Add failing test for active seat-only plan upgrade without duplicate items.
- [x] Replace array subtraction with upstream-style multiset line-item diffing.
- [x] Apply the same diff semantics to scheduled phases and direct subscription updates.

### Task 5: Endpoint Metadata and Verification

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/routes/*.rb`
- Test: `packages/better_auth-stripe/test/better_auth/stripe/routes/*_test.rb`

- [x] Add explicit Stripe endpoint OpenAPI operation ids.
- [x] Hide `/stripe/webhook` from OpenAPI metadata.
- [x] Run `rbenv exec bundle exec rake test` from `packages/better_auth-stripe`.

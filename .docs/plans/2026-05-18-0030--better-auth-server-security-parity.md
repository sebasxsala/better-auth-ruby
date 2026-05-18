# BetterAuth Server-Side Security and Upstream Parity Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `packages/better_auth` server-only behavior against upstream parity gaps, missing expected errors, and Rack-thread blocking risks.

**Architecture:** Keep all behavior in the framework-agnostic core gem. Mirror upstream Better Auth v1.6.9 where applicable, and document Ruby-specific Rack hardening through focused tests rather than new public dependencies.

**Tech Stack:** Ruby, Rack, Minitest, StandardRB, vendored Better Auth TypeScript source under `upstream/better-auth/1.6.9`.

---

### Task 1: OAuth Token Endpoint Session Boundary

**Files:**
- Modify: `packages/better_auth/lib/better_auth/routes/account.rb`
- Test: `packages/better_auth/test/better_auth/routes/account_test.rb`

- [x] Add Rack/request-backed rejection before `userId` fallback in `get_access_token`.
- [x] Add Rack/request-backed rejection before `userId` fallback in `refresh_token`.
- [x] Add tests proving unauthenticated Rack requests with `userId` return `401`.
- [x] Add tests proving direct server `auth.api` calls with `userId` still work.

### Task 2: Server-Only Password Verification and Credential Errors

**Files:**
- Modify: `packages/better_auth/lib/better_auth/routes/password.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/user.rb`
- Test: `packages/better_auth/test/better_auth/routes/password_test.rb`
- Test: `packages/better_auth/test/better_auth/routes/user_routes_test.rb`

- [x] Mark `/verify-password` as server-only so Rack calls return `403`.
- [x] Keep direct `auth.api.verify_password` usable.
- [x] Return `CREDENTIAL_ACCOUNT_NOT_FOUND` when password actions require a missing credential account.
- [x] Keep `INVALID_PASSWORD` for wrong passwords on existing credential accounts.

### Task 3: Email Verification Session Ownership

**Files:**
- Modify: `packages/better_auth/lib/better_auth/routes/email_verification.rb`
- Test: `packages/better_auth/test/better_auth/routes/email_verification_test.rb`

- [x] Reuse the current session only when it belongs to the verified user.
- [x] Create a new session when a different user’s session cookie is present.
- [x] Add a regression test for verifying user B while user A is signed in.

### Task 4: Social OAuth State and ID Token Safety

**Files:**
- Modify: `packages/better_auth/lib/better_auth/routes/social.rb`
- Modify: `packages/better_auth/lib/better_auth/social_providers/base.rb`
- Test: `packages/better_auth/test/better_auth/routes/social_test.rb`
- Test: `packages/better_auth/test/better_auth/social_providers_test.rb`

- [x] Store OAuth state server-side or in a signed cookie and require callback correlation.
- [x] Reject callback state that is signed but missing or mismatched from the initiating browser context.
- [x] Remove the generic default that treats decoded ID-token payloads as verified.
- [x] Return upstream-style ID-token unsupported/invalid errors unless a provider supplies a real verifier.

### Task 5: Bounded External HTTP and JWKS Caching

**Files:**
- Create: `packages/better_auth/lib/better_auth/http_client.rb`
- Modify: `packages/better_auth/lib/better_auth.rb`
- Modify: request-path Net::HTTP call sites in `packages/better_auth/lib/better_auth`
- Test: focused plugin/provider tests for timeout options and JWKS caching

- [x] Route request-path `Net::HTTP` calls through an internal helper with explicit open/read timeouts.
- [x] Preserve existing verifier/fetcher hooks.
- [x] Cache One Tap and JWT remote JWKS responses with a conservative TTL.
- [x] Convert timeout failures into existing expected API errors.

### Task 6: Organization Throughput and Parity Coverage

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/organization.rb`
- Test: `packages/better_auth/test/better_auth/plugins/organization_test.rb`

- [x] Default omitted member-list limit to configured membership limit or `100`.
- [x] Clamp excessive limits.
- [x] Avoid per-member user lookup by bulk-loading users.
- [x] Add tests for limit, sorting/filtering basics, non-member rejection, and dynamic access-control cross-org regressions.

### Task 7: Additional Missing Security/Parity Tests

**Files:**
- Test: `packages/better_auth/test/better_auth/router_test.rb`
- Test: `packages/better_auth/test/better_auth/routes/session_routes_test.rb`
- Test: `packages/better_auth/test/better_auth/routes/social_test.rb`
- Test: `packages/better_auth/test/better_auth/password_test.rb`

- [x] Add disabled-path bypass cases for encoded paths, traversal-style normalization, unicode, and case variants.
- [x] Add `update_session` field filtering and cookie mutation tests.
- [x] Add deferred session refresh POST tests.
- [x] Add disabled social provider tests.
- [ ] Add legacy scrypt compatibility edge fixtures where Ruby has compatible fixtures.

### Verification

- [x] Run focused tests after each task with `rbenv exec bundle exec ruby -Itest <test-file>`.
- [x] Run `rbenv exec bundle exec standardrb`.
- [x] Run `rbenv exec bundle exec rake test`.
- [x] If local MySQL/Postgres fixture tests fail, record them as environment blockers unless the database fixtures are available.

Full-suite note: final `rbenv exec bundle exec rake test` completed with 856 runs and 4443 assertions, with 0 failures and 0 errors.

Code-review follow-up completed:

- Generic OAuth database-backed Rack callbacks now require the signed state cookie to exist and match the state value.
- Social provider JWKS fetches now go through the bounded HTTP helper and map fetch timeouts to invalid-token verification results.
- Organization member listing no longer invokes dynamic `membership_limit` functions on read paths; non-numeric dynamic limits default to `100` for listing.

# API Key Server Security And Parity Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `packages/better_auth-api-key` server behavior against request-mode identity spoofing, upstream parity gaps, cleanup failures, and avoidable blocking paths.

**Architecture:** Keep direct trusted server API behavior distinct from HTTP/request-mode behavior. Request-mode identity must come from a session, while direct server calls may use explicit `userId` as upstream allows. Cleanup remains incidental best-effort work and usage accounting stays authoritative before a key is accepted.

**Tech Stack:** Ruby, BetterAuth endpoint/plugin APIs, Minitest, Rack request tests, vendored Better Auth v1.6.9 as behavior reference.

---

### Task 1: Request-Mode Identity Hardening

**Files:**
- Modify: `packages/better_auth-api-key/test/better_auth/api_key/routes/create_api_key_test.rb`
- Modify: `packages/better_auth-api-key/test/better_auth/api_key/routes/update_api_key_test.rb`
- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/routes/create_api_key.rb`
- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/routes/update_api_key.rb`
- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/validation.rb`

- [x] Add failing request-mode tests for unauthenticated `userId` create/update and authenticated mismatched `userId`.
- [x] Reject request-mode `userId` authority unless it matches an authenticated session.
- [x] Keep direct server API calls with `userId` working.
- [x] Expand server-only create/update matrices for `rateLimitEnabled`, non-nil `remaining`, and permissions/quota fields.

### Task 2: Verify Multi-Config Parity

**Files:**
- Modify: `packages/better_auth-api-key/test/better_auth/api_key/routes/verify_api_key_test.rb`
- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/routes/verify_api_key.rb`
- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/validation.rb`

- [x] Add failing test for verifying a non-default config key without passing `configId`.
- [x] Allow omitted `configId` verification to search configured API-key backends and then resolve behavior from the matched record config.
- [x] Preserve explicit wrong `configId` rejection.

### Task 3: Cleanup Error Handling

**Files:**
- Modify: `packages/better_auth-api-key/test/better_auth/api_key/routes/index_test.rb`
- Modify: `packages/better_auth-api-key/test/better_auth/api_key/routes/list_api_keys_test.rb`
- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/routes/index.rb`
- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/routes/list_api_keys.rb`

- [x] Add failing tests showing incidental cleanup failures do not fail create/list/update/verify.
- [x] Make normal cleanup best-effort and logged.
- [x] Keep explicit delete-all-expired endpoint returning a failure payload when bypass cleanup itself fails.
- [x] Call cleanup once per list request, not once per returned key.

### Task 4: List Server Load Reduction

**Files:**
- Modify: `packages/better_auth-api-key/test/better_auth/api_key/routes/list_api_keys_test.rb`
- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/adapter.rb`
- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/routes/list_api_keys.rb`

- [x] Add tests with a recording adapter to prevent duplicate database scans across equivalent configs.
- [x] Group equivalent storage backends when no `configId` is supplied.
- [x] Push `limit`, `offset`, and `sort_by` into database adapter calls where one config maps directly to one reference filter.
- [x] Keep filtering by config/reference semantics correct after storage grouping.

### Task 5: Usage Accounting Concurrency

**Files:**
- Modify: `packages/better_auth-api-key/test/better_auth/api_key/validation_test.rb`
- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/adapter.rb`
- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/validation.rb`

- [x] Add concurrent verification tests for `remaining` in one Ruby process.
- [x] Do not defer quota/rate-limit mutations when doing so would allow overuse.
- [x] Use a per-key in-process lock around read/compute/write validation for the Ruby process; keep behavior compatible with all adapters.

### Task 6: Verification

- [x] Run focused tests:
  `rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb test/better_auth/api_key/routes/list_api_keys_test.rb test/better_auth/api_key/routes/create_api_key_test.rb test/better_auth/api_key/routes/update_api_key_test.rb test/better_auth/api_key/routes/verify_api_key_test.rb test/better_auth/api_key/routes/index_test.rb test/better_auth/api_key/validation_test.rb`
- [x] Run full package tests:
  `rbenv exec bundle exec rake test`
- [x] Run package style check:
  `rbenv exec bundle exec standardrb`

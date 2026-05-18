# Passkey Server Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden server-side passkey verification, credential ownership, and regression coverage while keeping documented Ruby-specific security improvements over upstream.

**Architecture:** Keep all behavior in `packages/better_auth-passkey`, using the existing route/helper split. Add tests before production changes, then tighten helper behavior and endpoint state transitions without changing public options.

**Tech Stack:** Ruby, Minitest, Rack-compatible Better Auth endpoints, `webauthn` gem, in-memory adapter tests.

---

### Task 1: Origin and RP Validation

**Files:**
- Modify: `packages/better_auth-passkey/lib/better_auth/passkey/utils.rb`
- Test: `packages/better_auth-passkey/test/better_auth/passkey/utils_test.rb`
- Test: `packages/better_auth-passkey/test/better_auth/passkey/routes/registration_test.rb`

- [x] Add failing tests that reject a request `Origin` not present in explicit `origin:` or the resolved configured `base_url`.
- [x] Add failing tests that explicit `origin:` arrays still allow any configured origin.
- [x] Implement allowed-origin resolution from `config[:origin]` or `ctx.context.base_url`/`ctx.context.options.base_url`, not from the request `Origin` header.
- [x] Make nonblank invalid `base_url` fail closed instead of silently returning `localhost`; preserve empty base URL fallback to `localhost`.
- [x] Run `rbenv exec bundle exec ruby -Itest test/better_auth/passkey/utils_test.rb` and the registration route tests.

### Task 2: Duplicate Registration and Create Failure Handling

**Files:**
- Modify: `packages/better_auth-passkey/lib/better_auth/passkey/routes/registration.rb`
- Modify: `packages/better_auth-passkey/lib/better_auth/passkey/credentials.rb`
- Test: `packages/better_auth-passkey/test/better_auth/passkey/routes/registration_test.rb`

- [x] Add failing tests for callback raise, adapter create raise, and duplicate create failure challenge cleanup.
- [x] Add a failing regression test proving a known duplicate `credentialID` is rejected before `WebAuthn::Credential.from_create`.
- [x] Add a helper to extract the response credential id before full WebAuthn verification.
- [x] Reject known duplicate IDs before expensive verification and keep the existing post-verification duplicate check.
- [x] Translate credential uniqueness failures to `400 PREVIOUSLY_REGISTERED`; keep unrelated create failures as `500 FAILED_TO_VERIFY_REGISTRATION`.
- [x] Run the registration route tests.

### Task 3: Authentication State Transitions

**Files:**
- Modify: `packages/better_auth-passkey/lib/better_auth/passkey/routes/authentication.rb`
- Test: `packages/better_auth-passkey/test/better_auth/passkey/routes/authentication_test.rb`

- [x] Add failing tests for passkey counter update returning `nil` and user lookup returning `nil`.
- [x] Require the counter update to succeed before creating a session.
- [x] Find the user before creating the session so missing users cannot leave orphan sessions.
- [x] Preserve challenge consumption on all verification outcomes.
- [x] Run the authentication route tests.

### Task 4: Management Enumeration Resistance

**Files:**
- Modify: `packages/better_auth-passkey/lib/better_auth/passkey/routes/management.rb`
- Test: `packages/better_auth-passkey/test/better_auth/passkey/routes/management_test.rb`

- [x] Add failing tests that missing and other-user passkey IDs produce the same `PASSKEY_NOT_FOUND` response for update and delete.
- [x] Query management endpoints by both `id` and current `userId`.
- [x] Preserve unchanged records for cross-user update/delete attempts.
- [x] Run the management route tests.

### Task 5: Replay and Rack Integration Coverage

**Files:**
- Test: `packages/better_auth-passkey/test/better_auth/passkey/routes/registration_test.rb`
- Test: `packages/better_auth-passkey/test/better_auth/passkey/routes/authentication_test.rb`
- Test: `packages/better_auth-passkey/test/better_auth/passkey/passkey_rack_test.rb`

- [x] Add success replay tests: reusing the same registration or authentication challenge fails with `CHALLENGE_NOT_FOUND`.
- [x] Add a Rack-level pre-auth registration test using `Rack::MockRequest` to verify `Set-Cookie`, context propagation, and resolved user fields.
- [x] Run `rbenv exec bundle exec rake test` from `packages/better_auth-passkey`.

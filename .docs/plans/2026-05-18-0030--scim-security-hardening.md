# SCIM Security Hardening Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `better_auth-scim` server behavior while preserving upstream parity unless a Ruby-specific security adaptation is explicit.

**Architecture:** Keep SCIM behavior inside `packages/better_auth-scim`; do not change core Better Auth APIs unless tests only inspect existing schema output. Add tests first for each security or parity regression, then update SCIM helpers/routes to make failures explicit and bounded.

**Tech Stack:** Ruby 3.2+, Better Auth Ruby plugin APIs, Rack, Minitest, `rbenv exec bundle exec rake test`.

---

## Checklist

- [x] Default `provider_ownership` to enabled for new SCIM providers; store `userId` on personal providers by default.
- [x] Preserve explicit legacy mode with `provider_ownership: { enabled: false }`, but document that it allows shared management of unowned personal providers.
- [x] Deny session management access to legacy unowned personal providers when ownership is enabled; bearer-token SCIM operations may continue until the provider is regenerated.
- [x] Require org-scoped bearer tokens to include the matching organization component during DB and `default_scim` verification.
- [x] Change `DELETE /scim/v2/Users/:id` to remove only the SCIM account link for the current provider, deleting the underlying Better Auth user only when it has no remaining accounts.
- [x] Parse and validate `filter` before early empty-list returns; use upstream-compatible `"Invalid filter expression"` details for malformed filters.
- [x] Fix `PUT /scim/v2/Users/:id` display-name fallback so it uses the selected primary/first email, matching upstream.
- [x] Return SCIM Error-shaped bodies for PATCH validation failures.
- [x] Add bounded validation for PATCH operation count and nested value depth.
- [x] Add SCIM list pagination support for `startIndex` and `count`; keep current default response shape when pagination params are absent.
- [x] Update `packages/better_auth-scim/README.md` for intentional Ruby security defaults and legacy ownership mode.
- [x] Run focused SCIM tests and the full `packages/better_auth-scim` test suite.

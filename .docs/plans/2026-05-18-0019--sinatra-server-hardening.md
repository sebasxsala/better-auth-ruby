# Sinatra Server Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `packages/better_auth-sinatra` server-only integration behavior against upstream parity drift, request-context loss, misconfiguration, and missing security coverage.

**Architecture:** Keep authentication semantics in core Better Auth. The Sinatra package should only normalize Rack mount behavior, pass real request context to core, validate Sinatra-specific configuration, and document the supported setup.

**Tech Stack:** Ruby 3.2+, Sinatra, Rack, RSpec, StandardRB, Better Auth Ruby core.

---

## Checklist

- [x] Preserve trailing slashes when forwarding matched auth requests from `BetterAuth::Sinatra::MountedApp` to core, while still normalizing only enough to decide mount membership.
- [x] Add Sinatra specs proving `/api/auth/ok/` returns core 404 by default and returns 200 only when `advanced: { skip_trailing_slashes: true }` is configured.
- [x] Change duplicate `better_auth` registration from warning-and-append to a clear `ArgumentError`.
- [x] Update the duplicate registration spec to expect the new error.
- [x] Change helper session lookup to call `auth.api.get_session(request: Rack::Request.new(request.env), method: "GET", as_response: true)` so request-aware hooks see the real Rack request without leaking the protected route's HTTP method into `get-session`.
- [x] Add helper specs for request object availability, app-set `Set-Cookie` preservation, vendor JSON accept negotiation, and helper error behavior.
- [x] Add mounted security parity specs for origin checks: missing/null/untrusted origin, unsafe redirect or callback values, and cross-site fetch metadata on mutating auth routes.
- [x] Harden Rake task config loading: support `BETTER_AUTH_CONFIG`/`OPEN_AUTH_CONFIG`, require an app config for migration-generation/migrate/routes tasks, and fail loudly when no config is loaded.
- [x] Add migration task specs for missing config, explicit config path, plugin schema inclusion, unsupported adapter, invalid dialect, and failed SQL before migration recording.
- [x] Document the shared config requirement and natural Rack nesting requirement in `packages/better_auth-sinatra/README.md`.

## Verification

- [x] Run `rbenv exec bundle exec rspec` from `packages/better_auth-sinatra`.
- [x] Run `rbenv exec bundle exec standardrb` from `packages/better_auth-sinatra`.

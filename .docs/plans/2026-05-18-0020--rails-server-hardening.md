# Rails Server Hardening Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `packages/better_auth-rails` server-only integration behavior, upstream parity, error handling, and test coverage.

**Architecture:** Keep authentication behavior in `packages/better_auth`; Rails stays a mounting, helper, generator, migration, and ActiveRecord adapter layer. Fix Rails glue where it changes core behavior or drops core side effects.

**Tech Stack:** Ruby, Rails/Railties, ActiveRecord, Rack, RSpec.

---

## Checklist

- [x] Fix `MountedApp` path reconstruction behind an outer `SCRIPT_NAME` / relative URL root.
- [x] Add Rails boundary handling for unexpected endpoint errors while preserving configured `on_api_error` throw/callback behavior.
- [x] Register mounted auth instances so controller helpers can use the same auth object as the Rails route.
- [x] Ensure controller helper session lookup clears Better Auth runtime state and forwards stale-cookie cleanup headers to Rails responses.
- [x] Fix ActiveRecord adapter creation for schema models without an `id` field, especially database-backed rate limits.
- [x] Align Rails migration string types with upstream by using `text` for long unindexed strings while preserving bounded ID-like/indexed fields.
- [x] Make Better Auth rake tasks depend on `:environment` so app initializers are loaded before generator config is read.
- [x] Add the missing `better_auth-passkey` development dependency used by Rails migration specs.
- [x] Bring README examples back in sync with the generated initializer and remove the local absolute docs path.

## Test Plan

- [x] Add routing specs for server-only plugin endpoints, mounted origin/callback security, mount path reconstruction, and unexpected endpoint errors.
- [x] Add controller helper specs for real signed cookies, custom mounted auth, runtime cleanup, and stale-cookie cleanup headers.
- [x] Add ActiveRecord adapter and migration specs for database rate-limit models without IDs and long token-like columns.
- [x] Add rake/generator coverage for Rails rake task environment loading and README/template drift.
- [x] Run focused Rails specs for routing, controller helpers, adapter, migration, generators, and rake tasks.
- [x] Run full `bundle exec rspec`; PostgreSQL/MySQL setup failures remain because local test databases/permissions are unavailable.

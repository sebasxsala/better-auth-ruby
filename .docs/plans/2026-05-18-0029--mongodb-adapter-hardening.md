# MongoDB Adapter Hardening Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the MongoDB adapter packages against expensive joins, unsafe pagination, raw runtime errors, and upstream parity drift.

**Architecture:** Runtime behavior changes belong in `packages/better_auth-mongodb`; `packages/better_auth-mongo-adapter` remains a deprecated compatibility package with mirrored tests and docs. The adapter should reject malformed caller input with controlled `BetterAuth::APIError` `BAD_REQUEST` errors before invoking MongoDB.

**Tech Stack:** Ruby 3.2+, Minitest, official `mongo` gem, Better Auth Ruby adapter contract.

---

### Task 1: Red Tests

**Files:**
- Modify: `packages/better_auth-mongodb/test/better_auth/adapters/mongodb_test.rb`
- Modify: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb`

- [x] Add tests proving joined queries paginate base records before `$lookup`.
- [x] Add tests for invalid `limit`, `offset`, join `limit`, and configured default fallback.
- [x] Add tests for empty update payload rejection and `_id` exclusion from valid updates.
- [x] Add tests for invalid date strings and malformed `where`/`join` shapes.
- [x] Add tests for scalar `in` rejection, scalar `not_in` retention, and default snake_case storage names.
- [x] Run each package test file and verify the new tests fail before implementation.

### Task 2: Runtime Hardening

**Files:**
- Modify: `packages/better_auth-mongodb/lib/better_auth/mongodb.rb`

- [x] Reorder `find_many` aggregation so base `$sort`, `$skip`, and `$limit` happen before join stages, with projection after joins.
- [x] Add positive integer validation for explicit limits and non-negative validation for offsets.
- [x] Treat invalid or non-positive `advanced.database.default_find_many_limit` as the default cap of 100.
- [x] Validate `where` entries, join maps, and explicit join `on` hashes before using them.
- [x] Reject scalar `in` values with `BAD_REQUEST`; keep scalar `not_in` coercion.
- [x] Raise `BAD_REQUEST` for invalid date strings and empty update documents.

### Task 3: Documentation

**Files:**
- Modify: `packages/better_auth-mongodb/README.md`
- Modify: `packages/better_auth-mongo-adapter/README.md`

- [x] Document positive pagination requirements and default-limit fallback.
- [x] Document scalar `in` rejection and scalar `not_in` behavior.
- [x] Document update `_id` stripping and default snake_case storage names.

### Task 4: Verification

- [x] Run `rbenv exec bundle exec rake test` in `packages/better_auth-mongodb`.
- [x] Run `rbenv exec bundle exec rake test` in `packages/better_auth-mongo-adapter`.
- [x] Confirm no files outside the MongoDB packages and saved plan were changed.

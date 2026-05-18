# Redis Storage Hardening Plan

**Summary**
- Plan file target: `.docs/plans/2026-05-18-0029--redis-storage-hardening.md`.
- Scope is only `packages/better_auth-redis-storage`.
- Fix confirmed package issues: upstream-shaped API gaps, unsafe Redis glob prefix matching, blocking `KEYS` default, SCAN/list/clear robustness, weak Redis integration coverage, and error-path tests.

**Public API Changes**
- Add upstream-shaped aliases:
  - `BetterAuth.redisStorage(...)`
  - `keyPrefix:` keyword support for `BetterAuth.redis_storage`, `BetterAuth.redisStorage`, `BetterAuth::RedisStorage.build`, `BetterAuth::RedisStorage.redisStorage`, and `BetterAuth::RedisStorage.new`.
- Keep `key_prefix:` as canonical Ruby spelling.
- Change omitted `scan_count` to default to `SCAN_DEFAULT_COUNT` and use SCAN.
- Keep explicit `scan_count: nil` as legacy upstream-compat mode using `KEYS`, documented as unsafe for large/shared Redis.

**Checklist**
- [x] Save this plan to `.docs/plans/2026-05-18-0029--redis-storage-hardening.md` with this checklist.
- [x] Update `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb` to resolve `key_prefix`/`keyPrefix` through a sentinel so conflicting explicit values raise `ArgumentError`.
- [x] Add `BetterAuth.redisStorage` as a module-level alias/builder.
- [x] Change default `scan_count` to `SCAN_DEFAULT_COUNT`; preserve explicit `scan_count: nil` for legacy `KEYS`.
- [x] Escape Redis glob metacharacters in prefixes before building `KEYS`/`SCAN` match patterns.
- [x] Make `scan_keys` return unique keys in first-seen order.
- [x] Make SCAN-backed `clear` collect the matched key set first, then delete, avoiding keyspace mutation during cursor iteration.
- [x] Keep command failures unrescued, but add tests proving Redis client errors propagate from `get`, `set`, `setex`, `del`, `keys`, `scan`, and `incr`.
- [x] Update `README.md` to document `keyPrefix`, `redisStorage`, SCAN default, explicit legacy `KEYS`, escaped prefixes, and operational notes.
- [x] Fix the atomic-clear integration test so it writes a stale key into the just-cleared generation, not an older generation.

**Test Plan**
- Unit tests in `test/better_auth/redis_storage_test.rb`:
  - aliases and `keyPrefix:` forwarding
  - conflicting prefix keywords raise
  - default SCAN path and explicit `scan_count: nil` KEYS path
  - escaped glob prefixes containing `*`, `?`, `[`, `]`, and `\`
  - SCAN duplicate de-duping
  - clear scans first, deletes after, and chunks deletes
  - expected Redis command errors propagate
- Real Redis integration tests in `test/better_auth/redis_storage_integration_test.rb`:
  - direct TTL expiry/TTL presence
  - verification and rate-limit keys get Redis TTLs
  - many-key SCAN list/clear with small `scan_count`
  - corrected `atomic_clear` stale-generation behavior
  - hashed verification identifiers do not expose raw identifiers in Redis keys and delete/update cleanup works
- Verification commands:
  - `rbenv exec bundle exec rake test`
  - `rbenv exec bundle exec standardrb`
  - `REDIS_INTEGRATION=1 REDIS_URL=redis://localhost:6379/15 rbenv exec bundle exec rake test:integration`

**Assumptions**
- No changes outside `packages/better_auth-redis-storage`.
- Core concurrency findings in rate limiting and active-session indexes are real risks, but fixing them requires `packages/better_auth` changes and is intentionally out of scope here.
- Diverging from upstream’s blocking `KEYS` default is accepted in favor of server safety.

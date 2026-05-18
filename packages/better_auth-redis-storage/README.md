# better_auth-redis-storage

Redis secondary storage package for Better Auth Ruby.

This gem tracks the server-side behavior of upstream `@better-auth/redis-storage`
pinned at Better Auth `v1.6.9`. The Ruby gem versions independently from the
upstream npm package; `BetterAuth::RedisStorage::VERSION` is the Ruby gem
version.

## Installation

Add the gem and require the package before configuring auth:

```ruby
gem "better_auth-redis-storage"
```

```ruby
require "redis"
require "better_auth/redis_storage"

redis = Redis.new(url: ENV.fetch("REDIS_URL"))

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: :memory,
  secondary_storage: BetterAuth.redis_storage(client: redis)
)
```

The canonical Ruby form is also supported:

```ruby
storage = BetterAuth::RedisStorage.new(client: redis)
```

For upstream-shaped call sites, use `BetterAuth.redisStorage(client: redis)` or
the camelCase class alias. The upstream `keyPrefix:` keyword is accepted
alongside the canonical Ruby `key_prefix:` keyword:

```ruby
storage = BetterAuth.redisStorage(client: redis, keyPrefix: "my-app:")
storage = BetterAuth::RedisStorage.redisStorage(client: redis, keyPrefix: "my-app:")
```

## Configuration

```ruby
storage = BetterAuth::RedisStorage.new(
  client: redis,
  key_prefix: "better-auth:",
  scan_count: BetterAuth::RedisStorage::SCAN_DEFAULT_COUNT,
  atomic_clear: false
)
```

`client` must respond to `get`, `set`, `setex`, `del`, and `scan`. It should
also respond to `keys` only when `scan_count: nil` is configured, and to `incr`
when `atomic_clear:` is enabled. This matches the interfaces exposed by the
`redis` and `redis-namespace` gems.

`key_prefix` defaults to `"better-auth:"`. `keyPrefix:` is accepted for
upstream-shaped call sites. Passing `nil` falls back to the default. Any other
value, including the empty string, is honored verbatim. Redis databases are not
isolation boundaries for shared clients; applications sharing a Redis instance
should use distinct prefixes.

`list_keys` and `clear` escape Redis glob metacharacters in `key_prefix` before
matching keys, so prefixes containing characters such as `*`, `?`, `[`, `]`, or
`\` are treated as literal namespace bytes.

> **Warning:** Passing `key_prefix: ""` puts Better Auth keys at the root of
> the selected Redis logical namespace. `list_keys` and `clear` then match `*`,
> so collisions across apps or tenants are possible and `clear` deletes every
> key in that Redis database. Use an application-specific prefix unless the
> Redis database is fully dedicated to Better Auth.

`scan_count` defaults to `BetterAuth::RedisStorage::SCAN_DEFAULT_COUNT` and uses
Redis `SCAN` for `list_keys` and `clear`. Set `scan_count:` to a larger positive
count such as `500` or `1000` to tune scan page size:

```ruby
storage = BetterAuth::RedisStorage.new(client: redis, scan_count: 500)
```

For exact legacy upstream behavior, pass `scan_count: nil` to use blocking
`KEYS "#{key_prefix}*"`. This is intended only for small or dedicated Redis
databases because `KEYS` can block Redis while it walks the keyspace:

```ruby
storage = BetterAuth::RedisStorage.new(client: redis, scan_count: nil)
```

`atomic_clear` is a Ruby-only opt-in for applications that need `clear` to be
logically atomic under concurrent writers:

```ruby
storage = BetterAuth::RedisStorage.new(
  client: redis,
  scan_count: 500,
  atomic_clear: true
)
```

When enabled, data keys are stored under a generation prefix such as
`better-auth:v1:<key>`. Calling `clear` atomically increments the generation key
so new reads and writes immediately move to the next generation. The previous
generation is then deleted best-effort, but correctness does not depend on that
physical cleanup finishing immediately.

## Behavior

The storage object implements the Better Auth secondary storage contract:

```ruby
storage.get(key)
storage.set(key, value, ttl = nil)
storage.delete(key)
storage.list_keys
storage.clear
```

`listKeys` is available as a camelCase alias for upstream parity.

`list_keys` returns every matching logical key but Redis does not guarantee key
order for `KEYS` or `SCAN`. The SCAN path removes duplicate cursor results while
preserving first-seen order. Sort the returned array in application code when a
stable order matters.

TTL handling for `set(key, value, ttl)`:

| TTL value | Redis command |
| --- | --- |
| `nil`, non-numeric strings, `0`, negative numbers, non-finite numbers | `set(prefixed_key, value)` |
| Positive `Integer` | `setex(prefixed_key, ttl, value)` |
| Positive finite `Float` or other `Numeric` values `>= 1` | `setex(prefixed_key, ttl.to_i, value)` |
| Positive finite `Float` or other `Numeric` values `< 1` | `set(prefixed_key, value)` |
| Positive numeric `String` | `setex(prefixed_key, ttl.to_i, value)` |

`set`, `delete`, and `clear` return `nil`, mirroring upstream's `Promise<void>`
contract in Ruby form. Tests and applications should assert stored values via
`get` rather than relying on truthy return values.

`clear` intentionally differs from upstream when there are no matching keys:
upstream calls `del(...keys)` even when `keys` is empty, while this Ruby gem
skips `del` to avoid Redis `ERR wrong number of arguments for 'del'`.
When keys do exist, `clear` deletes them in batches of
`BetterAuth::RedisStorage::DELETE_CHUNK_SIZE` keys per `del` call to avoid very
large Redis argument lists. The SCAN path collects the matched key set before
deleting it so cursor iteration is not affected by mutating the keyspace.

With `atomic_clear: true`, `clear` increments a generation key with Redis
`INCR`, making old generation keys immediately invisible to `get`, `set`,
`delete`, `list_keys`, and Better Auth itself. Cleanup of the old generation is
best-effort and uses `SCAN` by default.

Redis Cluster users should treat `list_keys` and `clear` as operationally
constrained helpers. This adapter does not scan every cluster node, and
multi-key `del` calls require keys to live in a compatible hash slot. Prefer a
single-slot prefix strategy such as Redis hash tags when using these helpers in
clustered deployments. `atomic_clear: true` improves the logical `clear`
contract because correctness uses a single `INCR` generation key, but physical
cleanup of old generations remains subject to the connected client's scan
coverage.

## Better Auth Usage

`secondary_storage` is used by Better Auth for session payload storage,
active-session indexes, verification values, and rate limiting when
`rate_limit: { storage: "secondary-storage" }` is configured.

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: :memory,
  secondary_storage: BetterAuth.redis_storage(client: redis),
  rate_limit: { storage: "secondary-storage", enabled: true }
)
```

Custom secondary storage backends should implement:

- `get(key)`
- `set(key, value, ttl = nil)`
- `delete(key)`
- Optional: `list_keys` or `listKeys`
- Optional: `clear`

## Testing

The normal unit suite skips real Redis unless explicitly enabled:

```bash
bundle exec rake test
```

Run the Redis integration suite with:

```bash
REDIS_INTEGRATION=1 REDIS_URL=redis://localhost:6379/15 bundle exec rake test:integration
```

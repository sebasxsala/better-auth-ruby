# better_auth-telemetry

Opt-in telemetry package for Better Auth Ruby. Ports the upstream
`@better-auth/telemetry` package (vendored at
`upstream/better-auth/1.6.9/packages/telemetry/`) using only Ruby's standard
library.

Telemetry is **disabled by default**. The package never sends data unless an
operator explicitly opts in, and it is automatically skipped when the host
process is running under `RACK_ENV=test`, `RAILS_ENV=test`, or `APP_ENV=test`.
It is not configured through `plugins: [...]`; it is an optional gem that core
soft-loads when available.

## Installation

Add the gem:

```ruby
gem "better_auth-telemetry"
```

When the gem is bundled, `BetterAuth::Auth#initialize` automatically wires
`auth.telemetry` to a publisher. When the gem is **not** bundled, `auth.telemetry`
is still safe to call: it returns a noop publisher whose `#publish` is a no-op.
Core's behavior is unchanged either way.

Require `better_auth/telemetry` only when using the telemetry API directly:

```ruby
require "better_auth/telemetry"
```

## Opting in

Two equivalent ways to opt in. Either is sufficient on its own.

### Via options

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: :postgres,
  telemetry: { enabled: true }
)
```

An explicit `telemetry: { enabled: false }` always wins over the env var:
setting `options[:telemetry][:enabled] = false` disables telemetry even when
`BETTER_AUTH_TELEMETRY=1` is set.

### Via environment variables

The package reads every variable through `BetterAuth::Env.get`, which honors
both the `BETTER_AUTH_*` and `OPEN_AUTH_*` prefixes. The `OPEN_AUTH_*` form
takes precedence over the `BETTER_AUTH_*` form when both are set.

| Purpose      | `BETTER_AUTH_*` form           | `OPEN_AUTH_*` form           |
|--------------|--------------------------------|------------------------------|
| Opt in       | `BETTER_AUTH_TELEMETRY`        | `OPEN_AUTH_TELEMETRY`        |
| Debug mode   | `BETTER_AUTH_TELEMETRY_DEBUG`  | `OPEN_AUTH_TELEMETRY_DEBUG`  |
| Endpoint URL | `BETTER_AUTH_TELEMETRY_ENDPOINT` | `OPEN_AUTH_TELEMETRY_ENDPOINT` |

A value is treated as truthy when it is non-empty, not equal to `"0"`, and not
equal to (case-insensitive) `"false"`. Unset and empty are both treated as
absent. No other telemetry environment variables are recognized.

```bash
export BETTER_AUTH_TELEMETRY=1
export BETTER_AUTH_TELEMETRY_ENDPOINT=https://telemetry.example.com/ingest
```

## Test environment skip

When `RACK_ENV`, `RAILS_ENV`, or `APP_ENV` equals `"test"`, or `TEST` is set to
a truthy value, telemetry is skipped even if it is otherwise opted in. Bypass
this skip by setting
`context[:skip_test_check] = true`. `skip_test_check` only bypasses the test
gate; it does not opt telemetry in on its own.

```ruby
BetterAuth::Telemetry.create(
  options,
  { skip_test_check: true } # opt-in still required via options or env
)
```

## Debug mode

When debug mode is on (`options[:telemetry][:debug] = true` or
`BETTER_AUTH_TELEMETRY_DEBUG` set to a truthy value), every event is logged via
the configured logger using `logger.info(JSON.pretty_generate(event))` and
**no HTTP request is made**. This is the recommended mode for inspecting what
the package would send before pointing it at a real endpoint.

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: :postgres,
  telemetry: { enabled: true, debug: true }
)
```

When neither debug mode nor `custom_track` is configured and an endpoint is
set, the publisher enqueues events into a bounded in-process dispatcher. A
single short-lived worker POSTs JSON events to the endpoint via `Net::HTTP` with
5-second open, read, and write timeouts. HTTP telemetry is fire-and-forget, so
constructing `BetterAuth.auth` and request-time `#publish` calls are not blocked
by a slow or unavailable endpoint. If the queue is full, the event is dropped
and a payload-free error is logged. Any `StandardError` raised during HTTP
delivery is rescued and logged at error level rather than propagated.

## The `custom_track` injection seam

`context[:custom_track]` is a callable (typically a `Proc` or lambda) that
receives every event in lieu of HTTP delivery. It is the testing seam used by
the gem's own test suite, and it is also useful in production to forward
events to an in-process queue, an audit log, or a custom collector.

```ruby
recorder = []
custom_track = ->(event) { recorder << event }

publisher = BetterAuth::Telemetry.create(
  { secret: "x", database: :memory, telemetry: { enabled: true } },
  { custom_track: custom_track, skip_test_check: true }
)

publisher.publish(type: "ping", payload: { hello: "world" })

# recorder now contains the init event plus { type: "ping", payload: { hello: "world" }, anonymousId: "..." }
```

If `custom_track` raises, the exception is rescued, logged at error level, and
swallowed; `#publish` always returns `nil`. The `anonymousId` on every event
emitted by a single publisher is the same string, derived from
`BetterAuth::Telemetry.project_id(base_url)`.

The package accepts both snake_case and camelCase keys on the context for
parity with callers mirroring upstream type definitions: `:custom_track` and
`:customTrack` are equivalent, as are `:skip_test_check` and `:skipTestCheck`.

## Differences from upstream

The upstream `@better-auth/telemetry` package targets multiple JavaScript
runtimes (Node, Bun, Deno, edge) and ships two build entrypoints. This Ruby
port collapses both upstream variants into a single server-side Ruby
implementation and adapts every detector to idiomatic Ruby. The wire format
preserves upstream camelCase keys and redaction rules so existing telemetry
consumers can ingest events from Ruby projects without schema branching.

The intentional Ruby-specific deviations are:

- **Single Ruby implementation.** No Node, Bun, Deno, or edge runtime
  branches. Detectors do not probe for `npm_config_user_agent`, do not walk
  `node_modules`, and do not classify against JavaScript-only runtimes.
- **`runtime.engine` extra key.** The runtime payload includes an `:engine`
  key (`"ruby"`, `"jruby"`, `"truffleruby"`) sourced from `RUBY_ENGINE` so
  consumers can distinguish Ruby implementations. Upstream emits only `name`
  and `version`.
- **`cpuSpeed` omitted.** Upstream's `systemInfo.cpuSpeed` field is not
  emitted at all on the Ruby side. There is no portable Ruby standard-library
  API for CPU speed, and emitting `nil` would invite consumers to assume the
  field can ever be populated.
- **`cpuModel` always `nil`.** The `systemInfo.cpuModel` key is present in the
  payload (so the schema matches upstream) but is always `nil`. Ruby has no
  portable standard-library API for the CPU model string.
- **`packageManager` reflects Bundler, not npm.** When Bundler is loadable
  and a Gemfile is locatable, `payload.packageManager` is
  `{ name: "bundler", version: Bundler::VERSION }`. Otherwise the field is
  `nil`. Upstream's `npm_config_user_agent` parsing has no Ruby analogue.
- **Framework probe list is Ruby-specific.** The framework detector inspects
  `Gem.loaded_specs` for `rails`, `sinatra`, `hanami`, `hanami-router`,
  `roda`, `grape`, `rack` (in that order). Node-only frameworks (`next`,
  `nuxt`, `astro`, `sveltekit`, `solid-start`, `tanstack-start`, `hono`,
  `express`, `elysia`, `expo`) are intentionally not probed.
- **Database probe list is Ruby-specific.** The database detector falls back
  to `Gem.loaded_specs` for `sequel`, `pg`, `mysql2`, `sqlite3`,
  `activerecord`, `mongoid`, `mongo`, `rom-sql` (in that order) when no
  context override or `BetterAuth::Adapters::*` adapter class match is found.
  Known Better Auth adapter classes are reported as `memory`, `postgres`,
  `mysql`, `sqlite`, `mssql`, or `mongodb`. When core passes the generic
  `"adapter"` database marker for an external adapter, telemetry refines it
  from `context.adapter` only when the adapter class is known; unknown
  namespaced adapters remain the generic `"adapter"` marker.
- **Telemetry tests validate metadata only.** This package does not boot real
  Rails, Sinatra, Hanami, or database-backed applications, and it does not run
  rate-limit behavior against every storage backend. Those behaviors belong to
  the framework, adapter, and core packages. Telemetry coverage is intentionally
  limited to detector precedence, redaction shape, opt-in decisions, and
  delivery behavior.
- **Standard library only HTTP.** HTTP delivery uses `Net::HTTP` with 5-second
  open, read, and write timeouts behind a bounded single-worker dispatcher. No
  external HTTP-client gem is required at runtime, and HTTP delivery does not
  block `BetterAuth.auth` construction or request-time `#publish` calls.
- **Safer Ruby telemetry redaction.** Ruby object values that JavaScript would
  omit or stringify unsafely are reduced before delivery. Field maps,
  additional-field maps, trusted-provider lists, custom cookie/header lists,
  `advanced.database.generateId`, `onAPIError.errorURL`, and unknown namespaced
  adapter class names are emitted as counts, booleans, or the generic
  `"adapter"` marker instead of raw app-specific values.
- **Explicit false is a strong opt-out.** `telemetry: { enabled: false }`
  disables telemetry even when `BETTER_AUTH_TELEMETRY` or `OPEN_AUTH_TELEMETRY`
  is truthy. This is intentionally stricter than upstream so application
  configuration can override process-wide env vars.
- **snake_case canonical context keys, with camelCase synonyms accepted.**
  The Ruby-canonical context keys are `:custom_track`, `:database`,
  `:adapter`, `:skip_test_check`. The package also accepts the camelCase
  variants (`:customTrack`, `:skipTestCheck`) for parity with callers
  mirroring upstream type definitions.
- **`appName` is not emitted.** The `app_name` value is used internally by
  `BetterAuth::Telemetry.project_id` to derive the `anonymousId` but is
  intentionally not emitted as a payload field, since it can be
  user-identifying.
- **Project IDs are keyed by derivation input.** A process hosting multiple
  auth instances can derive distinct anonymous IDs for distinct
  `app_name`/`base_url` pairs. When no app name is configured, the Ruby fallback
  uses the Bundler root directory name rather than the first locked dependency.
- **Public `BetterAuth::Telemetry.reset_project_id!` testing helper.** A
  module-level helper is exposed for resetting the memoized
  `anonymous_id` between tests. It has no effect on production behavior and
  exists solely so test suites can assert deterministic project_id derivation
  across opt-in / opt-out cycles.

## License

MIT

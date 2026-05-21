# Better Auth Ruby Examples

These apps exercise the same Better Auth flows across the supported Ruby stacks:
Vanilla Rack, Rails, Sinatra, Hanami, Grape, and Roda.

Each app mounts:

- `/` - shared light-mode dashboard
- `/api/auth` - the framework-specific Better Auth integration
- `/example/*` - dashboard utility endpoints for settings, database inspection, and reset

## Start Shared Services

Use the isolated examples compose file when you already have local databases on
the usual ports:

```bash
docker compose -f examples/compose.yml up -d redis postgres mysql mongodb mssql mongodb-init mssql-init
```

SQLite and memory mode do not need Docker. External database defaults:

| Provider | Default URL |
| --- | --- |
| Postgres | `postgres://user:password@127.0.0.1:15432/better_auth` |
| MySQL | `mysql2://user:password@127.0.0.1:13306/better_auth` |
| MongoDB | `mongodb://127.0.0.1:27018/better_auth?directConnection=true` |
| MSSQL | `tinytds://sa:Password123!@127.0.0.1:11433/better_auth` |
| Redis | `redis://127.0.0.1:16379/0` |

Override them with `BETTER_AUTH_EXAMPLE_POSTGRES_URL`,
`BETTER_AUTH_EXAMPLE_MYSQL_URL`, `BETTER_AUTH_EXAMPLE_MONGODB_URL`,
`BETTER_AUTH_EXAMPLE_MSSQL_URL`, and `BETTER_AUTH_EXAMPLE_REDIS_URL`.

The repository root `docker-compose.yml` still uses the standard ports
`5432`, `3306`, `27017`, `1433`, and `6379` for package tests. The examples
compose file intentionally uses alternate host ports so it does not interact
with existing `openauth-*` or other local containers.

## Run Apps

Run `bundle install` inside each example before the first boot.

Recommended launcher from the repository root:

```bash
examples/bin/serve rails
examples/bin/serve vanilla
examples/bin/serve sinatra
examples/bin/serve hanami
examples/bin/serve grape
examples/bin/serve roda
```

The launcher picks the first free port starting from the app default and sets
`BETTER_AUTH_URL` plus the example database URLs for the isolated compose file.

For day-to-day development, add `--watch` so the app restarts automatically when
you change files in the selected example, `examples/shared`, or `packages`:

```bash
examples/bin/serve --watch rails
examples/bin/serve --watch vanilla
examples/bin/serve --watch sinatra
examples/bin/serve --watch hanami
examples/bin/serve --watch grape
examples/bin/serve --watch roda
```

| App | Command | URL |
| --- | --- | --- |
| Vanilla Rack | `examples/bin/serve vanilla` | starts at <http://localhost:9292> |
| Sinatra | `examples/bin/serve sinatra` | starts at <http://localhost:4567> |
| Rails | `examples/bin/serve rails` | starts at <http://localhost:3000> |
| Hanami | `examples/bin/serve hanami` | starts at <http://localhost:2300> |
| Grape | `examples/bin/serve grape` | starts at <http://localhost:9292> |
| Roda | `examples/bin/serve roda` | starts at <http://localhost:9293> |

Manual commands still work. If you pick a custom port manually, set
`BETTER_AUTH_URL=http://localhost:<port>` too.

## Dashboard

The dashboard provides:

- Email/password sign up, sign in, and sign out.
- Current user display with avatar, name, and email.
- `get-session` and `list-sessions` viewers.
- Seeded users view with quick sign-in for admin, normal users, and
  organization members.
- Organization view with a dropdown to switch between one organization at a
  time and inspect its members, emails, and roles.
- Database explorer with tables/collections, columns, row counts, column filters,
  record scrolling, and reload.
- Drop-and-migrate, plus drop-migrate-and-seed for the selected provider.
- Runtime database provider switching.
- Runtime rate-limit adapter switching between memory and Redis.

Changing the database provider or rate-limit settings clears Better Auth session
cookies because the selected auth instance may point at different user/session
storage.

## Drop And Migrate

The reset button drops only Better Auth tables/collections for the active
provider, then recreates schema:

- SQL providers use Better Auth SQL schema generation and migration execution.
- MongoDB drops Better Auth collections and recreates indexes.
- Memory mode invalidates the in-process auth instance.
- SQLite uses a local file under the example app `tmp/` directory.

The seed button performs the same reset and then creates local test data:
example users, an admin user, organizations, organization memberships and
representative plugin records for API key, device authorization, JWT/JWKS, SSO,
OAuth/OIDC provider tables, SCIM, passkey, SIWE wallet addresses, Stripe
subscriptions, and two-factor tables where the enabled plugin schema is
available. All seeded email users use `password123` so the dashboard can switch
sessions quickly.

## Notes

These examples are local development fixtures. They intentionally keep auth
behavior in the shared Better Auth packages and use the framework packages only
for mounting and integration.

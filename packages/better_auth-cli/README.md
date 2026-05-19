# better_auth-cli

Command-line tools for Better Auth Ruby.

```bash
better-auth generate --config config/better_auth.rb --dialect postgres --output db/better_auth/schema.sql
better-auth migrate --config config/better_auth.rb --yes
better-auth migrate status --config config/better_auth.rb
better-auth doctor --config config/better_auth.rb
better-auth mongo indexes --config config/better_auth.rb
```

The config file should return a `Hash` or `BetterAuth::Configuration`.
`doctor` validates the config, secret strength, HTTPS base URL, rate-limit
storage, SQL adapter support, and pending Better Auth migrations.
`mongo indexes` is for MongoDB adapters and idempotently ensures the indexes
declared by the active Better Auth schema.

Install `openauth-cli` for the `openauth` executable alias.

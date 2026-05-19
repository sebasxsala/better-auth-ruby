# openauth-cli

Command-line alias for Better Auth Ruby.

```bash
openauth generate --config config/better_auth.rb --dialect postgres --output db/better_auth/schema.sql
openauth migrate --config config/better_auth.rb --yes
openauth migrate status --config config/better_auth.rb
openauth doctor --config config/better_auth.rb
openauth mongo indexes --config config/better_auth.rb
```

This package depends on `better_auth-cli` and publishes the `openauth`
executable.

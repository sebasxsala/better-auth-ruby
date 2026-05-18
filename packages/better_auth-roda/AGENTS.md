# Roda Package Guide

Read this file when editing `packages/better_auth-roda/`.

This package is the Roda integration layer for `better_auth`. Keep
authentication behavior in `packages/better_auth`; this package should focus on
Roda plugin mounting, helpers, configuration glue, SQL migration tasks, docs,
and Roda-specific tests.

## Boundaries

- Do not duplicate core auth behavior here.
- Prefer delegating to `BetterAuth` core APIs instead of reimplementing flows.
- Keep Roda-only assumptions inside this package.
- Do not add a Sequel-specific default adapter; Roda apps must configure the
  desired core database adapter explicitly.

## Testing

Use the package's existing RSpec setup for Roda integration coverage:

```bash
bundle exec rspec
```

When behavior depends on core auth semantics, add or update tests in
`packages/better_auth` as well.

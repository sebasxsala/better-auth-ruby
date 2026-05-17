# Repository Guide

This repository is a Ruby port of Better Auth. Keep behavior aligned with the
vendored upstream Better Auth source unless a Ruby-specific adaptation is
explicitly documented.

## Before Editing

- Read this file before making repository changes.
- Package-level `AGENTS.md` files are optional. Read one only when it exists in
  the package you are editing; it adds package-specific rules to this guide.
- For features that mirror Better Auth, review the matching upstream source and
  tests before changing behavior.

## Upstream Source of Truth

Target upstream version: Better Auth `v1.6.9`, fixed at commit
`f484269228b7eb8df0e2325e7d264bb8d7796311`.

The upstream source is vendored at:

```text
upstream/better-auth/1.6.9/
```

Common reference paths:

- `upstream/better-auth/1.6.9/packages/better-auth/src/` - core auth logic
- `upstream/better-auth/1.6.9/packages/better-auth/src/plugins/` - plugins
- `upstream/better-auth/1.6.9/**/*.test.ts` - upstream behavior tests

Adapt the behavior to idiomatic Ruby. Do not make a line-by-line TypeScript port
when Ruby structure, naming, or error handling should differ.

## Packages

| Package | Purpose |
| --- | --- |
| `packages/better_auth` | Core Rack-compatible authentication library. Framework-agnostic. |
| `packages/better_auth-rails` | Rails integration: engine, generators, helpers, and Rails-specific tests. |
| `packages/better_auth-sinatra` | Sinatra integration: mounting, helpers, migration tasks, docs, and tests. |
| `packages/better_auth-hanami` | Hanami integration layer. |
| `packages/better_auth-api-key` | API key plugin. |
| `packages/better_auth-oauth-provider` | OAuth provider plugin. |
| `packages/better_auth-passkey` | Passkey/WebAuthn plugin. |
| `packages/better_auth-scim` | SCIM provisioning plugin. |
| `packages/better_auth-sso` | SSO plugin. |
| `packages/better_auth-stripe` | Stripe plugin. |
| `packages/better_auth-redis-storage` | Redis secondary storage package. |
| `packages/better_auth-mongodb` | MongoDB adapter package. |
| `packages/better_auth-mongo-adapter` | Legacy MongoDB adapter package kept for compatibility. |
| `packages/openauth*` | Alias packages that install or expose the corresponding `better_auth*` packages. |

Keep shared authentication behavior in `packages/better_auth`. Adapter and
framework packages should provide integration code, tasks, generators, docs, and
tests around the core behavior.

## Documentation

Documentation lives in a few places:

- `README.md` - repository overview and getting-started entry point.
- `packages/*/README.md` - package-specific usage and installation notes.
- `docs/` - documentation website app.
- `docs/content/docs/` - main user-facing documentation pages.
- `docs/content/blogs/` and `docs/content/changelogs/` - website blog and
  changelog content.
- `examples/` - runnable examples that should match documented setup flows.
- `.docs/` - internal project notes, plans, and agent-facing working documents.

When changing public behavior, update the relevant package README and website
docs if users need to know about the change. Keep internal notes in `.docs/`;
do not put agent plans or scratch material in the public docs site.

## Plans

Only create a saved implementation plan when the user asks for a plan, asks to
save one, or the task is explicitly being handed off to another agent/session.

Saved plans belong in `.docs/plans/` and use this filename format:

```text
YYYY-MM-DD-HHMM--short-name.md
```

Use checkbox steps so progress can be marked as work is completed. Update the
plan when a phase completes, upstream behavior differs meaningfully, or a
Ruby-specific adaptation is chosen.

## Testing

- Avoid mocks unless the real dependency is impractical.
- Test observable behavior instead of implementation details.
- Prefer database-backed tests over in-memory substitutes when database behavior
  matters.
- Check upstream tests for behavior and edge-case coverage before porting or
  changing upstream-backed features.

## Versioning and Releases

Version each gem independently.

- Only bump versions for gems being released.
- Do not bump versions for normal unreleased commits.
- Patch: backward-compatible fixes and internal/docs/CI updates.
- Minor: new public behavior/options/endpoints, and breaking public changes
  while still pre-`1.0`.
- Major: breaking public API changes after `1.0`.

Prerelease versions such as `0.2.0.beta.1` are appropriate for validation before
stable release. Release tags must exactly match package versions.

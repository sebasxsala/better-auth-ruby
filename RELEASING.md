# Releasing

This document describes the release process for Better Auth Ruby gems.

Keep this file named `RELEASING.md`; that is the conventional GitHub/Ruby
project name for release instructions.

## Release Workflow

Releases are handled by `.github/workflows/release.yml`.

The workflow publishes one `better_auth*` package per package-prefixed tag. A
tag must match the package version exactly:

| Gem | Release tag |
| --- | --- |
| `better_auth` | `better_auth-vX.Y.Z` |
| `better_auth-rails` | `better_auth-rails-vX.Y.Z` |
| `better_auth-passkey` | `better_auth-passkey-vX.Y.Z` |
| `better_auth-sinatra` | `better_auth-sinatra-vX.Y.Z` |
| `better_auth-hanami` | `better_auth-hanami-vX.Y.Z` |
| `better_auth-api-key` | `better_auth-api-key-vX.Y.Z` |
| `better_auth-oauth-provider` | `better_auth-oauth-provider-vX.Y.Z` |
| `better_auth-redis-storage` | `better_auth-redis-storage-vX.Y.Z` |
| `better_auth-mongodb` | `better_auth-mongodb-vX.Y.Z` |
| `better_auth-mongo-adapter` | `better_auth-mongo-adapter-vX.Y.Z` |
| `better_auth-scim` | `better_auth-scim-vX.Y.Z` |
| `better_auth-sso` | `better_auth-sso-vX.Y.Z` |
| `better_auth-stripe` | `better_auth-stripe-vX.Y.Z` |

Stable release tags must be contained in `main` or a `vX.Y.x` maintenance
branch. Prerelease tags, such as `0.8.0.beta.1`, may also be contained in
`canary`.

The workflow can also be run manually with `workflow_dispatch`:

- `dry_run: true` builds and validates without publishing.
- `publish_openauth_aliases: true` publishes the `openauth*` alias gems.

## Package Order

Publish packages in dependency order. RubyGems must already have dependency
versions available before dependent gems are pushed.

1. `better_auth`
2. Packages that depend on `better_auth`:
   `better_auth-api-key`, `better_auth-hanami`, `better_auth-mongodb`,
   `better_auth-oauth-provider`, `better_auth-passkey`,
   `better_auth-rails`, `better_auth-redis-storage`, `better_auth-scim`,
   `better_auth-sinatra`, `better_auth-sso`, and `better_auth-stripe`.
3. Compatibility or alias gems that pin package versions:
   `better_auth-mongo-adapter` after `better_auth-mongodb`, and
   `better_auth_rails` with `better_auth-rails`.
4. OpenAuth alias gems after their matching `better_auth*` packages are live:
   `openauth`, `openauth-api-key`, `openauth-hanami`, `openauth-mongodb`,
   `openauth-oauth-provider`, `openauth-passkey`, `openauth-rails`,
   `openauth-redis-storage`, `openauth-scim`, `openauth-sinatra`,
   `openauth-sso`, and `openauth-stripe`.

For MongoDB specifically, release `better_auth-mongodb` first. Only publish
`better_auth-mongo-adapter` when you want to update the deprecated compatibility
package; it depends on the exact `better_auth-mongodb` version.

## Version Files

Each gem has independent versioning. Update only the package versions being
released.

| Gem | Version file |
| --- | --- |
| `better_auth` | `packages/better_auth/lib/better_auth/version.rb` |
| `better_auth-rails` | `packages/better_auth-rails/lib/better_auth/rails/version.rb` |
| `better_auth-sinatra` | `packages/better_auth-sinatra/lib/better_auth/sinatra/version.rb` |
| `better_auth-hanami` | `packages/better_auth-hanami/lib/better_auth/hanami/version.rb` |
| `better_auth-redis-storage` | `packages/better_auth-redis-storage/lib/better_auth/redis_storage/version.rb` |
| `better_auth-mongodb` | `packages/better_auth-mongodb/lib/better_auth/mongodb/version.rb` |
| `better_auth-mongo-adapter` | `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter/version.rb` |
| `better_auth-api-key` | `packages/better_auth-api-key/lib/better_auth/api_key/version.rb` |
| `better_auth-passkey` | `packages/better_auth-passkey/lib/better_auth/passkey/version.rb` |
| `better_auth-oauth-provider` | `packages/better_auth-oauth-provider/lib/better_auth/oauth_provider/version.rb` |
| `better_auth-scim` | `packages/better_auth-scim/lib/better_auth/scim/version.rb` |
| `better_auth-sso` | `packages/better_auth-sso/lib/better_auth/sso/version.rb` |
| `better_auth-stripe` | `packages/better_auth-stripe/lib/better_auth/stripe/version.rb` |

Alias package versions are currently declared directly in their gemspecs under
`packages/openauth-*` and `packages/openauth`.

## Dependency Matrix

| Gem | Internal dependency |
| --- | --- |
| `better_auth-*` plugins/adapters, except `better_auth-mongo-adapter` | `better_auth ~> 0.1` |
| `better_auth-mongo-adapter` | `better_auth-mongodb = X.Y.Z` |
| `better_auth_rails` | `better_auth-rails = X.Y.Z` |
| `openauth` | `better_auth = X.Y.Z` |
| `openauth-*` aliases | matching `better_auth-* = X.Y.Z` |

When bumping a package to a new public minor line, update dependency constraints
where needed. For example, after `better_auth` reaches a version where `~> 0.1`
is no longer appropriate, update dependent gemspecs before publishing them.

## Release Process

### 1. Prepare

Start from a stable branch and make sure CI is clean:

```bash
git checkout canary
git pull origin canary
rake ci
```

For a stable release, merge `canary` to `main` after validation:

```bash
git checkout main
git pull origin main
git merge canary
git push origin main
```

### 2. Update Versions and Changelogs

For each package being released:

- Update its version file or alias gemspec version.
- Update the package changelog.
- Update root `CHANGELOG.md` when the release is notable at the repo level.
- Update pinned alias dependencies if the alias package is being released.

Do not bump versions for normal unreleased commits.

### 3. Validate

Run the package test suite and linter for every package being released. For a
full release set, run:

```bash
rake ci
```

Validate the GitHub Actions release workflow without publishing:

```text
Actions -> Release -> Run workflow -> dry_run: true
```

### 4. Tag Packages

Create one tag per package you want GitHub Actions to publish:

```bash
git tag -a better_auth-v0.7.0 -m "Release better_auth 0.7.0"
git push origin better_auth-v0.7.0
```

For a multi-package release, push tags in dependency order. Example MongoDB
compatibility release:

```bash
git tag -a better_auth-mongodb-v0.7.0 -m "Release better_auth-mongodb 0.7.0"
git push origin better_auth-mongodb-v0.7.0

git tag -a better_auth-mongo-adapter-v0.7.0 -m "Release better_auth-mongo-adapter 0.7.0"
git push origin better_auth-mongo-adapter-v0.7.0
```

### 5. Publish OpenAuth Aliases

OpenAuth alias packages are published through the manual workflow, not package
tags:

```text
Actions -> Release -> Run workflow
dry_run: false
publish_openauth_aliases: true
```

Run this only after the matching `better_auth*` packages are available on
RubyGems.

### 6. Version Branches

Use version branches for active release lines:

| Branch | Purpose |
| --- | --- |
| `canary` | Active development. All PRs merge here first. |
| `main` | Stable releases. Merges from `canary` when ready. |
| `v0.x` | Latest of the 0.x release line. |
| `v1.0.x`, `v1.1.x`, ... | Future maintenance release lines. |

Major and minor versions get their own branch. Patch versions do not.

```bash
git checkout -b v0.x main
git push origin v0.x
```

For later patches:

```bash
git checkout v0.x
git merge main
git push origin v0.x
```

## Manual Publish

Prefer GitHub Actions. Manual publish is only for recovery.

```bash
cd packages/better_auth-mongodb
gem build better_auth-mongodb.gemspec
gem push better_auth-mongodb-0.7.0.gem
```

If publishing a dependent gem manually, confirm its dependency version already
exists on RubyGems first.

## Post-Release Checks

- Verify every pushed gem appears on RubyGems.
- Verify the GitHub Release was created from the package tag.
- Install the released gem in a scratch app when the release touches packaging
  or dependencies.
- Announce the release if it includes user-facing behavior.

## Hotfix Process

For urgent fixes to a released version:

```bash
git checkout v0.x
git checkout -b fix/critical-bug
# ... make fix ...
git commit -m "fix(core): resolve critical auth bypass"
# PR into v0.x, then cherry-pick to canary
```

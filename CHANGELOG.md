# Changelog

This repository contains independently versioned Ruby packages. Package-specific
release notes live in each package's `CHANGELOG.md`.

## 2026-05-05

### 0.7.0 release set

- `better_auth` `0.7.0`: completed OpenAPI support with upstream base-route schema parity, richer plugin endpoint schemas, Scalar reference parity, hardened OAuth token/client-secret behavior, MCP OAuth-provider alignment, join-query handling, router hardening, and host-app responsibility docs.
- `better_auth-api-key` `0.7.0`: hardened API key sessions by exposing token fingerprints instead of raw keys, improved listing and cleanup behavior, and expanded metadata and cleanup coverage.
- `better_auth-hanami` `0.7.0`: aligned Sequel adapter query behavior, route mounting, action helpers, and install/migration generators with the shared adapter semantics.
- `better_auth-mongodb` `0.7.0`: added Mongo index setup helpers, default `find_many` limits, upstream-shaped connector handling, scalar `not_in` support, and stronger transaction/index documentation.
- `better_auth-oauth-provider` `0.7.0`: hardened consent, metadata, revocation, token, logout, endpoint rate-limit, and constant-time secret flows.
- `better_auth-passkey` `0.7.0`: hardened WebAuthn challenge invalidation, duplicate credential checks, registration verification errors, and session freshness requirements.
- `better_auth-rails` `0.7.0`: aligned Active Record adapter behavior, trusted-origin/controller-helper handling, configuration secrets, and MySQL/PostgreSQL integration coverage.
- `better_auth-redis-storage` `0.7.0`: hardened Redis key validation, TTL coercion, chunked and streaming clears, optional atomic clears, and real Redis CI coverage.
- `better_auth-scim` `0.7.0`: hashes generated provider tokens by default and splits provider management/validation flows with improved SCIM user and patch behavior.
- `better_auth-sinatra` `0.7.0`: hardened mounted path dispatch, root mount validation, migration parsing, JSON auth errors, repeated configuration warnings, and route/task docs.
- `better_auth-sso` `0.7.0`: hardened SAML configuration, OIDC callback state/nonce checks, exact TXT domain verification, JWT runtime dependency, and metadata XML coverage.
- `better_auth-stripe` `0.7.0`: requires verified Stripe webhook construction, adds webhook origin hardening, and keeps subscription route middleware coverage aligned with upstream behavior.

## 2026-04-29

### Release candidates

- `better_auth` `0.3.0`: upstream v1.6.9 parity for social providers, OAuth/OIDC protocol behavior, routes, schemas, adapters, and plugin hooks.
- `better_auth-rails` `0.2.1`: Active Record adapter falsey-value lookup and JSON/array migration type fixes.
- `better_auth-api-key` `0.2.0`: upstream v1.6.9 API key behavior, route shapes, metadata, permissions, expiration, and rate-limiting parity.
- `better_auth-hanami` `0.1.1`: route generator, mounted path, migration type, and Sequel adapter fixes.
- `better_auth-oauth-provider` `0.2.0`: upstream v1.6.9 OAuth provider behavior for dynamic clients, consent, token, discovery, userinfo, revocation, and session flows.
- `better_auth-passkey` `0.2.0`: upstream server parity for passkey registration, authentication, credential metadata, verification, and origin handling.
- `better_auth-redis-storage` `0.2.0`: upstream-shaped Redis storage builders, optional `SCAN` support, and expanded compatibility coverage.
- `better_auth-scim` `0.2.0`: upstream SCIM provisioning parity for users, groups, filters, patch operations, schema responses, and token behavior.
- `better_auth-sinatra` `0.1.1`: mounted base-path, session helper, and migration dialect normalization fixes.
- `better_auth-sso` `0.2.0`: upstream SSO parity for OIDC, SAML, organization flows, metadata, account linking, and error shapes.
- `better_auth-stripe` `0.2.0`: upstream Stripe parity for checkout, portal, subscriptions, webhooks, customers, and organization billing.

### Held

- `better_auth-mongo-adapter` remains at `0.1.0`; it is documented for a future first publish but was not version-bumped with this release set.

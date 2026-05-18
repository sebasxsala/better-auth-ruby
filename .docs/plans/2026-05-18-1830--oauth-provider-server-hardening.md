# OAuth Provider Server Hardening Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Harden the Ruby OAuth provider server package against upstream parity, security, error-shape, and blocking-behavior gaps found during package-only audit.

**Architecture:** Keep public OAuth provider behavior aligned with Better Auth v1.6.9. Implement shared OAuth protocol fixes in `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb` only where this package depends on the shared helper, and keep endpoint behavior in `packages/better_auth-oauth-provider`.

**Tech Stack:** Ruby, BetterAuth core/plugin endpoints, Minitest, Rack-compatible API responses.

---

## Checklist

- [x] Add failing tests for client auth method enforcement: `client_secret_basic` must use Basic auth, `client_secret_post` must use body credentials, `none` must not send a secret, malformed Basic auth returns expected OAuth errors.
- [x] Fix `authenticate_client!` to enforce `tokenEndpointAuthMethod`, enforce `clientSecretExpiresAt`, and make auth-code exchange consume codes using the authenticated client id.
- [x] Add `Cache-Control: no-store` and `Pragma: no-cache` to all token responses.
- [x] Add failing tests for public clients opting out of PKCE, mixed `prompt=none login/consent/select_account`, `localhost` loopback port mismatch, and `request_uri` preserving only front-channel `client_id`.
- [x] Fix PKCE so public clients always require PKCE; fix request URI resolution to match upstream PAR semantics; reject invalid prompt combinations with protocol-shaped errors.
- [x] Add failing tests for code exchange after deleted/expired session, code replay, missing token params, disabled clients, and invalid redirect/client mismatch.
- [x] Fix token lifecycle parity: reload user/session before issuing code tokens, issue refresh tokens only with `offline_access`, and revoke descendant access tokens when a refresh token is revoked.
- [x] Add `store_tokens` support with hashed default for access, refresh, and authorization-code persistence; change default `store_client_secret` to hashed; keep explicit `store_client_secret: "plain"` supported and document migration impact.
- [x] Add tests proving DB rows do not store returned bearer values or client secrets in plaintext under defaults.
- [x] Fix metadata to publish the default JWKS URI when JWT plugin signing is active.
- [x] Reject public-client introspection without a client secret to match advertised introspection auth methods.
- [x] Normalize non-object JSON bodies, scalar metadata, and MCP verifier decode failures into expected 400/401 errors instead of internal exceptions.
- [x] Add schema indexes for OAuth hot predicates: client owner/reference, consent client/user/reference, refresh client/user, access client/user/refresh.
- [x] Add performance/regression tests or benchmarks for refresh replay revocation, client lists, and consent lists without changing list response shape.
- [x] Update package README/changelog notes for stricter parity behavior, hashed defaults, migration guidance, and refresh-token behavior.
- [x] Run `rbenv exec bundle exec rake test` in `packages/better_auth-oauth-provider`; also run impacted core OAuth protocol tests if present.

## Public API / Behavior Changes

- New option: `store_tokens`, default `"hashed"`, with custom hash callback support matching upstream intent.
- Default `store_client_secret` changes from `"plain"` to `"hashed"`.
- Refresh tokens are no longer issued merely because the client allows `refresh_token`; requested scopes must include `offline_access`.
- Token, introspection, and revoke client authentication becomes method-strict.

## Assumptions

- Compatibility-breaking changes are acceptable because this is pre-1.0 and security/upstream parity is the selected priority.
- Pagination is deferred; this plan only adds indexes and performance coverage for list endpoints.

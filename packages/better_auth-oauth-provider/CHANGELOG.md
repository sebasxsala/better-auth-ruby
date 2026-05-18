# Changelog

## Unreleased

- Changed OAuth provider defaults to hash stored client secrets and opaque OAuth tokens, with `store_tokens` support for custom token hashing.
- Hardened token, introspection, and revocation client authentication to enforce the registered auth method and reject public-client introspection/revocation.
- Aligned refresh-token issuance with upstream by requiring `offline_access`, and revoking descendant access tokens when a refresh token is revoked.
- Added no-store token response headers, default JWKS discovery metadata, authorization-code session revalidation, prompt/request-uri validation, MCP verifier error normalization, and OAuth hot-path schema indexes.

## 0.7.0 - 2026-05-05

- Fixed OAuth provider consent approval, metadata, issuer normalization, revocation persistence, and endpoint-specific rate limits for hardening parity.
- Changed RP-initiated logout ID token validation to use the hardened HS256 ID token key; old ID tokens signed only with the public client id will no longer validate.
- Hardened OAuth client endpoints, token exchange, introspection, userinfo, and pairwise behavior with expanded parity coverage.

## 0.3.0 - 2026-04-30

- Added upstream-parity support for provider init validation, request URI resolution, prompt handling, consent reference IDs, client references, custom token/id-token claims, scope-specific access-token expiry, M2M token defaults, userinfo JWT verification, and expanded introspection fields.
- Aligned dynamic registration, admin client creation, authorization, consent, token, refresh, revoke, and userinfo behavior with upstream edge cases.
- Expanded OAuth provider upstream parity tests across authorization, metadata, client privileges, pairwise endpoints, organization integration, prompts, rate limits, PKCE/token handling, and userinfo.

## 0.2.0 - 2026-04-29

- Aligned OAuth provider server behavior with upstream `@better-auth/oauth-provider` v1.6.9: upstream-shaped client and consent CRUD routes, server-only admin client routes, discovery metadata auth-method and signing-alg semantics, canonical access-token and consent schema, dynamic-registration PKCE defaults, refresh replay cascade revocation, rotate-secret response shape, and pairwise sector identifiers.
- Added upstream-parity OAuth provider behavior for dynamic client registration controls, PKCE enforcement, consent management, client management, token prefixes, refresh rotation, JWT resource access tokens, pairwise subjects, userinfo claims, introspection/revocation hints, end-session, `/oauth2/continue`, metadata cache headers, conditional JWKS metadata, and rate limits.
- Updated package and docs examples to use executable registration and token exchange flows.

## 0.1.0

- Initial package skeleton for Better Auth OAuth provider.

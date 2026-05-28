# Changelog

## Unreleased

- **Breaking:** SAML is no longer a transitive dependency. Add `gem "better_auth-saml"` when using SAML providers.
- Split protocol code into `better_auth-oidc` and `better_auth-saml`; this gem is now the convenience facade.

## 0.10.0 - 2026-05-21

- Hardened SSO redirect, OIDC, SAML metadata, logout, and response handling.
- Expanded adapter, Rack edge-case, and rate-limit coverage.

## 0.7.0 - 2026-05-05

- Fixed SAML config validation for `singleSignOnService` and added validation for `singleLogoutService`.
- Hardened OIDC callbacks by binding signed state `providerId` to the callback route and verifying `nonce` on JWKS-backed ID tokens.
- Changed SSO domain verification to require exact TXT record matches and corrected the insufficient access error code to `INSUFFICIENT_ACCESS`.
- Declared `jwt` as a direct runtime dependency for the SSO gem.
- Added regression coverage for SAML SP metadata XML responses.

## 0.2.0 - 2026-04-29

- Improved SSO upstream parity for OIDC and SAML provider flows, organization handling, callback behavior, metadata parsing, account linking, and response/error shapes.
- Expanded SSO documentation and coverage for SAML, OIDC, and ruby-saml integration paths.

## 0.1.0

- Initial package skeleton for Better Auth SSO.

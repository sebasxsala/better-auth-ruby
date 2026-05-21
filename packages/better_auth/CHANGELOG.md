# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Fixed organization owner counting to page through adapter results instead of
  relying on a single uncapped `find_many` call.

## [0.7.0] - 2026-05-05

### Added

- Completed OpenAPI support with upstream v1.6.9 base-route schema parity, `/ok` and `/error` documentation, richer helper-generated schemas, plugin endpoint metadata coverage, and Scalar reference configuration parity.
- Added shared join query handling for adapter-backed relation loading.

### Changed

- Modernized the MCP plugin to use OAuth Provider-style client, token, metadata, and protected-resource behavior while keeping legacy MCP routes as aliases.
- Changed OAuth HS256 ID token signing to use non-public key material; existing ID tokens signed only with the public client id will no longer validate.

### Fixed

- Fixed OAuth refresh token rotation to reject refresh tokens presented by a different authenticated client.
- Fixed OAuth client-secret verification to use constant-time comparison for encrypted and custom-hashed storage modes.
- Hardened router and OAuth protocol behavior around path handling, issuer metadata, and public route coverage.

## [0.4.0] - 2026-04-30

### Added

- Added upstream-parity helpers for async execution, host resolution, instrumentation, request state, URL handling, OAuth2, deprecation warnings, and expanded route behavior.
- Added two-factor, OAuth protocol, social route, organization, admin, adapter, schema, and session parity coverage.

### Changed

- Aligned core auth, email OTP, generic OAuth, organization, two-factor, OAuth protocol, adapter, router, rate-limiter, logger, and middleware behavior more closely with upstream Better Auth.

### Fixed

- Fixed upstream parity gaps in organization handling, generic OAuth user info, email OTP sign-up, database schema behavior, and route/session edge cases.

## [0.3.0] - 2026-04-29

### Added

- Added upstream-parity social provider support, including provider-specific authorization, token, profile, refresh, and revocation behavior for the expanded provider set.
- Added OAuth/OIDC protocol hardening for authorization, callback, discovery, metadata, token, and userinfo flows.
- Added upstream v1.6.9 parity coverage for schema generation, adapter behavior, plugin hooks, session handling, and account/user route edge cases.

### Changed

- Extracted MongoDB adapter support behind the external `better_auth-mongodb` package while preserving compatibility for existing adapter configuration.
- Updated auth routes, router behavior, rate limiting, password and email-verification flows, and schema metadata to match upstream semantics more closely.

### Fixed

- Fixed social provider edge cases, magic-link expiration behavior, adapter value coercion, and callback/session handling across Rack integrations.

## [0.1.1] - 2026-03-22

### Fixed

- Fixed gemspec files list to use `Dir.glob` instead of `git ls-files` for better CI compatibility

### Added

- Initial project setup
- Basic gem structure
- StandardRB configuration
- Minitest for core testing
- RSpec for Rails adapter testing
- CI/CD workflows for GitHub Actions

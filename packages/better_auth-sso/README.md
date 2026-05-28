# Better Auth SSO

External SSO plugin package for `better_auth`.

SSO is the app-facing feature: provider management, domain verification, composed
routes, account linking, and sign-in orchestration. Protocol code is split into
focused gems so OIDC-only apps do not install SAML/XML dependencies.

## Installation matrix

```ruby
# OIDC enterprise only (no SAML XML stack)
gem "better_auth-oidc"

# Full SSO plugin (always includes OIDC via better_auth-oidc)
gem "better_auth-sso"

# SAML identity providers (required in addition to better_auth-sso)
gem "better_auth-saml"
```

```ruby
require "better_auth"
require "better_auth/sso"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.sso
  ]
)
```

SAML loads automatically when `better_auth-saml` is in the bundle, when
`ENV["BETTER_AUTH_SSO_SAML"]=1`, or when plugin config enables SAML. Otherwise
add `gem "better_auth-saml"` before using SAML providers.

SAML XML validation is provided by `better_auth-saml` and backed by `ruby-saml`.
Production XML SAML deployments should configure `BetterAuth::SSO::SAML.sso_options`
or compatible SAML hooks so AuthnRequest generation and SAMLResponse parsing use
the real XML/SAML boundary instead of the lightweight JSON/base64 fallback used by
local tests:

```ruby
require "better_auth/sso"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.sso(
      BetterAuth::SSO::SAMLHooks.merge_options(
        {},
        BetterAuth::SSO::SAML.sso_options
      )
    )
  ]
)
```

## SAML Single Logout

SAML SLO follows upstream route shapes when `saml.enableSingleLogout` is enabled:

- `POST /sso/saml2/logout/:providerId` starts SP-initiated logout for the current session.
- `GET|POST /sso/saml2/sp/slo/:providerId` handles IdP LogoutRequest and LogoutResponse payloads.
- ACS stores SAML `NameID` and `SessionIndex` lookup records so IdP-initiated logout can revoke the matching Better Auth session.

Ruby keeps the lightweight JSON/base64 fallback used by the local SAML test adapter, and real XML deployments should configure `BetterAuth::SSO::SAML.sso_options` or compatible SAML hooks.

SCIM is a separate provisioning feature and lives in `better_auth-scim`.

## Organization Assignment

When the organization plugin is installed, SSO can add users to an organization
linked to an SSO provider. SSO login flows assign from the matched provider.
Generic OAuth callbacks under `/callback/:provider` also assign by verified SSO
email domain when domain verification is enabled, matching upstream behavior for
users who sign in through non-SSO OAuth but share an enterprise domain.

## Schema Compatibility

The Ruby package intentionally keeps the historical default SSO provider model
name `ssoProviders` for backward compatibility. Upstream Better Auth defaults to
`ssoProvider`; configure `model_name:` if your application needs a different
storage model name.

Field mapping options are supported through `fields:` for the SSO provider
schema, including `issuer`, `oidcConfig`, `samlConfig`, `userId`, `providerId`,
`organizationId`, `domain`, and `domainVerified`.

## Scope and Non-Goals

This package does not currently imply support for advanced enterprise features
such as `private_key_jwt`, mTLS client authentication, every SAML XML edge case,
or large internal SSO refactors. Those items are tracked in the
[upstream and product alignment backlog](../../.docs/backlog/upstream-product-alignment.md)
until they have explicit product scope and upstream parity decisions.

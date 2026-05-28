# Better Auth OIDC

Enterprise OpenID Connect relying-party helpers for Better Auth Ruby.

Use this package when you need OIDC discovery, JWKS validation, and plugin extensions without pulling in SAML/XML dependencies.

```ruby
require "better_auth"
require "better_auth/oidc"
```

For the full SSO plugin (provider CRUD, domain verification, composed routes), add `better_auth-sso`:

```ruby
gem "better_auth-sso"
gem "better_auth-saml" # only when using SAML identity providers
```

```ruby
require "better_auth/sso"

BetterAuth.auth(plugins: [BetterAuth::Plugins.sso])
```

SCIM provisioning is separate (`better_auth-scim`). SAML SP primitives live in `better_auth-saml`.

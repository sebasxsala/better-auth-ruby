# Better Auth SAML

SAML 2.0 service provider primitives for Better Auth Ruby enterprise SSO.

This package owns `ruby-saml` and SAML-specific plugin extensions. OIDC-only deployments should not install it.

```ruby
require "better_auth"
require "better_auth/saml"
```

For the full SSO plugin, pair with `better_auth-sso` (which depends on `better_auth-oidc`):

```ruby
gem "better_auth-sso"
gem "better_auth-saml"
```

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

SAML is a protocol used by SSO; it is not the same feature as SSO itself. See `better_auth-sso` for provider management and composed routes.

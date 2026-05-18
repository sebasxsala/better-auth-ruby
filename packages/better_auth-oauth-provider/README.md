# Better Auth OAuth Provider

External OAuth provider plugin package for `better_auth`.

Upstream ships OAuth provider as `@better-auth/oauth-provider`, separate from core plugin exports. This gem mirrors that boundary for Ruby while keeping Ruby option names snake_case and upstream-compatible HTTP paths and JSON keys.

```ruby
require "better_auth"
require "better_auth/oauth_provider"

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  base_url: "https://auth.example.com/api/auth",
  plugins: [
    BetterAuth::Plugins.oauth_provider(
      scopes: ["openid", "profile", "email", "offline_access"],
      consent_page: "/oauth2/consent",
      allow_dynamic_client_registration: true
    )
  ]
)
```

## Client Registration

Dynamic registration is disabled by default. Enable it explicitly and call it with an authenticated session unless unauthenticated registration is also enabled.

```ruby
client = auth.api.register_o_auth_client(
  headers: {"cookie" => session_cookie},
  body: {
    client_name: "Example Client",
    redirect_uris: ["https://client.example.com/callback"],
    token_endpoint_auth_method: "client_secret_post",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    scope: "openid profile offline_access"
  }
)
```

## Authorization Code Token Exchange

Authorization code clients use S256 PKCE by default.

```ruby
tokens = auth.api.o_auth2_token(
  body: {
    grant_type: "authorization_code",
    code: params[:code],
    redirect_uri: "https://client.example.com/callback",
    client_id: client[:client_id],
    client_secret: client[:client_secret],
    code_verifier: verifier
  }
)
```

When `resource` is present and valid, access tokens are JWTs. Without `resource`, access tokens are opaque and introspectable.
By default, valid JWT access-token audiences are the provider issuer URL and, when `openid` is granted, the UserInfo endpoint. Set `valid_audiences` to allow additional resource servers.

## Routes

| Method | Path | Ruby API method |
| --- | --- | --- |
| `GET` | `/.well-known/oauth-authorization-server` | `auth.api.get_o_auth_server_config` |
| `GET` | `/.well-known/openid-configuration` | `auth.api.get_open_id_config` |
| `POST` | `/oauth2/register` | `auth.api.register_o_auth_client` |
| `POST` | `/oauth2/create-client` | `auth.api.create_o_auth_client` |
| `POST` | `/admin/oauth2/create-client` | `auth.api.admin_create_o_auth_client` |
| `PATCH` | `/admin/oauth2/update-client` | `auth.api.admin_update_o_auth_client` |
| `GET` | `/oauth2/get-client?client_id=...` | `auth.api.get_o_auth_client` |
| `GET` | `/oauth2/get-clients` | `auth.api.get_o_auth_clients` |
| `POST` | `/oauth2/update-client` | `auth.api.update_o_auth_client` |
| `POST` | `/oauth2/delete-client` | `auth.api.delete_o_auth_client` |
| `GET` | `/oauth2/public-client?client_id=...` | `auth.api.get_o_auth_client_public` |
| `POST` | `/oauth2/public-client-prelogin` | `auth.api.get_o_auth_client_public_prelogin` |
| `POST` | `/oauth2/client/rotate-secret` | `auth.api.rotate_o_auth_client_secret` |
| `GET` | `/oauth2/authorize` | `auth.api.o_auth2_authorize` |
| `POST` | `/oauth2/continue` | `auth.api.o_auth2_continue` |
| `POST` | `/oauth2/consent` | `auth.api.o_auth2_consent` |
| `GET` | `/oauth2/get-consent?id=...` | `auth.api.get_o_auth_consent` |
| `GET` | `/oauth2/get-consents` | `auth.api.get_o_auth_consents` |
| `POST` | `/oauth2/update-consent` | `auth.api.update_o_auth_consent` |
| `POST` | `/oauth2/delete-consent` | `auth.api.delete_o_auth_consent` |
| `POST` | `/oauth2/token` | `auth.api.o_auth2_token` |
| `POST` | `/oauth2/introspect` | `auth.api.o_auth2_introspect` |
| `POST` | `/oauth2/revoke` | `auth.api.o_auth2_revoke` |
| `GET` | `/oauth2/userinfo` | `auth.api.o_auth2_user_info` |
| `GET`, `POST` | `/oauth2/end-session` | `auth.api.o_auth2_end_session` |

Deprecated aliases remain for one minor release: `GET /oauth2/client/:id` -> `/oauth2/get-client`, `GET /oauth2/clients` -> `/oauth2/get-clients`, `PATCH /oauth2/client` -> `/oauth2/update-client`, `DELETE /oauth2/client` -> `/oauth2/delete-client`, `GET /oauth2/client` -> `/oauth2/public-client`, and `GET/PATCH/DELETE /oauth2/consent` plus `GET /oauth2/consents` -> the `get/update/delete/get-consents` consent routes.

Admin client routes are server-only. They are available through `auth.api.*` and return `403` through the Rack handler.

## Options

Common options accepted by `BetterAuth::Plugins.oauth_provider`:

- `login_page`
- `consent_page`
- `scopes`
- `claims`
- `grant_types`
- `allow_dynamic_client_registration`
- `allow_unauthenticated_client_registration`
- `client_registration_default_scopes`
- `client_registration_allowed_scopes`
- `client_credential_grant_default_scopes`
- `store_client_secret`
- `store_tokens`
- `prefix`
- `code_expires_in`
- `id_token_expires_in`
- `refresh_token_expires_in`
- `access_token_expires_in`
- `m2m_access_token_expires_in`
- `scope_expirations`
- `advertised_metadata`
- `valid_audiences`
- `allow_public_client_prelogin`
- `custom_token_response_fields`
- `custom_access_token_claims`
- `custom_user_info_claims`
- `pairwise_secret`
- `signup`
- `select_account`
- `post_login`
- `client_privileges`
- `rate_limit`
- `jwks_uri`
- `disable_jwt_plugin`
- `store`

`store_client_secret` defaults to `"hashed"`. Set `store_client_secret: "plain"` only when migrating an existing app that still depends on plaintext client secrets. `store_tokens` defaults to `"hashed"` for opaque access tokens, refresh tokens, and authorization codes; custom hash callbacks may be supplied with `hash: ->(token, type) { ... }`.

Token, introspection, and revocation client authentication is method-strict: `client_secret_basic` clients must authenticate with HTTP Basic credentials, `client_secret_post` clients must use body credentials, and public clients cannot authenticate to introspection or revocation. Authorization-code clients receive refresh tokens only when the granted scope includes `offline_access`.

`rate_limit` accepts per-route overrides:

```ruby
rate_limit: {
  token: {window: 60, max: 20},
  authorize: {window: 60, max: 30},
  introspect: {window: 60, max: 100},
  revoke: {window: 60, max: 30},
  register: {window: 60, max: 5},
  userinfo: false
}
```

Use `false` to disable a route-specific rule.

## Schema Migration

`oauthAccessToken` now uses the upstream canonical columns `token`, `expiresAt`, `scopes`, `clientId`, `sessionId`, `userId`, `referenceId`, and `refreshId`. Legacy `access_token`, `refresh_token`, `access_token_expires_at`, and `scope` columns should be copied forward then dropped. `oauthConsent#consent_given` is also removed; a consent row means consent was granted.

After enabling the hashed defaults, newly created OAuth client secrets and opaque tokens are stored hashed. Existing plaintext rows continue to require either a migration that re-registers/rotates secrets and tokens or a temporary explicit `store_client_secret: "plain"` setting for old clients during rollout.

For non-Rails SQL apps, run the equivalent of:

```sql
UPDATE better_auth_oauth_access_tokens
SET token = COALESCE(token, access_token),
    expires_at = COALESCE(expires_at, access_token_expires_at),
    scopes = COALESCE(scopes, scope)
WHERE token IS NULL OR scopes IS NULL;

DELETE FROM better_auth_oauth_consents WHERE consent_given = false;
```

Then drop the legacy access-token and consent columns. Rails apps using `better_auth-rails` generate migrations from the active plugin schema, so regenerating after this change emits only the canonical columns.

## Ruby Adaptations

When the JWT plugin is registered, JWT access tokens and ID tokens use the JWT plugin's configured `jwks.key_pair_config.alg`, defaulting to `EdDSA` like upstream, and discovery metadata publishes the active JWKS URI. If the JWT plugin is not registered, or `disable_jwt_plugin: true` is set, Ruby intentionally falls back to HS256 for compatibility; with hashed client-secret storage, that fallback uses a server-derived per-client key.

Upstream `oauthProviderResourceClient` and MCP protected-resource helpers remain future API-boundary work for Ruby. This gem currently hardens authorization-server behavior only.

Route OpenAPI metadata blocks from upstream TypeScript are intentionally not ported into this package. Use the Ruby `open_api` plugin for generated OpenAPI output.

The upstream `@better-auth/oauth-provider/client`, React/Solid client plugins, dashboard UI, and browser helpers are not ported. Ruby apps call the JSON endpoints directly or wrap `auth.api.*`.

OIDC provider remains a core `better_auth` plugin because upstream still exposes it from `better-auth/plugins`. OAuth provider is the newer standalone provider package.

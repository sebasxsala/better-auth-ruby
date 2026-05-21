# better_auth-passkey

Passkey/WebAuthn plugin package for Better Auth Ruby.

## Installation

Add the gem and require the package before configuring the plugin:

```ruby
gem "better_auth-passkey"
```

```ruby
require "better_auth/passkey"

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: :memory,
  plugins: [
    BetterAuth::Plugins.passkey(
      rp_id: "localhost",
      rp_name: "Example App",
      origin: "http://localhost:3000"
    )
  ]
)
```

## Options

`BetterAuth::Plugins.passkey` accepts Ruby `snake_case` options:

- `rp_id`: WebAuthn relying party ID. Defaults to the configured `base_url` host.
- `rp_name`: WebAuthn relying party name. Defaults to the Better Auth app name.
- `origin`: allowed WebAuthn origin or array of origins.
- `authenticator_selection`: supports `resident_key`, `user_verification`, and `authenticator_attachment`.
- `advanced.web_authn_challenge_cookie`: challenge cookie name. Defaults to `better-auth-passkey`.
- `registration`: supports `require_session`, `resolve_user`, `after_verification`, and `extensions`.
- `authentication`: supports `after_verification` and `extensions`.
- `schema`: deep-merged schema overrides. The built-in SQL table remains `passkeys`, matching the Ruby adapter convention.

HTTP routes and wire JSON keys are kept compatible with upstream Better Auth passkey server behavior. Ruby method names and configuration keys remain idiomatic `snake_case`.

## Passkey-first registration

Use `require_session: false` to register a passkey before a session exists:

```ruby
BetterAuth::Plugins.passkey(
  registration: {
    require_session: false,
    resolve_user: lambda do |data|
      invitation = Invitations.verify!(data.fetch(:context))
      {
        id: invitation.user_id,
        name: invitation.email,
        display_name: invitation.name,
        email: invitation.email
      }
    end,
    after_verification: lambda do |data|
      Audit.passkey_registered!(
        user_id: data.fetch(:user).fetch(:id),
        context: data.fetch(:context)
      )
      nil
    end
  }
)
```

Pass `context` when generating registration options:

```ruby
auth.api.generate_passkey_registration_options(query: { context: invitation_token })
```

During passkey-first registration, `after_verification` may return `{ user_id: "..." }` to attach the credential to a concrete user. During session-required registration, switching users is rejected.

## Callback contracts

Ruby uses hashes for the upstream TypeScript contracts:

- Stored challenge value: `expectedChallenge`, `userData.id`, optional `userData.name`, optional `userData.displayName`, and optional `context`.
- `resolve_user` receives `{ ctx:, context: }` and must return at least `id` and `name`; it may also return `display_name` and `email`.
- Registration `after_verification` receives `{ ctx:, verification:, user:, client_data:, context: }`.
- Authentication `after_verification` receives `{ ctx:, verification:, client_data: }`.
- Callback `verification` values are objects from the Ruby `webauthn` gem. They are not the TypeScript `VerifiedRegistrationResponse` or `VerifiedAuthenticationResponse` structs from upstream's Node implementation.
- Passkey records use upstream wire keys including `userId`, `credentialID`, `publicKey`, `deviceType`, `backedUp`, `createdAt`, and optional `aaguid`.

### Ruby vs TypeScript callback shapes

Callback parity is behavioral at the HTTP JSON boundary, not a static export of
the TypeScript interfaces from `@better-auth/passkey`. Treat
`data[:verification]` as the Ruby `webauthn` verification result or hash-like
object produced by this gem, not as a SimpleWebAuthn DTO.

## WebAuthn extensions

```ruby
BetterAuth::Plugins.passkey(
  registration: {
    extensions: { credProps: true }
  },
  authentication: {
    extensions: ->(_data) { { hmacGetSecret: true } }
  }
)
```

## Browser client scope

This gem provides server WebAuthn routes. It does not ship the upstream browser-only `@better-auth/passkey/client` helper, `passkeyClient`, `startRegistration`, `startAuthentication`, conditional UI, autofill, or extension-result handling. Use the browser WebAuthn APIs directly or wrap them in application JavaScript.

## WebAuthn configuration

The plugin uses `WebAuthn::RelyingParty` per request for `rp_id`, `rp_name`, and allowed origins. It does not mutate global `WebAuthn.configuration`, so multiple Better Auth instances can use different relying-party settings in the same Ruby process.

## Upstream parity notes

The Ruby plugin tracks Better Auth `v1.6.9` upstream behavior. A few wire-shape and validation details are worth noting:

- `excludeCredentials` entries (registration options) are emitted as `{id, transports?}` to match upstream's `@simplewebauthn/server` output. `allowCredentials` (authentication options) still includes `type: "public-key"` to mirror upstream's authentication wire shape.
- `transports` is omitted entirely from credential descriptors when the stored value is missing or empty (rather than emitting an empty array).
- The default storage table is named `passkeys` (plural) in the SQL adapters, mapped from the upstream `passkey` model. Custom SQL adapters that translate the `passkey` model name continue to work.
- `credentialID` is unique in the Ruby schema. This is intentional hardening beyond upstream v1.6.9 and prevents the same WebAuthn credential from being stored more than once.
- `rp_id` resolution falls back to `URI.parse(base_url).host` (port stripped). When `base_url` is empty or unparseable, `rp_id` defaults to `"localhost"`.
- For passkey-first registration, the `after_verification` callback may return `{ user_id: nil }` or `{ user_id: "" }` to leave the resolved user unchanged. Returning any other non-empty-string value (integer, boolean, etc.) raises `RESOLVED_USER_INVALID`.
- `update_passkey` accepts an empty-string `name` to match upstream `z.string()`. Missing or non-string `name` still raises `VALIDATION_ERROR`.
- Cross-user `delete_passkey` and `update_passkey` raise `NOT_FOUND` with the `PASSKEY_NOT_FOUND` message. This is an intentional Ruby hardening to avoid user/passkey enumeration while preserving the upstream error message.
- Existing databases should deduplicate historical `credential_id` values before adding the unique constraint during migration.

## Notes

This package depends on the maintained `webauthn` gem. Keeping passkeys outside `better_auth` avoids installing WebAuthn dependencies for applications that do not use passkeys.

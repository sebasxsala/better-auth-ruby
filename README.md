# Better Auth Ruby

A modern authentication framework for Ruby, inspired by Better Auth.

> This project is independent and is not affiliated with, maintained by, or endorsed by the Better Auth project.

Ruby server packages for [Better Auth](https://github.com/better-auth/better-auth).
The core is Rack-first, with adapters for Rails, Sinatra, Hanami, Grape, and Roda, plus
Ruby packages for selected Better Auth plugins.

[Documentation](https://better-auth-rb.vercel.app/) -
[Supported features](https://better-auth-rb.vercel.app/docs/supported-features) -
[Upstream Better Auth](https://better-auth.com) -
[Issues](https://github.com/sebasxsala/better-auth-rb/issues)

Current upstream target: Better Auth `v1.6.9`.

This project is active work. The Ruby port implements a large server-side
surface, but exact upstream parity is still being tightened across some routes,
adapter edge cases, OpenAPI schemas, and docs pages.

## Install

### Rails

```ruby
# Gemfile
gem "better_auth-rails"
```

```bash
bundle install
bin/rails generate better_auth:install
```

```ruby
# config/routes.rb
Rails.application.routes.draw do
  better_auth
end
```

### Rack

```ruby
# Gemfile
gem "better_auth"
```

```ruby
require "better_auth"

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  base_url: "http://localhost:3000",
  database: BetterAuth::Adapters::Memory.new
)

run auth
```

### Sinatra

```ruby
# Gemfile
gem "better_auth-sinatra"
```

```ruby
require "sinatra/base"
require "better_auth/sinatra"

class App < Sinatra::Base
  register BetterAuth::Sinatra

  better_auth at: "/api/auth" do |config|
    config.secret = ENV.fetch("BETTER_AUTH_SECRET")
    config.base_url = ENV.fetch("BETTER_AUTH_URL")
    config.database = ->(options) {
      BetterAuth::Adapters::Postgres.new(options, url: ENV.fetch("DATABASE_URL"))
    }
  end
end
```

### Roda

```ruby
# Gemfile
gem "better_auth-roda"
```

```ruby
require "roda"
require "better_auth/roda"

class App < Roda
  plugin :better_auth

  better_auth at: "/api/auth" do |config|
    config.secret = ENV.fetch("BETTER_AUTH_SECRET")
    config.base_url = ENV.fetch("BETTER_AUTH_URL")
    config.database = :memory
    config.email_and_password = {enabled: true}
  end

  route do |r|
    r.better_auth
  end
end
```

### Hanami

```ruby
# Gemfile
gem "better_auth-hanami"
```

```bash
bundle install
bundle exec rake better_auth:init
bin/hanami db migrate
```

### Grape

```ruby
# Gemfile
gem "better_auth-grape"
```

```ruby
require "grape"
require "better_auth/grape"

class API < Grape::API
  include BetterAuth::Grape

  format :json

  better_auth at: "/api/auth" do |config|
    config.secret = ENV.fetch("BETTER_AUTH_SECRET")
    config.base_url = ENV.fetch("BETTER_AUTH_URL", "http://localhost:9292")
    config.database = ->(options) {
      BetterAuth::Adapters::Postgres.new(options, url: ENV.fetch("DATABASE_URL"))
    }
  end
end
```

## Supported Features

See the docs page for the current support inventory:

- [Supported Features](https://better-auth-rb.vercel.app/docs/supported-features)
- [Local feature notes](.docs/features/)
- [Implementation plans](.docs/plans/)

Short version:

- Rack core, Rails, Sinatra, Hanami, Grape, and Roda integration packages exist.
- Email/password, sessions, social OAuth, database adapters, and many server
  plugins are implemented with Ruby tests.
- Payment docs and navigation only list Stripe. Other upstream payment plugins
  are intentionally not marked as supported.
- Browser client packages and TypeScript-only helpers are outside the Ruby
  server scope unless a Ruby package explicitly documents an equivalent.

## Packages

- [`better_auth`](packages/better_auth/): Rack core, auth routes, sessions,
  cookies, adapters, plugin system, and built-in server plugins.
- [`better_auth-rails`](packages/better_auth-rails/): Rails mount helpers,
  ActiveRecord adapter, controller helpers, migrations, and generators.
- [`better_auth-sinatra`](packages/better_auth-sinatra/): Sinatra extension,
  Rack mounting, helpers, and migration tasks.
- [`better_auth-hanami`](packages/better_auth-hanami/): Hanami integration,
  action helpers, Sequel adapter, migrations, and generators.
- [`better_auth-grape`](packages/better_auth-grape/): Grape integration,
  Rack mounting, helpers, and SQL migration tasks.
- [`better_auth-roda`](packages/better_auth-roda/): Roda plugin, Rack mounting,
  helpers, and SQL migration tasks.
- [`better_auth-cli`](packages/better_auth-cli/): CLI for generating, checking,
  and applying Better Auth SQL migrations through `better-auth`.
- [`better_auth-mongodb`](packages/better_auth-mongodb/): MongoDB
  database adapter.
- [`better_auth-redis-storage`](packages/better_auth-redis-storage/): Redis
  secondary storage.
- [`better_auth-api-key`](packages/better_auth-api-key/): API key plugin package.
- [`better_auth-passkey`](packages/better_auth-passkey/): Passkey/WebAuthn plugin
  package.
- [`better_auth-oauth-provider`](packages/better_auth-oauth-provider/): OAuth
  2.0/OIDC provider plugin package.
- [`better_auth-scim`](packages/better_auth-scim/): SCIM v2 provisioning plugin
  package.
- [`better_auth-sso`](packages/better_auth-sso/): OIDC and SAML SSO plugin
  package.
- [`better_auth-stripe`](packages/better_auth-stripe/): Stripe billing plugin
  package.

OpenAuth alias packages are also available for users who prefer that naming.
They install and load the matching Better Auth Ruby packages, and their READMEs
point back to the canonical documentation at https://better-auth-rb.vercel.app/.

- [`openauth`](packages/openauth/): Alias for `better_auth`.
- [`openauth-cli`](packages/openauth-cli/): Alias CLI package that exposes
  `openauth`.
- [`openauth-rails`](packages/openauth-rails/): Alias for `better_auth-rails`.
- [`openauth-sinatra`](packages/openauth-sinatra/): Alias for `better_auth-sinatra`.
- [`openauth-hanami`](packages/openauth-hanami/): Alias for `better_auth-hanami`.
- [`openauth-grape`](packages/openauth-grape/): Alias for `better_auth-grape`.
- [`openauth-roda`](packages/openauth-roda/): Alias for `better_auth-roda`.
- [`openauth-mongodb`](packages/openauth-mongodb/): Alias for
  `better_auth-mongodb`.
- [`openauth-redis-storage`](packages/openauth-redis-storage/): Alias for
  `better_auth-redis-storage`.
- [`openauth-api-key`](packages/openauth-api-key/): Alias for
  `better_auth-api-key`.
- [`openauth-passkey`](packages/openauth-passkey/): Alias for
  `better_auth-passkey`.
- [`openauth-oauth-provider`](packages/openauth-oauth-provider/): Alias for
  `better_auth-oauth-provider`.
- [`openauth-scim`](packages/openauth-scim/): Alias for `better_auth-scim`.
- [`openauth-sso`](packages/openauth-sso/): Alias for `better_auth-sso`.
- [`openauth-stripe`](packages/openauth-stripe/): Alias for
  `better_auth-stripe`.

## Development

```bash
git clone --recursive https://github.com/sebasxsala/better-auth-rb.git
cd better-auth-rb
make install
make ci
```

Run a single package:

```bash
cd packages/better_auth
bundle exec rake test
```

Database-backed tests may require the repo services:

```bash
docker compose up -d
```

## Contributing

1. Branch from `canary`.
2. Read [`AGENTS.md`](AGENTS.md) and the package-specific instructions before
   editing a package.
3. Check upstream source and tests for behavior changes.
4. Run the relevant package tests, or `make ci` for the full repo.
5. Open a PR to `canary`.

## Security

Report vulnerabilities to security@openparcel.dev. See [`SECURITY.md`](SECURITY.md).

## License

[MIT License](LICENSE.md)

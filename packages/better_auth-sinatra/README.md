# Better Auth Sinatra

Sinatra adapter for Better Auth Ruby. This package is a thin integration around
the framework-agnostic `better_auth` Rack core.

## Installation

```ruby
gem "better_auth-sinatra"
```

```bash
bundle install
```

## Setup

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
    config.email_and_password = {enabled: true}
    config.plugins = []
  end

  get "/dashboard" do
    require_authentication
    current_user.fetch("email")
  end
end
```

The extension mounts the core Rack app at `/api/auth` by default. The mount path
cannot be `/`, because that would capture every Sinatra route before the app can
handle it. The core app still owns routes such as `/ok`, `/sign-up/email`,
`/sign-in/email`, and plugin endpoints.

Call `better_auth` once per Sinatra app class. Registering it more than once is
treated as a configuration error because each Rack mount must delegate to one
core Better Auth instance.

`better_auth at:` sets the path prefix that Better Auth uses as its core
`base_path`. The adapter supports two common Rack mount patterns:

- Natural Sinatra nesting: mount the Sinatra app under a parent `Rack::URLMap`,
  for example at `/api`, and configure `better_auth at: "/auth"`. Auth routes
  are available at `/api/auth/*`.
- Shared auth mount: mount the Sinatra app itself at the same path as auth, for
  example `/api/auth`, and configure `better_auth at: "/api/auth"`. The adapter
  reconstructs the logical path from Rack `SCRIPT_NAME` and `PATH_INFO`.

When using reverse proxies, `Rack::URLMap`, or another parent app, make sure the
`PATH_INFO` visible to Sinatra still aligns with the configured auth prefix.
`SCRIPT_NAME` handling depends on the Rack server and mount stack, so verify
redirect URLs and cookie paths in integration tests when mounting below a
sub-path. If the public auth URL includes a parent mount prefix, set
`config.base_url` to that public URL, for example `https://app.example/api/auth`;
core URL inference uses the configured Better Auth base path and cannot infer
every parent Rack mount layout from Sinatra alone.

## Helpers

- `current_session`
- `current_user`
- `authenticated?`
- `require_authentication`

`require_authentication` halts with `401` when no Better Auth user is present.
Requests that prefer JSON receive the same JSON error shape used by the core
router.

Sinatra helpers resolve sessions through the core `get-session` API path, so
Better Auth plugin hooks that affect session lookup, such as the bearer plugin,
run for `current_user` and `require_authentication`. Helper session lookup may
emit Better Auth `Set-Cookie` headers when stale cookies need to be cleared or
session cookies need to be refreshed.

## Rake Tasks

Load tasks from your app Rakefile:

```ruby
require "better_auth/sinatra/tasks"
```

Available tasks:

```bash
rake better_auth:install
rake better_auth:generate:migration
rake better_auth:migrate
rake better_auth:migrate:status
rake better_auth:doctor
rake better_auth:routes
```

`better_auth:install` creates `config/better_auth.rb`. SQL migrations are
generated under `db/better_auth/migrate`. When a SQL adapter is configured,
generation introspects the current database and emits only missing Better Auth
tables, columns, and indexes.

Migration and route tasks load Better Auth configuration from
`config/better_auth.rb` by default. Set `BETTER_AUTH_CONFIG` (or the
OpenAuth-compatible `OPEN_AUTH_CONFIG`) to a shared config file if your app keeps
Better Auth setup elsewhere:

```bash
BETTER_AUTH_CONFIG=config/auth/better_auth.rb rake better_auth:generate:migration
```

The migration tasks fail when no config file is found, so generated SQL cannot
silently omit app plugins or custom schema options.

## Database Notes

Sinatra does not include a Rails-style database layer or migration command.
This adapter uses Better Auth core SQL adapters for migrations. Set
`BETTER_AUTH_DIALECT=postgres`, `mysql`, or `sqlite` when generating SQL.

The migration runner delegates SQL rendering and execution behavior to the core
Better Auth SQL migration layer. It handles multiple statements, quoted strings,
and PostgreSQL dollar-quoted blocks; DDL rollback behavior still depends on the
database, so back up production data before migrating.

Exhaustive adapter behavior for PostgreSQL, MySQL, SQLite, and other database
families is covered in the core `better_auth` package. This Sinatra package only
smoke-tests that its configuration and Rake tasks delegate to those core paths.

ActiveRecord-backed Sinatra migrations are not supported yet. Apps that already
use `sinatra-activerecord` can still configure Better Auth manually, but the v1
Rake tasks do not emit ActiveRecord migrations.

## Development

```bash
cd packages/better_auth-sinatra
rbenv exec bundle exec rspec
RUBOCOP_CACHE_ROOT=/private/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache_sinatra rbenv exec bundle exec standardrb
```

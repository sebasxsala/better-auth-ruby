# Better Auth Hanami

Hanami adapter for Better Auth Ruby. It mounts the core Rack auth object inside
Hanami, uses Hanami's ROM/Sequel database gateway for persistence, renders
ROM::SQL migrations, generates Hanami relations/repos for app queries, and
provides action helpers plus generator tasks.

## Installation

```ruby
gem "better_auth-hanami"
```

```bash
bundle install
```

## Setup

Load the task file from your app Rakefile if your app does not already load
`lib/tasks`:

```ruby
# Rakefile
require "better_auth/hanami"
load Gem.loaded_specs.fetch("better_auth-hanami").full_gem_path + "/lib/tasks/better_auth.rake"
```

Generate the provider, route wiring, task wrapper, settings, relations/repos,
and base migration:

```bash
bundle exec rake better_auth:init
```

Run Hanami migrations:

```bash
bin/hanami db migrate
```

When you add plugins that introduce schema tables or fields, regenerate both
the migration and the app query objects. If the base migration already exists
and Hanami can connect to the current Sequel database, the migration generator
creates a new incremental update migration for missing plugin tables, additional
fields, and indexes:

```bash
bundle exec rake better_auth:generate:migration
bundle exec rake better_auth:generate:relations
bundle exec rake better_auth:doctor
```

## Configuration

The install generator creates `config/providers/better_auth.rb`:

```ruby
Hanami.app.register_provider(:better_auth) do
  prepare do
    require "better_auth/hanami"
  end

  start do
    better_auth_url = target["settings"].better_auth_url.to_s
    raise "better_auth_url must be configured" if better_auth_url.empty?

    BetterAuth::Hanami.configure do |config|
      config.secret = target["settings"].better_auth_secret
      config.base_url = better_auth_url
      config.base_path = "/api/auth"
      config.database = ->(options) {
        BetterAuth::Hanami::SequelAdapter.from_container(target, options)
      }
      config.trusted_origins = [better_auth_url]
      config.email_and_password = {enabled: true}
      config.plugins = []
    end

    auth = BetterAuth::Hanami.auth
    register "better_auth.auth", auth
    register "better_auth.rack_app", BetterAuth::Hanami::MountedApp.new(auth, mount_path: BetterAuth::Hanami.configuration.base_path)
  end
end
```

`trusted_origins` controls Better Auth origin and redirect URL validation. If
your browser client calls the auth endpoints from another origin, configure Rack
CORS middleware in your Hanami app as well so preflight requests and
`Access-Control-*` response headers match your frontend origin and credentials
policy. For the shared Rack/CORS/CSRF boundary, see
[`host-app-responsibilities.md`](../../.docs/features/host-app-responsibilities.md).

Do not rely on a Hanami-only empty `trusted_origins` list or inferred request
hosts as a strict deny-all-origin policy; set a canonical deployment URL in app
settings. The generated provider raises when `better_auth_url` is blank so auth
URLs and origin checks are not derived from an untrusted `Host` header. Keep
`BetterAuth::Hanami::MountedApp` behavior aligned with Hanami's router instead
of copying Rails mount internals without integration tests. Be cautious with
relation or inflector overrides generated for an app, because overwriting
application-specific Hanami relations can be destructive.

## Regenerating Migrations

The migration generator skips an existing `*_create_better_auth_tables.rb` file
by default so user-edited migrations are not overwritten. To intentionally
regenerate the base migration for a new app or after changing plugin schemas,
call the Ruby API with `force: true`:

```ruby
BetterAuth::Hanami::Generators::MigrationGenerator.new.run(force: true)
```

The generated rake task keeps the non-overwriting behavior:

```bash
bundle exec rake better_auth:generate:migration
```

## Routes

The generated `config/routes.rb` includes:

```ruby
require "better_auth/hanami"

module Bookshelf
  class Routes < Hanami::Routes
    include BetterAuth::Hanami::Routing

    better_auth
  end
end
```

By default this mounts Better Auth at `/api/auth`. Customize the path:

```ruby
better_auth at: "/auth"
```

`BetterAuth::Hanami::MountedApp` expects `PATH_INFO` in the shape produced by
Hanami's router; see `spec/better_auth/hanami/routing_spec.rb`. Custom Rack
stacks with different `SCRIPT_NAME` conventions may need application-level path
rewriting.

## Action Helpers

Include helpers in your base action:

```ruby
class Action < Hanami::Action
  include BetterAuth::Hanami::ActionHelpers
end
```

Use them from an action:

```ruby
def handle(request, response)
  return unless require_authentication(request, response)

  response.body = current_user(request).fetch("email")
end
```

## Relations And Repos

Better Auth uses `BetterAuth::Hanami::SequelAdapter` for its own reads and
writes. The generated Hanami relations/repos are for your application code when
you want to inspect or query Better Auth tables directly:

```ruby
users = Hanami.app["relations.users"].to_a
user = Hanami.app["repos.user_repo"].users.by_pk(user_id).one
```

If you prefer a custom persistence implementation, configure it directly:

```ruby
BetterAuth::Hanami.configure do |config|
  config.database = ->(options) { MyBetterAuthAdapter.new(options) }
end
```

When no Hanami `db.gateway` is available, the adapter still falls back to
memory storage in development and tests with a warning. In production it raises
instead, unless you intentionally set `config.allow_memory_fallback = true`.

## Limitations

- Supports Hanami 2.3+ only. Better Auth core depends on Rack 3, and Hanami 2.3 is the first Hanami line that allows Rack 3.
- Hanami 1.x and Hanami 2.2/Rack 2 apps are out of scope for this adapter.
- The stable command surface is Rake/generator based. A `hanami better_auth ...` command is not exposed because the current public guides do not document a stable third-party Hanami CLI extension API.
- Apps created with `--skip-db` can use memory storage for development or tests, but production apps should configure Hanami DB or pass an explicit Better Auth adapter.

## Development

```bash
cd packages/better_auth-hanami
rbenv exec bundle exec rspec
rbenv exec bundle exec standardrb
```

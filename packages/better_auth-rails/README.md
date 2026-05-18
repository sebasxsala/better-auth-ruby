# Better Auth Rails

Rails adapter for Better Auth Ruby. Provides seamless integration with Ruby on Rails applications including middleware, controller helpers, and generators.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "better_auth-rails"
```

### Defensive alias package

`better_auth_rails` is published only as a defensive alias package.

WARNING: This gem is an alias. Use `better_auth-rails`.

And then execute:

```bash
bundle install
```

## Usage

### Basic Setup

Add to your `config/application.rb`:

```ruby
require "better_auth/rails"
```

Compatibility require is also supported:

```ruby
require "better_auth_rails"
```

Or in your Gemfile:

```ruby
gem "better_auth-rails", require: "better_auth/rails"
```

### Initializer And Migration

Create the default initializer and base migration:

```bash
bin/rails generate better_auth:install
```

The same install path is available as a Rails task:

```bash
bin/rails better_auth:init
```

To generate only the base migration:

```bash
bin/rails generate better_auth:migration
bin/rails better_auth:generate:migration
```

The generators skip an existing `config/initializers/better_auth.rb` or existing `*_create_better_auth_tables.rb` migration instead of overwriting them.

### Configuration

The install generator creates `config/initializers/better_auth.rb`:

```ruby
BetterAuth::Rails.configure do |config|
  config.secret =
    Rails.application.credentials.dig(:better_auth, :secret) ||
    Rails.application.credentials.secret_key_base ||
    Rails.application.secret_key_base

  config.base_url = BetterAuth::Env.get("BETTER_AUTH_URL")
  config.base_path = "/api/auth"
  config.trusted_origins = [
    BetterAuth::Env.get("BETTER_AUTH_URL")
  ].compact

  config.session do |session|
    session.cookie_cache do |cookie|
      cookie.enabled = true
      cookie.max_age = 5 * 60
      cookie.strategy = "jwe"
    end
  end

  config.advanced do |advanced|
    advanced.ip_address do |ip|
      ip.ip_address_headers = ["x-forwarded-for"]
      ip.disable_ip_tracking = false
    end
  end

  config.experimental do |experimental|
    experimental.joins = false
  end

  config.social_providers do |providers|
    # providers.github = BetterAuth::SocialProviders.github(
    #   client_id: ENV.fetch("GITHUB_CLIENT_ID"),
    #   client_secret: ENV.fetch("GITHUB_CLIENT_SECRET")
    # )
  end

  config.plugins = []
  config.hooks do |hooks|
    hooks.before = []
    hooks.after = []
  end
end
```

Rails configuration is a thin option builder for the core Rack auth object. The same option concepts are available in core Ruby through `BetterAuth.auth(...)`; Rails places them in `config/initializers/better_auth.rb` so applications can rely on credentials, ActiveRecord, and Rails environment configuration.

Rails uses `BetterAuth::Rails::ActiveRecordAdapter` by default. The adapter uses whichever database adapter the Rails app is already configured with, including PostgreSQL and MySQL. To be explicit, set `config.database_adapter = :active_record`; for custom adapters, assign `config.database` directly.

#### Secret rotation

Rails can pass Better Auth secret rotation entries through the same `secrets` option as core:

```ruby
BetterAuth::Rails.configure do |config|
  config.secret = Rails.application.secret_key_base
  config.secrets = [
    {version: 2, value: Rails.application.credentials.dig(:better_auth, :secret_v2)},
    {version: 1, value: Rails.application.credentials.dig(:better_auth, :secret_v1)}
  ].compact
end
```

Core Better Auth also reads `BETTER_AUTH_SECRETS` when `secrets` is not configured directly.

#### Trusted origins

The generated initializer derives `trusted_origins` from `BetterAuth::Env.get("BETTER_AUTH_URL")`. If that environment variable is unset, Rails passes an empty list. Browser clients should set trusted origins explicitly in deployment so origin checks and callback URLs do not depend on an empty environment value. See [`host-app-responsibilities.md`](../../.docs/features/host-app-responsibilities.md) for the boundary between Better Auth origin checks, browser CORS headers, and host-app CSRF policy.

#### Option builder keys

The Rails option builder accepts unknown keys so plugin and custom options can flow through to core Better Auth. That also means typos become option keys silently. Validate configuration names against the core docs or the Ruby option names when adding new settings.

### JavaScript Client

Ruby Better Auth exposes the same HTTP route surface. Frontend apps should use the upstream Better Auth JavaScript client and point it at the Ruby server:

```ts
import { createAuthClient } from "better-auth/client";

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000",
  basePath: "/api/auth",
});
```

Plugin schemas are included in generated migrations through the same configuration:

```ruby
require "better_auth/api_key"

BetterAuth::Rails.configure do |config|
  config.plugins = [
    BetterAuth::Plugins.api_key
  ]
end

# Then regenerate before migrating if this is a new app:
# bin/rails generate better_auth:migration
```

### Routes

Mount the Better Auth Rack app in your routes:

```ruby
Rails.application.routes.draw do
  better_auth
end
```

By default this mounts at `/api/auth`. Rails mounts the core Rack auth app through a small wrapper so Better Auth still sees the full auth path after Rails moves the mount prefix into `SCRIPT_NAME`. To customize the path:

```ruby
Rails.application.routes.draw do
  better_auth at: "/auth"
end
```

The Better Auth core router handles internal routes such as `/callback/:providerId`.

### Controller Helpers

Include the controller helpers in your ApplicationController:

```ruby
class ApplicationController < ActionController::Base
  include BetterAuth::Rails::ControllerHelpers
end
```

Now you have access to authentication methods:

```ruby
class PostsController < ApplicationController
  before_action :require_authentication

  def index
    @user = current_user
  end
end
```

### Available Methods

- `current_session` - Returns the current Better Auth session hash
- `current_user` - Returns the current Better Auth user hash
- `authenticated?` - Returns true when a user is present
- `require_authentication` - Halts with `head :unauthorized` and returns `false` when no user is present

`ControllerHelpers` prepare the Better Auth context for the current Rails request before reading the session. Custom Rack middleware or controller code that bypasses `BetterAuth::Router` and reads sessions directly should call `prepare_for_request!` on the auth context first.

## Development

Full documentation is being adapted in the root `docs/` app. The Rails guide lives at `docs/content/docs/integrations/rails.mdx`; pages with a Ruby port warning still contain upstream TypeScript examples for reference.

### Setup

```bash
# Clone the monorepo
git clone --recursive https://github.com/sebasxsala/better-auth.git
cd better-auth/packages/better_auth-rails

# Install dependencies
bundle install
```

### Running Tests

```bash
# Run all tests
rbenv exec bundle exec rspec

# Run with coverage
COVERAGE=true rbenv exec bundle exec rspec

# Run specific test
rbenv exec bundle exec rspec spec/better_auth/rails/controller_helpers_spec.rb
```

### Code Style

We use StandardRB for linting:

```bash
# Check style
RUBOCOP_CACHE_ROOT=/private/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache_rails rbenv exec bundle exec standardrb

# Auto-fix issues
RUBOCOP_CACHE_ROOT=/private/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache_rails rbenv exec bundle exec standardrb --fix
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sebasxsala/better-auth.

When contributing:
1. Fork the repository
2. Create your feature branch (`git checkout -b feat/amazing-feature`)
3. Make sure tests pass (`bundle exec rspec`)
4. Ensure code style passes (`bundle exec standardrb`)
5. Commit your changes (`git commit -m 'feat: add amazing feature'`)
6. Push to the branch (`git push origin feat/amazing-feature`)
7. Open a Pull Request towards the `canary` branch

## License

The gem is available as open source under the terms of the MIT License.

# better_auth-grape

Grape integration for Better Auth Ruby.

## Installation

```ruby
gem "better_auth-grape"
```

## Usage

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
    config.email_and_password = {
      enabled: true
    }
    config.plugins = []
  end

  get "/dashboard" do
    require_authentication
    {email: current_user.fetch("email")}
  end
end
```

When the API uses Grape path prefixes or path-based versioning, pass a relative
auth path and the adapter mounts below the effective Grape path:

```ruby
class API < Grape::API
  include BetterAuth::Grape

  prefix :api
  version "v1", using: :path

  better_auth at: "/auth" do |config|
    config.secret = ENV.fetch("BETTER_AUTH_SECRET")
    config.base_url = ENV.fetch("BETTER_AUTH_URL")
    config.database = :memory
  end
end
```

This exposes Better Auth at `/api/v1/auth`.

Load Rake tasks from your application Rakefile:

```ruby
require "better_auth/grape/tasks"
```

```bash
rake better_auth:install
BETTER_AUTH_DIALECT=postgres rake better_auth:generate:migration
rake better_auth:migrate
rake better_auth:migrate:status
rake better_auth:doctor
```

When a SQL adapter is configured, migration generation introspects the current
database and emits only missing Better Auth tables, columns, and indexes.

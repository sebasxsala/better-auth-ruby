# Better Auth Roda

Roda adapter for Better Auth Ruby. This package is a thin integration around
the core Rack auth object, with a Roda plugin, request helpers, and SQL
migration tasks.

## Installation

```ruby
gem "better_auth-roda"
```

## Usage

```ruby
require "roda"
require "better_auth/roda"

class App < Roda
  plugin :better_auth

  better_auth at: "/api/auth" do |config|
    config.secret = ENV.fetch("BETTER_AUTH_SECRET")
    config.base_url = ENV["BETTER_AUTH_URL"]
    config.database = :memory
    config.email_and_password = {enabled: true}
  end

  route do |r|
    r.better_auth

    r.get "dashboard" do
      current_user.to_json
    end
  end
end
```

## Development

```bash
cd packages/better_auth-roda
bundle exec rake ci
```

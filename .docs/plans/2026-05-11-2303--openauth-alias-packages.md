# OpenAuth Alias Packages

- [x] Read repository instructions and package layout.
- [x] Confirm this is packaging-only work with no upstream behavior change.
- [x] Add a packaging smoke test for OpenAuth alias gems.
- [x] Add `openauth` and matching `openauth-*` alias packages for existing gems.
- [x] Document alias packages with the Better Auth Ruby docs URL.
- [x] Wire the packaging smoke test into workspace CI.
- [x] Run packaging validation.

## Validation

- `ruby -Itest test/openauth_alias_packages_test.rb`
- `RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache bundle exec standardrb Rakefile test packages/openauth*/lib packages/openauth*/*.gemspec`
- `bundle exec ruby -e 'require "openauth"; require "openauth/api_key"; require "openauth/mongo_adapter"; require "openauth/oauth_provider"; require "openauth/passkey"; require "openauth/redis_storage"; require "openauth/scim"; require "openauth/sso"; require "openauth/stripe"; puts [OpenAuth::VERSION, OpenAuth::APIKey::VERSION, OpenAuth::Stripe::VERSION].join(" ")'`
- `bundle exec ruby -e 'require "openauth/rails"; require "openauth/sinatra"; require "openauth/hanami"; puts [OpenAuth::Rails::VERSION, OpenAuth::Sinatra::VERSION, OpenAuth::Hanami::VERSION].join(" ")'`
- `gem build` for every `packages/openauth*/openauth*.gemspec`, with output written to `/private/tmp`.

## Notes

- Upstream behavior does not need adaptation because these packages only redirect to the existing Ruby packages.
- Use version `0.7.0` to match the currently published package versions in this repository.
- Use hyphenated extension names, for example `openauth-stripe`, and slash require paths, for example `require "openauth/stripe"`.
- MongoDB uses the shorter `openauth-mongodb` alias while still depending on `better_auth-mongo-adapter`.

# better_auth-mongodb

MongoDB database adapter package for Better Auth Ruby.

## Installation

Add the gem and require the package before configuring auth:

```ruby
gem "better_auth-mongodb"
```

```ruby
require "mongo"
require "better_auth/mongodb"

mongo_client = Mongo::Client.new(ENV.fetch("BETTER_AUTH_MONGODB_URL"))

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: ->(options) {
    BetterAuth::Adapters::MongoDB.new(
      options,
      database: mongo_client.database,
      client: mongo_client,
      transaction: false
    )
  }
)
```

The lambda form lets Better Auth pass the final configuration into the adapter,
including plugins, custom schemas, and advanced database options.

## Notes

This package depends on the official `mongo` gem. Keeping MongoDB support outside `better_auth` avoids installing MongoDB client dependencies for applications that only use SQL, Rails, Hanami, or in-memory storage.

The adapter stores Better Auth models in singular MongoDB collections by default, maps logical `id` values to Mongo `_id`, converts ObjectId-compatible ids through the Mongo driver, and supports the shared Better Auth database adapter contract.

Transactions are deployment-dependent. MongoDB multi-document transactions may
be unavailable on standalone servers and usually require a replica set plus
compatible driver/session settings. The setup example uses `transaction: false`;
enable transactions only when the MongoDB deployment supports them.

When using a replica set, remove `transaction: false` or pass
`transaction: true`. When using standalone local MongoDB, keep
`transaction: false`.

## Indexes

MongoDB does not run SQL-style migrations. The adapter can create recommended
indexes from Better Auth schema metadata, but this is an explicit setup step:

```ruby
adapter = BetterAuth::Adapters::MongoDB.new(
  options,
  database: mongo_client.database,
  client: mongo_client,
  transaction: false
)

adapter.ensure_indexes!
```

`ensure_indexes!` creates indexes for schema fields marked `unique: true` or
`index: true`, including plugin schemas and custom model or field names. It
skips Mongo `_id` because MongoDB creates that index automatically. The method
returns a summary of requested indexes so deployment scripts can log what was
applied.

## Limits

By default, `find_many` calls without an explicit `limit:` are capped at 100 records. Configure the default with Better Auth's advanced database option:

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  advanced: {
    database: {
      default_find_many_limit: 250
    }
  },
  database: ->(options) {
    BetterAuth::Adapters::MongoDB.new(
      options,
      database: mongo_client.database,
      client: mongo_client,
      transaction: false
    )
  }
)
```

The same default applies to one-to-many join lookups when the join config does not set `limit:`. Passing an explicit `limit:` to `find_many` or to the join config overrides the default.

Explicit `limit:` values must be positive integers. Explicit `offset:` values
must be zero or positive integers. Invalid configured defaults, including
non-positive `default_find_many_limit` values, fall back to the built-in cap of
100 records.

One-to-one joins ignore one-to-many limits. They are returned as a single object or `nil`.

Ruby's MongoDB adapter matches upstream's adapter factory by requiring array
values for the `in` filter operator. The Ruby adapter still accepts scalar
values for `not_in` and coerces them to a one-element list, matching the Ruby
adapter-family behavior.

Update calls intentionally strip logical `id` / Mongo `_id` from `$set` payloads
so callers cannot mutate immutable Mongo identifiers. If an update contains no
caller-supplied schema fields after id and unknown fields are ignored, the
adapter raises `BAD_REQUEST` before calling MongoDB.

Default storage field names use Ruby's snake_case convention. For example, an
additional or plugin field named `camelCaseField` is stored as
`camel_case_field` unless the schema config provides an explicit `fieldName`.

## Compatibility

The older `better_auth-mongo-adapter` gem and `require "better_auth/mongo_adapter"`
entrypoint are deprecated compatibility shims. New applications should use
`better_auth-mongodb` and `require "better_auth/mongodb"`.

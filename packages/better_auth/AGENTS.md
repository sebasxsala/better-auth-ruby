# AGENTS.md - better_auth (Core)

**Always read this file when editing files in `packages/better_auth/`.**

This is the core authentication library. It is **framework-agnostic** and depends only on Rack. No Rails code belongs here.

## What This Package Is

`better_auth` is the Ruby translation of the upstream `packages/better-auth` TypeScript package. It contains all core authentication logic: session management, token handling, OAuth flows, user/account models, password hashing, and the plugin system.

## Upstream Reference

**Always check `upstream/better-auth/1.6.9/` before implementing or modifying features.**

The TypeScript code in `upstream/better-auth/1.6.9/packages/better-auth/` is the source of truth. Workflow:

1. **Find the feature** in `upstream/better-auth/1.6.9/packages/better-auth/src/` (and `plugins/` when applicable)
2. **Understand how it works** in TypeScript
3. **Translate to Ruby** using idiomatic Ruby and this gem’s patterns
4. **Adapt** — same behavior, not necessarily a line-by-line port

Key paths:

- `upstream/better-auth/1.6.9/packages/better-auth/src/` — core auth logic
- `upstream/better-auth/1.6.9/packages/better-auth/src/plugins/` — plugins

## Constraints

- **No Rails dependencies.** This gem must work with any Rack-based app (Sinatra, Hanami, Roda, etc.)
- **No RSpec.** This package uses Minitest exclusively.
- Runtime deps are intentionally small and framework-agnostic. `bcrypt` is optional: default password hashing uses `OpenSSL::KDF.scrypt`, and apps that configure `password_hasher: :bcrypt` must add `gem "bcrypt"`.
- If a dependency is needed for a feature, optimization, or simplification, ask for approval before adding it.

## Development

```bash
bundle install
bundle exec rake test       # Run Minitest suite
bundle exec standardrb      # Check linting
bundle exec standardrb --fix # Auto-fix
bundle exec rake ci         # Full CI (lint + test)
```

## Directory Structure

```
lib/
  better_auth.rb              # Main entry point, autoloads
  better_auth/
    version.rb                # BetterAuth::VERSION
    core.rb                   # Core module loader
    core/                     # Core auth logic (sessions, tokens, OAuth, etc.)

test/
  test_helper.rb              # Minitest setup, shared helpers
  better_auth_test.rb         # Top-level smoke tests
  better_auth/
    <module>_test.rb          # Tests mirror lib/ structure
```

## Namespace

- **Gem name**: `better_auth`
- **Require path**: `require "better_auth"`
- **Top-level module**: `BetterAuth`
- Everything lives under `BetterAuth::` (e.g., `BetterAuth::Session`, `BetterAuth::OAuth::Provider`)

## Testing

- Framework: **Minitest**
- Files: `test/**/*_test.rb`
- Run: `bundle exec rake test`
- All public APIs must have tests
- Prefer integration-style tests that exercise real flows over unit tests with mocks
- Use `cd ../.. && docker compose up -d` for database-dependent tests when working from this package

## Translating from Upstream

When porting a feature from `upstream/better-auth/1.6.9/packages/better-auth/src/`:

1. Read the TypeScript source thoroughly
2. Understand the data flow and side effects
3. Write the Ruby equivalent using idiomatic patterns
4. Ensure the same edge cases are handled
5. Write tests that verify the same behavior (check `upstream/better-auth/1.6.9/packages/better-auth/src/**/*.test.ts` for cases to port)

## Code Style

- StandardRB
- `# frozen_string_literal: true` in all Ruby files
- `snake_case` files/methods; `CamelCase` classes/modules

## After Everything is Done

**Unless the user asked for it or you are working on CI, do not commit.**

- `bundle exec standardrb` passes
- `bundle exec rake test` passes

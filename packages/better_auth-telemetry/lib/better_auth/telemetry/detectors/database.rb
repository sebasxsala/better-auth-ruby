# frozen_string_literal: true

require "rubygems"

module BetterAuth
  module Telemetry
    module Detectors
      # Database detector. Returns a small hash describing the database
      # backend the host application is using (or `nil` when no signal
      # is available).
      #
      # This is the Ruby-specific replacement for upstream's
      # `detect-database.ts`, which only walked the Node `package.json`
      # for known SQL/ORM packages. The Ruby port adds two earlier
      # precedence rules (a caller-supplied context override and a
      # `BetterAuth::Configuration` adapter check) so an application
      # with a configured Better Auth adapter does not fall through to
      # the generic gem fallback.
      #
      # ## Precedence chain (Requirement 10)
      #
      # 1. **Context override** — when the caller supplied a non-empty
      #    `context.database` string, return it verbatim with
      #    `version: nil`. The generic `"adapter"` marker is refined
      #    from `context.adapter` when it names a known
      #    `BetterAuth::Adapters::*` class.
      # 2. **Configuration adapter** — when `options` is a
      #    {BetterAuth::Configuration} (or a hash with a `:database`
      #    key) and the value is a known adapter symbol
      #    ({ADAPTER_SYMBOLS}) or a `BetterAuth::Adapters::*` instance
      #    ({ADAPTER_CLASS_MAP}), return its short identifier with
      #    `version: nil`.
      # 3. **Gem fallback** — when neither rule above matches, walk
      #    `Gem.loaded_specs` in {GEM_FALLBACKS} order and return the
      #    first match as `{name: <gem_name>, version: <spec.version.to_s>}`.
      # 4. Otherwise — `nil`.
      #
      # ## Failure handling
      #
      # The whole call is wrapped in `rescue StandardError; nil` so a
      # surprise from any branch (an exotic `context` shape, a
      # `Configuration` reader that raises on a partially constructed
      # instance, a `Gem.loaded_specs` mutation, …) degrades to `nil`
      # rather than escaping out of the init payload composition in
      # {BetterAuth::Telemetry.create}.
      #
      # @example Context override
      #   ctx = BetterAuth::Telemetry::NormalizedContext.from(database: "postgresql")
      #   BetterAuth::Telemetry::Detectors::Database.call(nil, ctx)
      #   # => {name: "postgresql", version: nil}
      #
      # @example Configuration symbol
      #   config = BetterAuth::Configuration.new(secret: "...", database: :memory)
      #   BetterAuth::Telemetry::Detectors::Database.call(config, nil)
      #   # => {name: "memory", version: nil}
      module Database
        # Map from `BetterAuth::Adapters::*` class name to the short
        # identifier reported in the init event. Class names are
        # matched as strings so loading the telemetry gem does not
        # autoload every adapter constant.
        ADAPTER_CLASS_MAP = {
          "BetterAuth::Adapters::Postgres" => "postgres",
          "BetterAuth::Adapters::MySQL" => "mysql",
          "BetterAuth::Adapters::SQLite" => "sqlite",
          "BetterAuth::Adapters::MSSQL" => "mssql",
          "BetterAuth::Adapters::Memory" => "memory",
          "BetterAuth::Adapters::MongoDB" => "mongodb"
        }.freeze

        # Map from a known {BetterAuth::Configuration#database} symbol
        # value to the short identifier reported in the init event.
        ADAPTER_SYMBOLS = {
          postgres: "postgres",
          mysql: "mysql",
          sqlite: "sqlite",
          mssql: "mssql",
          memory: "memory"
        }.freeze

        # Gems to probe in `Gem.loaded_specs`, in upstream-spec order.
        # First match wins.
        GEM_FALLBACKS = %w[sequel pg mysql2 sqlite3 activerecord mongoid mongo rom-sql].freeze

        module_function

        # Resolve the database signal for the host application.
        #
        # @param options [BetterAuth::Configuration, Hash, nil] the
        #   options passed to {BetterAuth::Telemetry.create}. May be a
        #   {BetterAuth::Configuration} (production path), a raw hash
        #   with a `:database` key, or `nil`.
        # @param context [BetterAuth::Telemetry::NormalizedContext, Hash, nil]
        #   the optional context. When it responds to `:database` (or
        #   carries a `:database` / `"database"` key) and the value is
        #   a non-empty string, that string short-circuits the chain.
        # @return [Hash{Symbol => String, nil}, nil] either
        #   `{name: String, version: String|nil}` or `nil` when nothing
        #   matches.
        def call(options, context)
          override = context_override(context)
          return {name: override, version: nil} if override

          identifier = identify_from_options(options)
          return {name: identifier, version: nil} if identifier

          detect_from_gems
        rescue
          nil
        end

        # Read `database` from a {NormalizedContext}-like or hash-like
        # context. Returns the raw string when present and non-empty,
        # otherwise `nil`. The generic `"adapter"` marker is refined
        # from a known `context.adapter` class name when possible.
        # Non-string values (e.g. a symbol set accidentally) are
        # ignored to keep the wire shape stable.
        #
        # @param context [#database, Hash, nil]
        # @return [String, nil]
        def context_override(context)
          return nil if context.nil?

          value =
            if context.respond_to?(:database)
              context.database
            elsif context.respond_to?(:[])
              context[:database] || context["database"]
            end

          return nil unless value.is_a?(String)
          return nil if value.empty?

          return context_adapter_identifier(context) || value if value == "adapter"

          value
        end

        # Read `adapter` from a {NormalizedContext}-like or hash-like
        # context and map known `BetterAuth::Adapters::*` class names to
        # their database identifiers. Unknown names stay generic by
        # returning `nil` so the caller can preserve `"adapter"`.
        #
        # @param context [#adapter, Hash, nil]
        # @return [String, nil]
        def context_adapter_identifier(context)
          return nil if context.nil?

          value =
            if context.respond_to?(:adapter)
              context.adapter
            elsif context.respond_to?(:[])
              context[:adapter] || context["adapter"]
            end

          return nil unless value.is_a?(String)

          ADAPTER_CLASS_MAP[value]
        end

        # Translate the configuration's `database` value into a short
        # identifier when it matches a known adapter symbol or a known
        # `BetterAuth::Adapters::*` class.
        #
        # @param options [BetterAuth::Configuration, Hash, nil]
        # @return [String, nil]
        def identify_from_options(options)
          database = configuration_database(options)
          return nil if database.nil?

          identify_adapter(database)
        end

        # Read `database` from a {BetterAuth::Configuration} or a raw
        # hash. Returns `nil` for any other input shape.
        #
        # @param options [BetterAuth::Configuration, Hash, nil]
        # @return [Object, nil]
        def configuration_database(options)
          return nil if options.nil?

          if defined?(::BetterAuth::Configuration) && options.is_a?(::BetterAuth::Configuration)
            return options.database
          end

          return options[:database] || options["database"] if options.is_a?(Hash)

          nil
        end

        # Map a known adapter symbol or a `BetterAuth::Adapters::*`
        # instance to its short identifier. Returns `nil` when the
        # value is neither a known symbol nor a known adapter class.
        #
        # @param value [Symbol, BetterAuth::Adapters::Base, Object]
        # @return [String, nil]
        def identify_adapter(value)
          if value.is_a?(Symbol)
            return ADAPTER_SYMBOLS[value]
          end

          ADAPTER_CLASS_MAP[adapter_class_name(value)]
        end

        # Resolve an object's class name without requiring the class
        # constant to exist. Some tests and external adapters expose a
        # class-like singleton object whose `#name` carries the adapter
        # identifier.
        #
        # @param value [Object]
        # @return [String, nil]
        def adapter_class_name(value)
          klass = value.class
          klass.name if klass.respond_to?(:name)
        end

        # Walk {GEM_FALLBACKS} in order and return the first
        # `Gem.loaded_specs` match as `{name:, version:}`. Returns
        # `nil` when no listed gem is loaded.
        #
        # @return [Hash{Symbol => String}, nil]
        def detect_from_gems
          GEM_FALLBACKS.each do |name|
            spec = ::Gem.loaded_specs[name]
            next if spec.nil?

            version = spec.respond_to?(:version) ? spec.version : nil
            return {name: name, version: version&.to_s}
          end
          nil
        end
      end
    end
  end
end

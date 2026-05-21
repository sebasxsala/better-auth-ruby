# frozen_string_literal: true

require "json"
require "uri"

module BetterAuthExamples
  module Settings
    COOKIE_NAME = "better_auth_example_settings"
    DATABASES = %w[memory sqlite postgres mysql mssql mongodb].freeze
    RATE_ADAPTERS = %w[memory redis].freeze
    DEFAULTS = {
      database: "memory",
      rate_adapter: "memory",
      rate_window: 10,
      rate_max: 100,
      disabled_plugins: []
    }.freeze
    COOKIE_MAX_AGE = 60 * 60 * 24 * 365

    module_function

    def from_request(request)
      from_cookie(request.cookies[COOKIE_NAME])
    end

    def from_cookie(value)
      return DEFAULTS.dup if value.nil? || value.to_s.empty?

      normalize(JSON.parse(URI.decode_www_form_component(value.to_s)))
    rescue JSON::ParserError, ArgumentError
      DEFAULTS.dup
    end

    def normalize(input)
      input = symbolize_keys(input || {})
      database = DATABASES.include?(input[:database].to_s) ? input[:database].to_s : DEFAULTS[:database]
      rate_adapter = RATE_ADAPTERS.include?(input[:rate_adapter].to_s) ? input[:rate_adapter].to_s : DEFAULTS[:rate_adapter]

      {
        database: database,
        rate_adapter: rate_adapter,
        rate_window: positive_integer(input[:rate_window], DEFAULTS[:rate_window]),
        rate_max: positive_integer(input[:rate_max], DEFAULTS[:rate_max]),
        disabled_plugins: plugin_ids(input[:disabled_plugins])
      }
    end

    def cookie_value(settings)
      URI.encode_www_form_component(JSON.generate(normalize(settings)))
    end

    def set_cookie_header(settings)
      "#{COOKIE_NAME}=#{cookie_value(settings)}; Path=/; Max-Age=#{COOKIE_MAX_AGE}; SameSite=Lax"
    end

    def clear_auth_cookie_headers(request = nil)
      names = %w[
        better-auth.session_token
        better-auth.session_data
        better-auth.account_data
        better-auth.dont_remember
      ]
      if request
        names.concat(request.cookies.keys.select { |name| name.start_with?("better-auth.session_token_multi-") })
      end
      names.uniq.map { |name| "#{name}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly" }
    end

    def symbolize_keys(value)
      value.each_with_object({}) do |(key, object_value), result|
        normalized = key.to_s
          .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
          .tr("-", "_")
          .downcase
          .to_sym
        result[normalized] = object_value
      end
    end

    def positive_integer(value, fallback)
      parsed = Integer(value)
      parsed.positive? ? parsed : fallback
    rescue ArgumentError, TypeError
      fallback
    end

    def plugin_ids(value)
      Array(value)
        .flat_map { |entry| entry.to_s.split(",") }
        .map { |entry| entry.strip.downcase }
        .reject(&:empty?)
        .uniq
        .sort
    end
  end
end

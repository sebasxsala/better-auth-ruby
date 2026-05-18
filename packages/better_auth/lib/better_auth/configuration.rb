# frozen_string_literal: true

require "securerandom"
require "uri"

module BetterAuth
  class Configuration
    DEFAULT_BASE_PATH = "/api/auth"
    DEFAULT_SECRET = "better-auth-secret-12345678901234567890"
    DEFAULT_SESSION = {
      update_age: 24 * 60 * 60,
      expires_in: 60 * 60 * 24 * 7,
      fresh_age: 60 * 60 * 24
    }.freeze
    DEFAULT_EMAIL_AND_PASSWORD = {
      min_password_length: 8,
      max_password_length: 128
    }.freeze
    DEFAULT_PASSWORD_HASHER = :scrypt
    SUPPORTED_PASSWORD_HASHERS = [:scrypt, :bcrypt].freeze
    DEFAULT_STATELESS_SESSION = {
      cookie_cache: {
        enabled: true,
        strategy: "jwe",
        refresh_cache: true
      }
    }.freeze
    DEFAULT_STATELESS_ACCOUNT = {
      store_state_strategy: "cookie",
      store_account_cookie: true
    }.freeze

    attr_reader :app_name,
      :base_url_config,
      :base_path,
      :context_base_url,
      :secret,
      :secret_config,
      :database,
      :plugins,
      :trusted_origins,
      :rate_limit,
      :session,
      :account,
      :user,
      :verification,
      :advanced,
      :email_and_password,
      :password_hasher,
      :email_verification,
      :social_providers,
      :experimental,
      :secondary_storage,
      :database_hooks,
      :hooks,
      :on_api_error,
      :disabled_paths,
      :trusted_origins_callback,
      :telemetry,
      :logger

    def initialize(options = {})
      options = symbolize_keys(options)
      @explicit_options = deep_dup(options)

      @logger = options[:logger]
      @app_name = options[:app_name] || "Better Auth"
      @base_path = normalize_base_path(options.fetch(:base_path, DEFAULT_BASE_PATH))
      @database = options[:database]
      @secondary_storage = options[:secondary_storage]
      @plugins = normalize_plugins(options[:plugins])
      @advanced = deep_merge({}, symbolize_keys(options[:advanced] || {}))
      @disabled_paths = Array(options[:disabled_paths]).compact.map(&:to_s)
      @database_hooks = options[:database_hooks]
      @hooks = options[:hooks]
      @on_api_error = symbolize_keys(options[:on_api_error] || options[:on_apierror] || {})
      @telemetry = symbolize_keys(options[:telemetry] || {})
      @social_providers = normalize_social_providers(options[:social_providers])
      @trusted_origins_callbacks = []
      @trusted_origins_callbacks << options[:trusted_origins] if options[:trusted_origins].respond_to?(:call)
      @trusted_origins_callback = combined_trusted_origins_callback
      legacy_secret = resolve_secret(options, allow_test_default: false)
      secrets = options.key?(:secrets) ? options[:secrets] : SecretConfig.parse_env(Env.get("BETTER_AUTH_SECRETS"))
      if secrets
        @secret_config = SecretConfig.build(secrets, legacy_secret, logger: logger)
        @secret = @secret_config.current_secret
      else
        @secret = legacy_secret || (test_environment? ? DEFAULT_SECRET : nil)
        @secret_config = @secret
      end
      @base_url_config = options[:base_url]
      @base_url, @context_base_url = normalize_base_url(options[:base_url])
      @session = normalize_session(options[:session])
      @account = normalize_account(options[:account])
      @user = symbolize_keys(options[:user] || {})
      @verification = symbolize_keys(options[:verification] || {})
      @email_and_password = normalize_email_and_password(options[:email_and_password])
      @password_hasher = normalize_password_hasher(options[:password_hasher])
      @email_verification = symbolize_keys(options[:email_verification] || {})
      @experimental = normalize_experimental(options[:experimental])
      @rate_limit = normalize_rate_limit(options[:rate_limit])
      @trusted_origins = normalize_trusted_origins(options[:trusted_origins])

      validate_secret
    end

    def trusted_origin?(url, allow_relative_paths: false)
      trusted_origins.any? do |origin|
        self.class.matches_origin_pattern?(url, origin, allow_relative_paths: allow_relative_paths)
      end
    end

    def base_url
      Thread.current[base_url_runtime_key] || @base_url
    end

    def set_runtime_base_url(value)
      Thread.current[base_url_runtime_key] = value
    end

    def clear_runtime_base_url!
      Thread.current[base_url_runtime_key] = nil
    end

    def production?
      production_environment?
    end

    def dynamic_base_url?
      URLHelpers.dynamic_config?(base_url_config)
    end

    def to_h
      {
        app_name: app_name,
        base_url: base_url,
        base_path: base_path,
        secret: secret,
        secret_config: secret_config,
        database: database,
        plugins: plugins,
        trusted_origins: trusted_origins,
        rate_limit: rate_limit,
        session: session,
        account: account,
        user: user,
        verification: verification,
        advanced: advanced,
        email_and_password: email_and_password,
        password_hasher: password_hasher,
        email_verification: email_verification,
        social_providers: social_providers,
        experimental: experimental,
        secondary_storage: secondary_storage,
        database_hooks: database_hooks,
        hooks: hooks,
        on_api_error: on_api_error,
        disabled_paths: disabled_paths,
        telemetry: telemetry
      }
    end

    def merge_defaults!(defaults)
      normalized = symbolize_keys(defaults || {})
      normalized.each do |key, value|
        next unless respond_to?(key)
        next if key == :database_hooks

        if key == :trusted_origins
          merge_trusted_origins_default(value)
          next
        end

        instance_variable_set("@#{key}", merge_default_value([key], public_send(key), value))
      end
    end

    def self.matches_origin_pattern?(url, pattern, allow_relative_paths: false)
      return relative_path_allowed?(url) if url.start_with?("/") && allow_relative_paths
      return false if url.start_with?("/")

      uri = parse_uri(url)
      return false unless uri

      if pattern.include?("*") || pattern.include?("?")
        if pattern.include?("://")
          origin = origin_for(uri)
          return true if origin && wildcard_match?(pattern, origin)

          return wildcard_match?(pattern, url)
        end

        return wildcard_match?(pattern, uri.host.to_s)
      end

      protocol = uri.scheme&.then { |scheme| "#{scheme}:" }
      if protocol == "http:" || protocol == "https:" || protocol.nil?
        pattern == origin_for(uri)
      else
        url.start_with?(pattern)
      end
    end

    def self.relative_path_allowed?(url)
      %r{\A/(?!/|\\|%2f|%5c)[\w\-.+/@]*(?:\?[\w\-.+/=&%@]*)?\z}i.match?(url)
    end

    def self.parse_uri(url)
      URI.parse(url)
    rescue URI::InvalidURIError
      nil
    end

    def self.origin_for(uri)
      return nil unless uri.scheme && uri.host

      port = uri.port
      default_port = (uri.scheme == "http" && port == 80) || (uri.scheme == "https" && port == 443)
      host = uri.host
      host = "[#{host}]" if host.include?(":") && !host.start_with?("[")
      origin = "#{uri.scheme}://#{host}"
      default_port ? origin : "#{origin}:#{port}"
    end

    def self.wildcard_match?(pattern, value)
      regex = Regexp.escape(pattern).gsub("\\*", ".*").gsub("\\?", ".")
      /\A#{regex}\z/.match?(value)
    end

    private

    def normalize_base_url(value)
      configured = value || env_base_url
      return ["", ""] unless configured && !configured.empty?

      if URLHelpers.dynamic_config?(configured)
        validate_dynamic_base_url!(configured)
        resolved = URLHelpers.resolve_base_url(configured, base_path)
        return ["", ""] unless resolved

        uri = URI.parse(resolved)
        return [self.class.origin_for(uri), resolved.sub(%r{/+\z}, "")]
      end

      with_path = append_base_path(configured.to_s)
      uri = URI.parse(with_path)
      validate_http_url!(uri, configured)
      [self.class.origin_for(uri), with_path.sub(%r{/+\z}, "")]
    rescue URI::InvalidURIError
      raise Error, "Invalid base URL: #{configured}. Please provide a valid base URL."
    end

    def validate_dynamic_base_url!(value)
      allowed_hosts = value[:allowed_hosts] || value["allowed_hosts"] || value[:allowedHosts] || value["allowedHosts"]
      raise Error, "baseURL.allowedHosts cannot be empty" if allowed_hosts.respond_to?(:empty?) && allowed_hosts.empty?
    end

    def normalize_base_path(value)
      return "" if value.nil? || value == "" || value == "/"

      path = value.to_s
      path.start_with?("/") ? path.sub(%r{/+\z}, "") : "/#{path.sub(%r{/+\z}, "")}"
    end

    def append_base_path(url)
      uri = URI.parse(url)
      validate_http_url!(uri, url)
      path = uri.path.to_s.sub(%r{/+\z}, "")
      has_path = !path.empty? && path != "/"
      trimmed = url.to_s.sub(%r{/+\z}, "")
      return trimmed if has_path || base_path.empty?

      "#{trimmed}#{base_path}"
    end

    def validate_http_url!(uri, original)
      return if uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)

      raise Error, "Invalid base URL: #{original}. URL must include 'http://' or 'https://'"
    end

    def env_base_url
      base_url = ENV["BASE_URL"]
      [
        Env.get("BETTER_AUTH_URL"),
        (base_url unless base_url == "/")
      ].find { |value| value && !value.empty? }
    end

    def resolve_secret(options, allow_test_default: true)
      [options[:secret], Env.get("BETTER_AUTH_SECRET"), ENV["AUTH_SECRET"]].find { |value| value && !value.empty? } ||
        ((allow_test_default && test_environment?) ? DEFAULT_SECRET : nil)
    end

    def validate_secret
      if secret.nil? || secret.empty?
        raise Error, "BETTER_AUTH_SECRET is missing. Set it in your environment or pass `secret` to BetterAuth.auth(secret: ...)."
      end

      if production_environment? && secret == DEFAULT_SECRET
        raise Error, "You are using the default secret. Please set `BETTER_AUTH_SECRET` in your environment variables or pass `secret` in your auth config."
      end

      return if test_environment? && secret == DEFAULT_SECRET

      warn("[better-auth] Warning: your BETTER_AUTH_SECRET should be at least 32 characters long for adequate security.") if secret.length < 32
      warn("[better-auth] Warning: your BETTER_AUTH_SECRET appears low-entropy. Use a randomly generated secret for production.") if entropy(secret) < 120
    end

    def entropy(value)
      unique = value.chars.uniq.length
      return 0 if unique.zero?

      Math.log2(unique**value.length)
    end

    def normalize_session(value)
      configured = symbolize_keys(value || {})
      cookie_cache = symbolize_keys(configured.delete(:cookie_cache) || {})
      session = deep_merge(DEFAULT_SESSION, configured)

      if database.nil?
        session = deep_merge(session, deep_dup(DEFAULT_STATELESS_SESSION))
        session[:cookie_cache][:max_age] ||= session[:expires_in]
      else
        session[:cookie_cache] = cookie_cache unless cookie_cache.empty?
      end

      session[:cookie_cache] = deep_merge(session[:cookie_cache] || {}, cookie_cache) unless cookie_cache.empty?
      if (database || secondary_storage) && session.dig(:cookie_cache, :refresh_cache)
        warn("[better-auth] `session.cookieCache.refreshCache` is enabled while `database` or `secondaryStorage` is configured. `refreshCache` is meant for stateless setups. Disabling `refreshCache`.")
        session[:cookie_cache] = session[:cookie_cache].merge(refresh_cache: false)
      end
      session
    end

    def normalize_account(value)
      configured = symbolize_keys(value || {})
      database.nil? ? deep_merge(DEFAULT_STATELESS_ACCOUNT, configured) : configured
    end

    def normalize_email_and_password(value)
      deep_merge(DEFAULT_EMAIL_AND_PASSWORD, symbolize_keys(value || {}))
    end

    def normalize_password_hasher(value)
      hasher = (value || DEFAULT_PASSWORD_HASHER).to_sym
      return hasher if SUPPORTED_PASSWORD_HASHERS.include?(hasher)

      raise Error, "Unsupported password hasher: #{value}. Supported hashers are :scrypt and :bcrypt."
    end

    def normalize_experimental(value)
      configured = symbolize_keys(value || {})
      {
        joins: !!configured[:joins]
      }
    end

    def normalize_rate_limit(value)
      configured = symbolize_keys(value || {})
      {
        enabled: configured.key?(:enabled) ? configured[:enabled] : production_environment?,
        window: configured[:window] || 10,
        max: configured[:max] || 100,
        storage: configured[:storage] || (secondary_storage ? "secondary-storage" : "memory")
      }.merge(configured)
    end

    def normalize_plugins(value)
      Array(value).compact.reject { |plugin| plugin == false }.map { |plugin| Plugin.coerce(plugin) }
    end

    def normalize_social_providers(value)
      symbolize_keys(value || {}).reject do |_id, provider|
        provider.nil? || provider == false || (provider.is_a?(Hash) && provider[:enabled] == false)
      end
    end

    def normalize_trusted_origins(value)
      origins = []
      origins << base_url unless base_url.nil? || base_url.empty?
      origins.concat(dynamic_base_url_trusted_origins)
      origins.concat(Array(value).compact) unless value.respond_to?(:call)
      origins.concat(env_trusted_origins)
      origins.map(&:to_s).reject(&:empty?).uniq
    end

    def dynamic_base_url_trusted_origins
      return [] unless URLHelpers.dynamic_config?(base_url_config)

      protocol = base_url_config[:protocol] || base_url_config["protocol"] || "https"
      allowed_hosts = base_url_config[:allowed_hosts] || base_url_config["allowed_hosts"] || base_url_config[:allowedHosts] || base_url_config["allowedHosts"] || []
      Array(allowed_hosts).map do |host|
        host = host.to_s
        host.match?(%r{\Ahttps?://}i) ? host : "#{protocol}://#{host}"
      end
    end

    def merge_trusted_origins_default(value)
      if value.respond_to?(:call)
        @trusted_origins_callbacks << value
        @trusted_origins_callback = combined_trusted_origins_callback
      else
        @trusted_origins = (trusted_origins + Array(value).compact.map(&:to_s).reject(&:empty?)).uniq
      end
    end

    def combined_trusted_origins_callback
      return nil if @trusted_origins_callbacks.empty?

      ->(request) { @trusted_origins_callbacks.flat_map { |callback| Array(callback.call(request)) }.compact }
    end

    def env_trusted_origins
      Env.csv("BETTER_AUTH_TRUSTED_ORIGINS")
    end

    def symbolize_keys(value)
      return value unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object_value), result|
        normalized_key = normalize_key(key)
        result[normalized_key] = object_value.is_a?(Hash) ? symbolize_keys(object_value) : object_value
      end
    end

    def normalize_key(key)
      key.to_s
        .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
        .tr("-", "_")
        .downcase
        .to_sym
    end

    def deep_merge(base, override)
      base.merge(override) do |_key, old_value, new_value|
        if old_value.is_a?(Hash) && new_value.is_a?(Hash)
          deep_merge(old_value, new_value)
        else
          new_value
        end
      end
    end

    def merge_default_value(path, current, default)
      if current.is_a?(Hash) && default.is_a?(Hash)
        default.each_with_object(current.dup) do |(key, value), result|
          result[key] = merge_default_value(path + [key], result[key], value)
        end
      else
        return current if explicit_path?(path)

        default
      end
    end

    def explicit_path?(path)
      path.reduce(@explicit_options) do |value, key|
        return false unless value.is_a?(Hash) && value.key?(key)

        value[key]
      end
      true
    end

    def deep_dup(value)
      return value.transform_values { |entry| deep_dup(entry) } if value.is_a?(Hash)
      return value.map { |entry| deep_dup(entry) } if value.is_a?(Array)

      value
    end

    def warn(message)
      if logger.respond_to?(:call)
        logger.call(:warn, message)
      elsif logger.respond_to?(:warn)
        logger.warn(message)
      end
    end

    def base_url_runtime_key
      :"better_auth_configuration_base_url_#{object_id}"
    end

    def test_environment?
      ENV["RACK_ENV"] == "test" || ENV["RAILS_ENV"] == "test" || ENV["APP_ENV"] == "test"
    end

    def production_environment?
      ENV["RACK_ENV"] == "production" || ENV["RAILS_ENV"] == "production" || ENV["APP_ENV"] == "production"
    end
  end
end

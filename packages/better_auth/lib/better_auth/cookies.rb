# frozen_string_literal: true

require "json"
require "time"
require "uri"

module BetterAuth
  module Cookies
    SECURE_COOKIE_PREFIX = "__Secure-"
    HOST_COOKIE_PREFIX = "__Host-"

    Cookie = Struct.new(:name, :attributes, keyword_init: true) do
      alias_method :options, :attributes
    end

    module_function

    def get_cookies(options)
      {
        session_token: create_cookie(options, "session_token", max_age: options.session[:expires_in] || 60 * 60 * 24 * 7),
        session_data: create_cookie(options, "session_data", max_age: options.session.dig(:cookie_cache, :max_age) || 60 * 5),
        account_data: create_cookie(options, "account_data", max_age: options.session.dig(:cookie_cache, :max_age) || 60 * 5),
        dont_remember: create_cookie(options, "dont_remember")
      }
    end

    def create_cookie(options, cookie_name, override_attributes = {})
      advanced = options.advanced || {}
      secure = if advanced.key?(:use_secure_cookies)
        advanced[:use_secure_cookies]
      elsif options.base_url.to_s.start_with?("https://")
        true
      else
        production_environment?
      end
      cross_subdomain = advanced.dig(:cross_subdomain_cookies, :enabled)
      domain = if cross_subdomain
        advanced.dig(:cross_subdomain_cookies, :domain) || begin
          uri = URI.parse(options.base_url.to_s)
          uri.host unless uri.host.to_s.empty?
        end
      end
      raise Error, "base_url is required when cross_subdomain_cookies are enabled" if cross_subdomain && domain.to_s.empty? && !options.dynamic_base_url?

      custom = advanced.dig(:cookies, cookie_name.to_sym) || {}
      prefix = advanced[:cookie_prefix] || "better-auth"
      name = custom[:name] || "#{prefix}.#{cookie_name}"
      attributes = {
        secure: !!secure,
        same_site: "lax",
        path: "/",
        http_only: true
      }
      attributes[:domain] = domain if domain
      attributes = attributes
        .merge(advanced[:default_cookie_attributes] || {})
        .merge(override_attributes || {})
        .merge(custom[:attributes] || {})
        .compact

      cookie_prefix = secure ? SECURE_COOKIE_PREFIX : ""
      Cookie.new(name: "#{cookie_prefix}#{name}", attributes: attributes)
    end

    def parse_cookies(cookie_header)
      cookie_header.to_s.split(/;\s*/).each_with_object({}) do |pair, result|
        name, value = pair.split("=", 2)
        next if name.to_s.empty? || value.nil?

        result[name.strip] = decode_cookie_value(value.strip)
      end
    end

    def strip_secure_cookie_prefix(name)
      name.to_s.delete_prefix(SECURE_COOKIE_PREFIX).delete_prefix(HOST_COOKIE_PREFIX)
    end

    def get_session_cookie(request_or_cookie_header, config = {})
      cookie_header = header_value(request_or_cookie_header)
      return nil if cookie_header.to_s.empty?

      parsed = parse_cookies(cookie_header)
      cookie_name = config[:cookie_name] || "session_token"
      cookie_prefix = config[:cookie_prefix] || "better-auth"
      candidates = [
        "#{cookie_prefix}.#{cookie_name}",
        "#{SECURE_COOKIE_PREFIX}#{cookie_prefix}.#{cookie_name}",
        "#{cookie_prefix}-#{cookie_name}",
        "#{SECURE_COOKIE_PREFIX}#{cookie_prefix}-#{cookie_name}"
      ]
      candidates.lazy.filter_map { |candidate| parsed[candidate] }.first
    end

    def set_session_cookie(ctx, session, dont_remember_me = false, overrides = {})
      token_cookie = ctx.context.auth_cookies[:session_token]
      max_age = dont_remember_me ? nil : ctx.context.session_config[:expires_in]
      ctx.set_signed_cookie(token_cookie.name, session.fetch(:session).fetch("token"), ctx.context.secret, token_cookie.attributes.merge(max_age: max_age).merge(overrides || {}))

      if dont_remember_me
        dont_remember_cookie = ctx.context.auth_cookies[:dont_remember]
        ctx.set_signed_cookie(dont_remember_cookie.name, "true", ctx.context.secret, dont_remember_cookie.attributes)
      end

      set_cookie_cache(ctx, session, dont_remember_me)
      ctx.context.set_new_session(session) if ctx.context.respond_to?(:set_new_session)
    end

    def set_cookie_cache(ctx, session, dont_remember_me)
      config = ctx.context.session_config[:cookie_cache] || {}
      return unless config[:enabled]

      cookie = ctx.context.auth_cookies[:session_data]
      max_age = dont_remember_me ? nil : cookie.attributes[:max_age]
      data = filtered_cache_data(ctx, session)
      strategy = config[:strategy] || "compact"
      secret = (strategy.to_s == "jwe") ? ctx.context.secret_config : ctx.context.secret
      value = encode_cookie_cache(data, secret, strategy: strategy, max_age: max_age || 60 * 5)
      attributes = cookie.attributes.merge(max_age: max_age)
      store = SessionStore.new(cookie.name, attributes, ctx)

      if value.length > SessionStore::CHUNK_SIZE
        store.set_cookies(store.chunk(value, attributes))
      else
        store.set_cookies(store.clean) if store.chunks?
        ctx.set_cookie(cookie.name, value, attributes)
      end
    end

    def set_account_cookie(ctx, account_data)
      return unless ctx.context.options.account[:store_account_cookie]

      cookie = ctx.context.auth_cookies[:account_data]
      attributes = cookie.attributes.merge(max_age: cookie.attributes[:max_age] || 60 * 5)
      value = Crypto.symmetric_encode_jwt(stringify_keys(account_data), ctx.context.secret_config, "better-auth-account", expires_in: attributes[:max_age])
      store = SessionStore.new(cookie.name, attributes, ctx)

      if value.length > SessionStore::CHUNK_SIZE
        store.set_cookies(store.chunk(value, attributes))
      else
        store.set_cookies(store.clean) if store.chunks?
        ctx.set_cookie(cookie.name, value, attributes)
      end
    end

    def get_account_cookie(ctx)
      cookie = ctx.context.auth_cookies[:account_data]
      value = SessionStore.get_chunked_cookie(ctx, cookie.name)
      return nil unless value

      Crypto.symmetric_decode_jwt(value, ctx.context.secret_config, "better-auth-account")
    end

    def get_cookie_cache(request_or_cookie_header, secret:, strategy: "compact", version: nil, cookie_prefix: "better-auth", cookie_name: "session_data", is_secure: nil, cookie_full_name: nil)
      cookie_header = header_value(request_or_cookie_header)
      return nil if cookie_header.to_s.empty?

      parsed = parse_cookies(cookie_header)
      name = if cookie_full_name
        cookie_full_name
      elsif is_secure.nil?
        production_environment? ? "#{SECURE_COOKIE_PREFIX}#{cookie_prefix}.#{cookie_name}" : "#{cookie_prefix}.#{cookie_name}"
      else
        secure_prefix = is_secure ? SECURE_COOKIE_PREFIX : ""
        "#{secure_prefix}#{cookie_prefix}.#{cookie_name}"
      end
      raw = parsed[name] || chunked_value(parsed, name)
      return nil unless raw

      payload = decode_cookie_cache(raw, secret, strategy: strategy)
      return nil unless payload && payload["session"] && payload["user"]

      expected_version = cookie_cache_version(version, payload["session"], payload["user"])
      return nil if version && (payload["version"] || "1") != expected_version

      payload
    end

    def expire_cookie(ctx, cookie)
      ctx.set_cookie(cookie.name, "", cookie.attributes.merge(max_age: 0))
    end

    def delete_session_cookie(ctx, skip_dont_remember_me: false)
      expire_cookie(ctx, ctx.context.auth_cookies[:session_token])
      expire_cookie(ctx, ctx.context.auth_cookies[:session_data])
      expire_cookie(ctx, ctx.context.auth_cookies[:account_data]) if ctx.context.options.account[:store_account_cookie]

      store = SessionStore.new(ctx.context.auth_cookies[:session_data].name, ctx.context.auth_cookies[:session_data].attributes, ctx)
      store.set_cookies(store.clean)
      expire_cookie(ctx, ctx.context.auth_cookies[:dont_remember]) unless skip_dont_remember_me
    end

    def dont_remember?(ctx)
      cookie = ctx.context.auth_cookies[:dont_remember]
      ctx.get_signed_cookie(cookie.name, ctx.context.secret) == "true"
    end

    def encode_cookie_cache(data, secret, strategy:, max_age:)
      case strategy.to_s
      when "jwt"
        Crypto.sign_jwt(data, secret, expires_in: max_age)
      when "jwe"
        Crypto.symmetric_encode_jwt(data, secret, "better-auth-session", expires_in: max_age)
      else
        expires_at = current_millis + (max_age.to_i * 1000)
        signed = data.merge("expiresAt" => expires_at)
        signature = Crypto.hmac_signature(JSON.generate(signed), secret, encoding: :base64url)
        Crypto.base64url_encode(JSON.generate({"session" => data, "expiresAt" => expires_at, "signature" => signature}))
      end
    end

    def decode_cookie_cache(value, secret, strategy:)
      case strategy.to_s
      when "jwt"
        Crypto.verify_jwt(value, secret)
      when "jwe"
        Crypto.symmetric_decode_jwt(value, secret, "better-auth-session")
      else
        payload = JSON.parse(Crypto.base64url_decode(value))
        return nil if payload["expiresAt"].to_i <= current_millis

        signed = payload.fetch("session").merge("expiresAt" => payload.fetch("expiresAt"))
        valid = Crypto.verify_hmac_signature(JSON.generate(signed), payload["signature"], secret, encoding: :base64url)
        valid ? payload["session"] : nil
      end
    rescue JSON::ParserError, KeyError, ArgumentError, JWT::DecodeError
      nil
    end

    def filtered_cache_data(ctx, session)
      {
        "session" => stringify_keys(Schema.parse_output(ctx.context.options, "session", stringify_keys(session.fetch(:session)))),
        "user" => stringify_keys(Schema.parse_output(ctx.context.options, "user", stringify_keys(session.fetch(:user)))),
        "updatedAt" => current_millis,
        "version" => cookie_cache_version(
          ctx.context.session_config.dig(:cookie_cache, :version),
          session.fetch(:session),
          session.fetch(:user)
        )
      }
    end

    def chunked_value(cookies, name)
      chunks = cookies.each_with_object([]) do |(cookie_name, value), result|
        next unless cookie_name.start_with?("#{name}.")

        result << [SessionStore.chunk_index(cookie_name), value]
      end
      return nil if chunks.empty?

      chunks.sort_by(&:first).map(&:last).join
    end

    def decode_cookie_value(value)
      URI.decode_uri_component(value)
    rescue ArgumentError
      value
    end

    def header_value(request_or_cookie_header)
      return request_or_cookie_header.headers["cookie"] if request_or_cookie_header.respond_to?(:headers)
      return request_or_cookie_header.get_header("HTTP_COOKIE") if request_or_cookie_header.respond_to?(:get_header)

      request_or_cookie_header.to_s
    end

    def cookie_cache_version(config, session, user)
      return "1" unless config
      return config.to_s unless config.respond_to?(:call)

      config.call(session, user).to_s
    end

    def current_millis
      (Time.now.to_f * 1000).to_i
    end

    def stringify_keys(value)
      return value.each_with_object({}) { |(key, object_value), result| result[key.to_s] = stringify_keys(object_value) } if value.is_a?(Hash)
      return value.map { |entry| stringify_keys(entry) } if value.is_a?(Array)

      value
    end

    def production_environment?
      ENV["RACK_ENV"] == "production" || ENV["RAILS_ENV"] == "production" || ENV["APP_ENV"] == "production"
    end
  end
end

# frozen_string_literal: true

require "time"

module BetterAuth
  module Session
    module_function

    def find_current(ctx, disable_cookie_cache: false, disable_refresh: false, sensitive: false)
      if ctx.context.current_session
        return ctx.context.current_session
      end

      token_cookie = ctx.context.auth_cookies[:session_token]
      token = ctx.get_signed_cookie(token_cookie.name, ctx.context.secret)
      return nil unless token

      cached = cached_session(ctx, token, disable_cookie_cache: disable_cookie_cache, sensitive: sensitive)
      if cached
        ctx.context.set_current_session(cached) if ctx.context.respond_to?(:set_current_session)
        return cached
      end

      found = ctx.context.internal_adapter.find_session(token)
      return missing_session(ctx) unless found

      session = stringify_keys(found[:session] || found["session"])
      user = stringify_keys(found[:user] || found["user"])
      return missing_session(ctx) if expired?(session)

      result = {session: session, user: user}
      result = refresh_session(ctx, result) if should_refresh?(ctx, session, disable_refresh)
      Cookies.set_cookie_cache(ctx, result, false)
      ctx.context.set_current_session(result) if ctx.context.respond_to?(:set_current_session)
      result
    end

    def cached_session(ctx, token, disable_cookie_cache:, sensitive:)
      config = ctx.context.session_config[:cookie_cache] || {}
      return nil if disable_cookie_cache || sensitive || !config[:enabled]

      payload = Cookies.get_cookie_cache(
        ctx,
        secret: ctx.context.secret,
        strategy: config[:strategy] || "compact",
        version: config[:version],
        cookie_prefix: ctx.context.options.advanced[:cookie_prefix] || "better-auth",
        is_secure: ctx.context.auth_cookies[:session_data].name.start_with?(Cookies::SECURE_COOKIE_PREFIX),
        cookie_full_name: ctx.context.auth_cookies[:session_data].name
      )
      return nil unless payload
      return nil if payload["session"]["token"] && payload["session"]["token"] != token

      result = {session: payload["session"], user: payload["user"]}
      result = refresh_cached_session(ctx, result) if should_refresh_cookie_cache?(config, payload)
      result
    end

    def missing_session(ctx)
      Cookies.delete_session_cookie(ctx)
      nil
    end

    def expired?(session)
      expires_at = normalize_time(session["expiresAt"])
      expires_at && expires_at <= Time.now
    end

    def should_refresh?(ctx, session, disable_refresh)
      return false if disable_refresh

      update_age = ctx.context.session_config[:update_age].to_i
      return true if update_age.zero?

      updated_at = normalize_time(session["updatedAt"])
      updated_at && updated_at + update_age <= Time.now
    end

    def refresh_session(ctx, result)
      now = Time.now
      expires_at = now + ctx.context.session_config[:expires_in].to_i
      updated = ctx.context.internal_adapter.update_session(
        result[:session]["token"],
        "expiresAt" => expires_at,
        "updatedAt" => now
      )
      session = stringify_keys(updated || result[:session]).merge("expiresAt" => expires_at, "updatedAt" => now)
      refreshed = {session: session, user: result[:user]}
      Cookies.set_session_cookie(ctx, refreshed, Cookies.dont_remember?(ctx))
      refreshed
    end

    def refresh_cached_session(ctx, result)
      now = Time.now
      session = stringify_keys(result[:session]).merge(
        "expiresAt" => now + ctx.context.session_config[:expires_in].to_i,
        "updatedAt" => now
      )
      refreshed = {session: session, user: result[:user]}
      Cookies.set_session_cookie(ctx, refreshed, Cookies.dont_remember?(ctx))
      refreshed
    end

    def should_refresh_cookie_cache?(config, payload)
      refresh_cache = config[:refresh_cache]
      return false if refresh_cache == false || refresh_cache.nil?

      max_age = (config[:max_age] || 60 * 5).to_i
      update_age = if refresh_cache.is_a?(Hash)
        (refresh_cache[:update_age] || refresh_cache["updateAge"] || refresh_cache["update_age"]).to_i
      else
        (max_age * 0.2).to_i
      end
      updated_at = payload["updatedAt"].to_i
      updated_at.positive? && updated_at + (update_age * 1000) <= (Time.now.to_f * 1000).to_i
    end

    def normalize_time(value)
      return value if value.is_a?(Time)
      return Time.at(value / 1000.0) if value.is_a?(Integer) && value > 10_000_000_000
      return Time.at(value) if value.is_a?(Integer)
      return nil if value.nil?

      Time.parse(value.to_s)
    end

    def stringify_keys(value)
      return value.each_with_object({}) { |(key, object_value), result| result[key.to_s] = stringify_keys(object_value) } if value.is_a?(Hash)
      return value.map { |entry| stringify_keys(entry) } if value.is_a?(Array)

      value
    end
  end
end

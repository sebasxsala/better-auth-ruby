# frozen_string_literal: true

require "json"

module BetterAuth
  class RateLimiter
    MISSING_CLIENT_IP_WARNING = "Rate limiting skipped: could not determine client IP address. " \
      "Ensure your runtime forwards a trusted client IP header and configure `advanced.ipAddress.ipAddressHeaders` if needed."

    class MemoryStore
      def initialize
        @entries = {}
        @mutex = Mutex.new
      end

      def get(key)
        @mutex.synchronize do
          entry = @entries[key]
          return nil unless entry

          if Time.now.to_f >= entry[:expires_at]
            @entries.delete(key)
            return nil
          end

          entry[:data]
        end
      end

      def set(key, value, ttl:, update: false)
        @mutex.synchronize do
          @entries[key] = {
            data: value,
            expires_at: Time.now.to_f + ttl.to_f
          }
        end
      end
    end

    def initialize
      @memory_store = MemoryStore.new
      @warned_missing_client_ip = false
    end

    def call(request, context, path)
      config = context.rate_limit_config || {}
      return unless config[:enabled]

      ip = client_ip(request, context.options)
      warn_missing_client_ip(context) unless ip
      return unless ip

      rule = rate_limit_rule(request, context, config, path)
      return if rule == false

      window = rule[:window] || 10
      max = rule[:max] || 100
      key = rate_limit_key(ip, path)
      now = Time.now.to_f
      storage = storage_for(context, config)
      data = read_storage(storage, key)

      unless data
        write_storage(storage, key, rate_limit_data(key, 1, now), ttl: window, update: false)
        return
      end

      last_request = data.fetch(:last_request).to_f
      count = data.fetch(:count).to_i
      if should_rate_limit?(max.to_i, window.to_f, count, last_request, now)
        return rate_limit_response(retry_after(last_request, window.to_f, now))
      end

      next_data = if now - last_request > window.to_f
        rate_limit_data(key, 1, now)
      else
        rate_limit_data(key, count + 1, now)
      end

      write_storage(storage, key, next_data, ttl: window, update: true)
      nil
    end

    private

    def rate_limit_response(retry_after)
      [
        429,
        {"content-type" => "application/json", "x-retry-after" => retry_after.to_s},
        [JSON.generate({message: "Too many requests. Please try again later."})]
      ]
    end

    def should_rate_limit?(max, window, count, last_request, now)
      now - last_request < window && count >= max
    end

    def retry_after(last_request, window, now)
      [(last_request + window - now).ceil, 0].max
    end

    def rate_limit_data(key, count, last_request)
      {
        key: key,
        count: count,
        last_request: last_request
      }
    end

    def rate_limit_rule(request, context, config, path)
      rule = {
        window: config[:window] || 10,
        max: config[:max] || 100
      }
      rule = default_special_rule(path) || rule
      rule = matching_plugin_rule(context, path) || rule
      custom_rule = matching_custom_rule(config, path)
      return resolve_custom_rule(custom_rule, request, rule) unless custom_rule.nil?

      rule
    end

    def default_special_rule(path)
      return {window: 10, max: 3} if path.start_with?("/sign-in", "/sign-up", "/change-password", "/change-email")
      return {window: 60, max: 3} if path == "/request-password-reset" ||
        path == "/send-verification-email" ||
        path.start_with?("/forget-password") ||
        path == "/email-otp/send-verification-otp" ||
        path == "/email-otp/request-password-reset"

      nil
    end

    def matching_custom_rule(config, path)
      custom_rules = config[:custom_rules] || {}
      custom_rules.find do |pattern, _rule|
        path_matches?(pattern.to_s, path)
      end&.last
    end

    def resolve_custom_rule(rule, request, current)
      return false if rule == false
      return rule.call(request, current) if rule.respond_to?(:call)

      rule || current
    end

    def storage_for(context, config)
      return [:custom, config[:custom_storage]] if config[:custom_storage]
      return [:database, context.internal_adapter.adapter] if config[:storage] == "database"

      if config[:storage] == "secondary-storage" && context.options.secondary_storage
        return [:secondary, context.options.secondary_storage]
      end

      [:memory, @memory_store]
    end

    def read_storage((type, storage), key)
      return read_database_storage(storage, key) if type == :database

      data = storage.get(key)
      data = JSON.parse(data) if type == :secondary && data.is_a?(String)
      normalize_rate_limit_data(symbolize_keys(data))
    rescue JSON::ParserError
      nil
    end

    def write_storage((type, storage), key, data, ttl:, update:)
      return write_database_storage(storage, key, data) if type == :database

      value = (type == :secondary) ? JSON.generate(secondary_storage_data(data)) : data
      return call_secondary_storage_set(storage, key, value, ttl: ttl, update: update) if type == :secondary

      call_storage_set(storage, key, value, ttl: ttl, update: update)
    end

    def read_database_storage(adapter, key)
      data = adapter.find_one(model: "rateLimit", where: [{field: "key", value: key}])
      normalize_rate_limit_data(symbolize_keys(data))
    end

    def write_database_storage(adapter, key, data)
      value = secondary_storage_data(data)
      existing = adapter.find_one(model: "rateLimit", where: [{field: "key", value: key}])
      if existing
        adapter.update(model: "rateLimit", where: [{field: "key", value: key}], update: value)
      else
        adapter.create(model: "rateLimit", data: value)
      end
    end

    def secondary_storage_data(data)
      {
        key: data[:key],
        count: data[:count],
        lastRequest: (data[:last_request].to_f * 1000).to_i
      }
    end

    def call_secondary_storage_set(storage, key, value, ttl:, update:)
      storage.set(key, value, ttl)
    rescue ArgumentError
      call_storage_set(storage, key, value, ttl: ttl, update: update)
    end

    def call_storage_set(storage, key, value, ttl:, update:)
      storage.set(key, value, ttl: ttl, update: update)
    rescue ArgumentError
      begin
        storage.set(key, value, ttl, update)
      rescue ArgumentError
        begin
          storage.set(key, value, ttl)
        rescue ArgumentError
          storage.set(key, value)
        end
      end
    end

    def symbolize_keys(value)
      return value unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object_value), result|
        result[key.to_s.gsub(/([a-z\d])([A-Z])/, "\\1_\\2").tr("-", "_").downcase.to_sym] = object_value
      end
    end

    def normalize_rate_limit_data(data)
      return data unless data.is_a?(Hash)

      last_request = data[:last_request]
      return data unless last_request.is_a?(Numeric) && last_request > 10_000_000_000

      data.merge(last_request: last_request / 1000.0)
    end

    def rate_limit_key(ip, path)
      "#{ip}|#{path}"
    end

    def client_ip(request, options)
      RequestIP.client_ip(request, options)
    end

    def warn_missing_client_ip(context)
      return if @warned_missing_client_ip
      return if context.options.advanced.dig(:ip_address, :disable_ip_tracking)

      @warned_missing_client_ip = true
      logger = context.logger
      if logger.respond_to?(:call)
        logger.call(:warn, MISSING_CLIENT_IP_WARNING)
      elsif logger.respond_to?(:warn)
        logger.warn(MISSING_CLIENT_IP_WARNING)
      end
    end

    def matching_plugin_rule(context, path)
      context.options.plugins
        .flat_map { |plugin| Array(plugin[:rate_limit]) }
        .find do |rule|
          matcher = rule[:path_matcher]
          matcher&.call(path)
        end
    end

    def path_matches?(pattern, path)
      return path == pattern unless pattern.include?("*")

      regex = Regexp.escape(pattern).gsub("\\*", ".*")
      /\A#{regex}\z/.match?(path)
    end
  end
end

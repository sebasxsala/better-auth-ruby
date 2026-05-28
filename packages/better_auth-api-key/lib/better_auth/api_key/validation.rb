# frozen_string_literal: true

module BetterAuth
  module APIKey
    module Validation
      module_function

      USAGE_LOCK_STRIPE_COUNT = 256

      def usage_lock_for(key)
        @usage_lock_stripes ||= Array.new(USAGE_LOCK_STRIPE_COUNT) { Mutex.new }
        @usage_lock_stripes[key.hash % USAGE_LOCK_STRIPE_COUNT]
      end

      def validate_create_update!(body, config, create:, client:)
        name = body[:name]
        if create && config[:require_name] && name.to_s.empty?
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["NAME_REQUIRED"])
        end
        if name && !name.to_s.length.between?(config[:minimum_name_length].to_i, config[:maximum_name_length].to_i)
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_NAME_LENGTH"])
        end
        prefix = body[:prefix]
        if prefix && !prefix.to_s.length.between?(config[:minimum_prefix_length].to_i, config[:maximum_prefix_length].to_i)
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_PREFIX_LENGTH"])
        end
        if prefix && !prefix.to_s.match?(/\A[a-zA-Z0-9_-]+\z/)
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_PREFIX_LENGTH"])
        end
        if body.key?(:remaining) && !body[:remaining].nil?
          minimum = create ? 0 : 1
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_REMAINING"]) if body[:remaining].to_i < minimum
        end
        if body[:metadata] && (create || config[:enable_metadata])
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["METADATA_DISABLED"]) unless config[:enable_metadata]
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_METADATA_TYPE"]) unless body[:metadata].nil? || body[:metadata].is_a?(Hash)
        end
        server_only_keys = %i[refill_amount refill_interval rate_limit_max rate_limit_time_window rate_limit_enabled remaining permissions]
        if client && server_only_keys.any? { |key| (create && key == :remaining) ? !body[:remaining].nil? : body.key?(key) }
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"])
        end
        amount_present = body.key?(:refill_amount)
        interval_present = body.key?(:refill_interval)
        if amount_present && !interval_present
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["REFILL_AMOUNT_AND_INTERVAL_REQUIRED"])
        end
        if interval_present && !amount_present
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["REFILL_INTERVAL_AND_AMOUNT_REQUIRED"])
        end
        if body.key?(:expires_in)
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_DISABLED_EXPIRATION"]) if config[:key_expiration][:disable_custom_expires_time]
          return if body[:expires_in].nil?

          days = body[:expires_in].to_f / 86_400
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_SMALL"]) if days < config[:key_expiration][:min_expires_in].to_f
          raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_LARGE"]) if days > config[:key_expiration][:max_expires_in].to_f
        end
      end

      def update_payload(body, config)
        update = {}
        update[:name] = body[:name] if body.key?(:name)
        update[:enabled] = body[:enabled] unless body[:enabled].nil?
        update[:remaining] = body[:remaining] if body.key?(:remaining)
        update[:refillAmount] = body[:refill_amount] if body.key?(:refill_amount)
        update[:refillInterval] = body[:refill_interval] if body.key?(:refill_interval)
        update[:rateLimitEnabled] = body[:rate_limit_enabled] if body.key?(:rate_limit_enabled)
        update[:rateLimitTimeWindow] = body[:rate_limit_time_window] if body.key?(:rate_limit_time_window)
        update[:rateLimitMax] = body[:rate_limit_max] if body.key?(:rate_limit_max)
        update[:expiresAt] = body[:expires_in].nil? ? nil : Time.now + body[:expires_in].to_i if body.key?(:expires_in)
        update[:metadata] = BetterAuth::APIKey::Utils.encode_json(body[:metadata]) if body.key?(:metadata) && config[:enable_metadata]
        update[:permissions] = BetterAuth::APIKey::Utils.encode_json(body[:permissions]) if body.key?(:permissions)
        update
      end

      def validate_api_key!(ctx, key, config, permissions: nil)
        hashed = BetterAuth::APIKey::Keys.hash(key, config)
        usage_lock_for(hashed).synchronize do
          record = BetterAuth::APIKey::Adapter.find_by_hash(ctx, hashed, config)
          raise BetterAuth::APIError.new("UNAUTHORIZED", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"]) unless record
          unless BetterAuth::APIKey::Routes.config_id_matches?(BetterAuth::APIKey::Types.record_config_id(record), config[:config_id])
            raise BetterAuth::APIError.new("UNAUTHORIZED", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"])
          end
          raise BetterAuth::APIError.new("UNAUTHORIZED", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_DISABLED"]) if record["enabled"] == false
          if record["expiresAt"] && record["expiresAt"] <= Time.now
            BetterAuth::APIKey::Adapter.schedule_record_delete(ctx, record, config)
            raise BetterAuth::APIError.new("UNAUTHORIZED", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_EXPIRED"])
          end
          if record["remaining"].to_i <= 0 && !record["remaining"].nil? && record["refillAmount"].nil?
            BetterAuth::APIKey::Adapter.schedule_record_delete(ctx, record, config)
            raise BetterAuth::APIError.new("TOO_MANY_REQUESTS", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["USAGE_EXCEEDED"])
          end

          check_permissions!(record, permissions)
          update = usage_update(record, config)
          updated = BetterAuth::APIKey::Adapter.update_record(ctx, record, update, config, defer: false)
          unless updated
            raise BetterAuth::APIError.new(
              "INTERNAL_SERVER_ERROR",
              message: BetterAuth::Plugins::API_KEY_ERROR_CODES["FAILED_TO_UPDATE_API_KEY"],
              code: "FAILED_TO_UPDATE_API_KEY"
            )
          end
          BetterAuth::APIKey::Adapter.migrate_legacy_metadata(ctx, updated || record.merge(update.transform_keys { |key_name| BetterAuth::Schema.storage_key(key_name) }), config)
        end
      end

      def usage_update(record, config)
        now = Time.now
        update = {lastRequest: now, updatedAt: now}

        if (try_again_in = BetterAuth::APIKey::RateLimit.try_again_in(record, config, now))
          raise BetterAuth::APIError.new(
            "UNAUTHORIZED",
            message: BetterAuth::Plugins::API_KEY_ERROR_CODES["RATE_LIMIT_EXCEEDED"],
            code: "RATE_LIMITED",
            body: {
              message: BetterAuth::Plugins::API_KEY_ERROR_CODES["RATE_LIMIT_EXCEEDED"],
              code: "RATE_LIMITED",
              details: {tryAgainIn: try_again_in}
            }
          )
        end
        update[:requestCount] = BetterAuth::APIKey::RateLimit.next_request_count(record, now) if BetterAuth::APIKey::RateLimit.counts_requests?(record, config)

        remaining = record["remaining"]
        if !remaining.nil?
          if remaining.to_i <= 0 && record["refillAmount"] && record["refillInterval"]
            last_refill = BetterAuth::APIKey::Utils.normalize_time(record["lastRefillAt"] || record["createdAt"])
            if !last_refill || ((now - last_refill) * 1000) > record["refillInterval"].to_i
              remaining = record["refillAmount"].to_i
              update[:lastRefillAt] = now
            end
          end
          raise BetterAuth::APIError.new("TOO_MANY_REQUESTS", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["USAGE_EXCEEDED"]) if remaining.to_i <= 0

          update[:remaining] = remaining.to_i - 1
        end
        update
      end

      def check_permissions!(record, required)
        return if required.nil? || required == {}

        BetterAuth::Plugins.load_plugin!(:access)
        actual = BetterAuth::APIKey::Utils.decode_json(record["permissions"]) || {}
        result = BetterAuth::Plugins::Role.new(actual).authorize(required)
        unless result[:success]
          raise BetterAuth::APIError.new("UNAUTHORIZED", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], code: "KEY_NOT_FOUND")
        end
      end
    end
  end
end

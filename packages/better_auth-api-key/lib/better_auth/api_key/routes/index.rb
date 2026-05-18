# frozen_string_literal: true

module BetterAuth
  module APIKey
    module Routes
      ROUTE_NAMES = %i[
        create_api_key
        verify_api_key
        get_api_key
        update_api_key
        delete_api_key
        list_api_keys
        delete_all_expired_api_keys
      ].freeze

      module_function

      def resolve_config(context, config, config_id = nil)
        configurations = config.fetch(:configurations, [config])
        return configurations.find { |entry| default_config_id?(entry[:config_id]) } || configurations.first if config_id.to_s.empty?

        configurations.find { |entry| entry[:config_id].to_s == config_id.to_s } ||
          begin
            default = configurations.find { |entry| default_config_id?(entry[:config_id]) }
            unless default
              context.logger.error(BetterAuth::Plugins::API_KEY_ERROR_CODES["NO_DEFAULT_API_KEY_CONFIGURATION_FOUND"]) if context.respond_to?(:logger) && context.logger.respond_to?(:error)
              raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Plugins::API_KEY_ERROR_CODES["NO_DEFAULT_API_KEY_CONFIGURATION_FOUND"])
            end
            default
          end
      end

      def default_config_id?(value)
        value.nil? || value.to_s.empty? || value.to_s == "default"
      end

      def config_id_matches?(record_config_id, expected_config_id)
        return true if default_config_id?(record_config_id) && default_config_id?(expected_config_id)

        record_config_id.to_s == expected_config_id.to_s
      end

      @last_expired_check = nil

      def delete_expired(context, config, bypass_last_check: false, raise_on_error: false)
        return unless config[:storage] == "database" || config[:fallback_to_database]
        unless bypass_last_check
          now = Time.now
          return if @last_expired_check && ((now - @last_expired_check) * 1000) < 10_000

          @last_expired_check = now
        end

        now = Time.now
        context.adapter.delete_many(
          model: BetterAuth::Plugins::API_KEY_TABLE_NAME,
          where: [
            {field: "expiresAt", value: now, operator: "lt"},
            {field: "expiresAt", value: nil, operator: "ne"}
          ]
        )
      rescue => error
        context.logger.error("[API KEY PLUGIN] Failed to delete expired API keys: #{error.message}") if context.respond_to?(:logger) && context.logger.respond_to?(:error)
        raise if raise_on_error
      end

      def schedule_cleanup(ctx, config)
        task = -> { delete_expired(ctx.context, config) }
        if config[:defer_updates] && BetterAuth::APIKey::Utils.background_tasks?(ctx)
          BetterAuth::APIKey::Utils.run_background_task(ctx, "Deferred API key cleanup", task)
        else
          task.call
        end
      end
    end
  end
end

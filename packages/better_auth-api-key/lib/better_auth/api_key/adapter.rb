# frozen_string_literal: true

require "json"
require "securerandom"
require "time"

module BetterAuth
  module APIKey
    module Adapter
      HASH_STORAGE_PREFIX = "api-key:"
      ID_STORAGE_PREFIX = "api-key:by-id:"
      REFERENCE_STORAGE_PREFIX = "api-key:by-ref:"

      module_function

      def storage_key_by_hash(hashed_key)
        "#{HASH_STORAGE_PREFIX}#{hashed_key}"
      end

      def storage_key_by_id(id)
        "#{ID_STORAGE_PREFIX}#{id}"
      end

      def storage_key_by_reference(reference_id)
        "#{REFERENCE_STORAGE_PREFIX}#{reference_id}"
      end

      def store(ctx, data, config)
        record = nil
        if config[:storage] == "database" || config[:fallback_to_database]
          record = ctx.context.adapter.create(model: BetterAuth::Plugins::API_KEY_TABLE_NAME, data: data)
        end
        record ||= data.transform_keys { |key| BetterAuth::Schema.storage_key(key) }.merge("id" => SecureRandom.hex(16))
        set(ctx, record, config) if config[:storage] == "secondary-storage"
        record
      end

      def find_by_hash(ctx, hashed, config)
        if config[:storage] == "secondary-storage"
          record = get(ctx, storage_key_by_hash(hashed), config) || get(ctx, "api-key:key:#{hashed}", config)
          return record if record
          return nil unless config[:fallback_to_database]
        end
        record = ctx.context.adapter.find_one(model: BetterAuth::Plugins::API_KEY_TABLE_NAME, where: [{field: "key", value: hashed}])
        set(ctx, record, config) if record && config[:storage] == "secondary-storage" && config[:fallback_to_database]
        record
      end

      def find_by_id(ctx, id, config)
        if config[:storage] == "secondary-storage"
          record = get(ctx, storage_key_by_id(id), config) || get(ctx, "api-key:id:#{id}", config)
          return record if record
          return nil unless config[:fallback_to_database]
        end
        record = ctx.context.adapter.find_one(model: BetterAuth::Plugins::API_KEY_TABLE_NAME, where: [{field: "id", value: id}])
        set(ctx, record, config) if record && config[:storage] == "secondary-storage" && config[:fallback_to_database]
        record
      end

      def list_for_reference(ctx, reference_id, config)
        if config[:storage] == "secondary-storage"
          begin
            storage_instance = storage(config, ctx.context)
            raw_ids = storage_instance&.get(storage_key_by_reference(reference_id)) || storage_instance&.get("api-key:user:#{reference_id}")
            ids = parse_id_list!(raw_ids)
            records = ids.filter_map { |id| find_by_id(ctx, id, config) }
            return records unless records.empty? && config[:fallback_to_database]
          rescue JSON::ParserError, NoMethodError => error
            if ctx.context.respond_to?(:logger) && ctx.context.logger.respond_to?(:warn)
              ctx.context.logger.warn("[API KEY PLUGIN] Corrupt api-key reference index for #{reference_id.inspect}: #{error.class}: #{error.message}")
            end
            return [] unless config[:fallback_to_database]
          end
        end
        records = ctx.context.adapter.find_many(model: BetterAuth::Plugins::API_KEY_TABLE_NAME, where: [{field: "referenceId", value: reference_id}])
        legacy = ctx.context.adapter.find_many(model: BetterAuth::Plugins::API_KEY_TABLE_NAME, where: [{field: "userId", value: reference_id}])
        combined = (records + legacy).uniq { |record| record["id"] }
        populate_reference(ctx, reference_id, combined, config) if config[:storage] == "secondary-storage" && config[:fallback_to_database]
        combined
      end

      def update_record(ctx, record, update, config, defer: false)
        performer = lambda do
          updated = nil
          if config[:storage] == "database" || config[:fallback_to_database]
            updated = ctx.context.adapter.update(model: BetterAuth::Plugins::API_KEY_TABLE_NAME, where: [{field: "id", value: record["id"]}], update: update)
            return nil unless updated
          else
            updated = record.merge(update.transform_keys { |key| BetterAuth::Schema.storage_key(key) })
          end
          set(ctx, updated, config) if config[:storage] == "secondary-storage"
          updated
        end

        if defer && config[:defer_updates] && BetterAuth::Plugins.api_key_background_tasks?(ctx)
          scheduled = record.merge(update.transform_keys { |key| BetterAuth::Schema.storage_key(key) })
          BetterAuth::APIKey::Utils.run_background_task(ctx, "Deferred API key update", performer)
          scheduled
        else
          performer.call
        end
      end

      def delete_record(ctx, record, config)
        ctx.context.adapter.delete(model: BetterAuth::Plugins::API_KEY_TABLE_NAME, where: [{field: "id", value: record["id"]}]) if config[:storage] == "database" || config[:fallback_to_database]
        delete(ctx, record, config) if config[:storage] == "secondary-storage"
      end

      def schedule_record_delete(ctx, record, config)
        task = -> { delete_record(ctx, record, config) }
        if config[:defer_updates] && BetterAuth::APIKey::Utils.background_tasks?(ctx)
          BetterAuth::APIKey::Utils.run_background_task(ctx, "Deferred API key delete", task)
        else
          task.call
        end
      end

      def migrate_legacy_metadata(ctx, record, config)
        parsed = BetterAuth::APIKey::Utils.decode_json(record["metadata"])
        return record unless parsed.is_a?(Hash)

        encoded = BetterAuth::APIKey::Utils.encode_json(parsed)
        return record.merge("metadata" => encoded) if record["metadata"] == encoded

        updated = record.merge("metadata" => encoded)
        if config[:storage] == "database" || config[:fallback_to_database]
          ctx.context.adapter.update(model: BetterAuth::Plugins::API_KEY_TABLE_NAME, where: [{field: "id", value: record["id"]}], update: {metadata: encoded})
        end
        set(ctx, updated, config) if config[:storage] == "secondary-storage"
        updated
      end

      def legacy_metadata_migration_needed?(record)
        parsed = BetterAuth::APIKey::Utils.decode_json(record["metadata"])
        parsed.is_a?(Hash) && BetterAuth::APIKey::Utils.encode_json(parsed) != record["metadata"]
      end

      def storage(config, context = nil)
        config[:custom_storage] || context&.options&.secondary_storage
      end

      def get(ctx, key, config)
        raw = storage(config, ctx.context)&.get(key)
        raw && deserialize_record(JSON.parse(raw))
      rescue JSON::ParserError
        nil
      end

      def set(ctx, record, config)
        storage_instance = storage(config, ctx.context)
        unless storage_instance
          raise BetterAuth::APIError.new("INTERNAL_SERVER_ERROR", message: "Secondary storage is required when storage mode is 'secondary-storage'")
        end

        serialized = JSON.generate(storage_record(record))
        expires_at = BetterAuth::APIKey::Utils.normalize_time(record["expiresAt"])
        ttl = expires_at ? [(expires_at - Time.now).to_i, 0].max : nil
        reference_id = BetterAuth::Plugins.api_key_record_reference_id(record)
        reference_key = storage_key_by_reference(reference_id)

        batch(storage_instance) do
          operations = [
            -> { storage_instance.set(storage_key_by_hash(record["key"]), serialized, ttl) },
            -> { storage_instance.set(storage_key_by_id(record["id"]), serialized, ttl) }
          ]
          operations << if config[:fallback_to_database]
            -> { storage_instance.delete(reference_key) }
          else
            -> { ref_list_add(storage_instance, reference_key, record["id"]) }
          end
          operations.each(&:call)
        end
      end

      def delete(ctx, record, config)
        storage_instance = storage(config, ctx.context)
        return unless storage_instance

        reference_id = BetterAuth::Plugins.api_key_record_reference_id(record)
        reference_key = storage_key_by_reference(reference_id)

        batch(storage_instance) do
          operations = [
            -> { storage_instance.delete(storage_key_by_hash(record["key"])) },
            -> { storage_instance.delete(storage_key_by_id(record["id"])) },
            # Ruby-only legacy storage layout cleanup; upstream never wrote here.
            -> { storage_instance.delete("api-key:key:#{record["key"]}") },
            -> { storage_instance.delete("api-key:id:#{record["id"]}") }
          ]
          operations << if config[:fallback_to_database]
            -> { storage_instance.delete(reference_key) }
          else
            -> { ref_list_remove(storage_instance, reference_key, record["id"]) }
          end
          operations.each(&:call)
        end
      end

      def ref_list_add(storage_instance, reference_key, id)
        ids = safe_parse_id_list(storage_instance.get(reference_key))
        ids << id unless ids.include?(id)
        storage_instance.set(reference_key, JSON.generate(ids))
      end

      def ref_list_remove(storage_instance, reference_key, id)
        ids = safe_parse_id_list(storage_instance.get(reference_key)).reject { |existing| existing == id }
        ids.empty? ? storage_instance.delete(reference_key) : storage_instance.set(reference_key, JSON.generate(ids))
      end

      def safe_parse_id_list(raw)
        return [] if raw.nil?
        return raw.dup if raw.is_a?(Array)

        parse_id_list!(raw)
      rescue JSON::ParserError
        []
      end

      def parse_id_list!(raw)
        return [] if raw.nil?
        return raw.dup if raw.is_a?(Array)

        parsed = JSON.parse(raw.to_s)
        parsed.is_a?(Array) ? parsed : []
      end

      def batch(storage_instance, &block)
        if storage_instance.respond_to?(:batch)
          storage_instance.batch(&block)
        else
          block.call
        end
      end

      def populate_reference(ctx, reference_id, records, config)
        storage_instance = storage(config, ctx.context)
        return unless storage_instance

        batch(storage_instance) do
          ids = []
          records.each do |record|
            serialized = JSON.generate(storage_record(record))
            expires_at = BetterAuth::APIKey::Utils.normalize_time(record["expiresAt"])
            ttl = expires_at ? [(expires_at - Time.now).to_i, 0].max : nil
            storage_instance.set(storage_key_by_hash(record["key"]), serialized, ttl)
            storage_instance.set(storage_key_by_id(record["id"]), serialized, ttl)
            ids << record["id"]
          end
          reference_key = storage_key_by_reference(reference_id)
          ids.empty? ? storage_instance.delete(reference_key) : storage_instance.set(reference_key, JSON.generate(ids))
        end
      end

      def batch_migrate_legacy_metadata(ctx, records, config)
        return records unless config[:storage] == "database" || config[:fallback_to_database]

        records.map { |record| migrate_legacy_metadata(ctx, record, config) }
      end

      def storage_record(record)
        record.transform_values { |value| value.is_a?(Time) ? value.iso8601 : value }
      end

      def deserialize_record(record)
        %w[createdAt updatedAt expiresAt lastRefillAt lastRequest].each do |field|
          record[field] = BetterAuth::APIKey::Utils.normalize_time(record[field]) if record[field]
        end
        record
      end
    end
  end
end

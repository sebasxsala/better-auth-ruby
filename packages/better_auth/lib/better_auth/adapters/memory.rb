# frozen_string_literal: true

require "securerandom"
require "time"

module BetterAuth
  module Adapters
    class Memory < Base
      attr_reader :db

      def initialize(options, db = nil)
        super(options)
        @db = db || build_db
      end

      def create(model:, data:, force_allow_id: false)
        model = model.to_s
        table_for(model) << transform_input(model, data, "create", force_allow_id)
        table_for(model).last
      end

      def find_one(model:, where: [], select: nil, join: nil)
        find_many(model: model, where: where, select: select, join: join, limit: 1).first
      end

      def find_many(model:, where: [], sort_by: nil, limit: nil, offset: nil, select: nil, join: nil)
        model = model.to_s
        records = table_for(model).select { |record| matches_where?(record, where || []) }.map(&:dup)
        records = records.map { |record| apply_join(model, record, join) } if join
        records = sort_records(model, records, sort_by) if sort_by
        records = records.drop(offset.to_i) if offset
        records = records.first(limit.to_i) if limit
        records = records.map { |record| select_fields(model, record, select) } if select && !select.empty?
        records
      end

      def update(model:, where:, update:)
        model = model.to_s
        ensure_update_input_has_fields!(model, update)
        records = table_for(model).select { |record| matches_where?(record, where || []) }
        data = transform_input(model, update, "update", true)
        ensure_update_data!(data)
        records.each { |record| record.merge!(data) }
        records.first
      end

      def update_many(model:, where:, update:)
        model = model.to_s
        ensure_update_input_has_fields!(model, update)
        records = table_for(model).select { |record| matches_where?(record, where || []) }
        data = transform_input(model, update, "update", true)
        ensure_update_data!(data)
        records.each { |record| record.merge!(data) }
        records.length
      end

      def delete(model:, where:)
        delete_many(model: model, where: where)
        nil
      end

      def delete_many(model:, where:)
        table = table_for(model)
        matches = table.select { |record| matches_where?(record, where || []) }
        @db[model.to_s] = table.reject { |record| matches.include?(record) }
        matches.length
      end

      def count(model:, where: nil)
        find_many(model: model, where: where || []).length
      end

      def transaction
        snapshot = Marshal.load(Marshal.dump(db))
        yield self
      rescue
        @db = snapshot
        raise
      end

      private

      def build_db
        Schema.auth_tables(options).keys.to_h { |model| [model, []] }
      end

      def table_for(model)
        db[model.to_s] ||= []
      end

      def transform_input(model, data, action, force_allow_id)
        fields = Schema.auth_tables(options).fetch(model).fetch(:fields)
        input = stringify_keys(data)
        output = {}

        fields.each do |field, attributes|
          next if field == "id" && input.key?(field) && !force_allow_id

          value_provided = input.key?(field)
          value = input[field]

          if value_provided && attributes[:input] == false && value && !force_allow_id
            raise APIError.new("BAD_REQUEST", message: "#{field} is not allowed to be set")
          end

          if !value_provided && action == "create" && attributes.key?(:default_value)
            value = resolve_default(attributes[:default_value])
            value_provided = true
          elsif !value_provided && action == "update" && attributes[:on_update]
            value = resolve_default(attributes[:on_update])
            value_provided = true
          end

          if !value_provided && action == "create" && attributes[:required]
            raise APIError.new("BAD_REQUEST", message: "#{field} is required") unless field == "id"
          end

          output[field] = coerce_value(value, attributes) if value_provided
        end

        output["id"] = generated_id if action == "create" && !output.key?("id") && fields.key?("id")
        output
      end

      def ensure_update_data!(data)
        raise APIError.new("BAD_REQUEST", message: "No fields to update") if data.empty?
      end

      def ensure_update_input_has_fields!(model, update)
        raise APIError.new("BAD_REQUEST", message: "No fields to update") unless update.is_a?(Hash)

        fields = Schema.auth_tables(options).fetch(model).fetch(:fields)
        input = stringify_keys(update)
        has_updatable_field = input.any? do |field, _value|
          next false if field == "id" || field == "_id"

          fields.key?(field) || fields.any? { |logical_field, attributes| Schema.storage_key(attributes[:field_name] || logical_field) == field }
        end
        raise APIError.new("BAD_REQUEST", message: "No fields to update") unless has_updatable_field
      end

      def generated_id
        generator = options.advanced.dig(:database, :generate_id)
        return generator.call.to_s if generator.respond_to?(:call)
        return SecureRandom.uuid if generator == "uuid"

        SecureRandom.hex(16)
      end

      def resolve_default(default)
        default.respond_to?(:call) ? default.call : default
      end

      def coerce_value(value, attributes)
        return value if value.nil?
        return Time.parse(value) if attributes[:type] == "date" && value.is_a?(String)

        value
      end

      def matches_where?(record, where)
        clauses = Array(where)
        return true if clauses.empty?

        result = evaluate_clause(record, clauses.first)
        clauses.each do |clause|
          clause_result = evaluate_clause(record, clause)
          if fetch_key(clause, :connector).to_s.upcase == "OR"
            result ||= clause_result
          else
            result &&= clause_result
          end
        end
        result
      end

      def evaluate_clause(record, clause)
        field = Schema.storage_key(fetch_key(clause, :field))
        value = fetch_key(clause, :value)
        operator = (fetch_key(clause, :operator) || "eq").to_s
        current = record[field]
        comparable = coerce_where_value(record, field, value, operator)

        case operator
        when "in"
          Array(comparable).include?(current)
        when "not_in"
          !Array(comparable).include?(current)
        when "contains"
          current.to_s.include?(comparable.to_s)
        when "starts_with"
          current.to_s.start_with?(comparable.to_s)
        when "ends_with"
          current.to_s.end_with?(comparable.to_s)
        when "ne"
          current != comparable
        when "gt"
          !current.nil? && !comparable.nil? && current > comparable
        when "gte"
          !current.nil? && !comparable.nil? && current >= comparable
        when "lt"
          !current.nil? && !comparable.nil? && current < comparable
        when "lte"
          !current.nil? && !comparable.nil? && current <= comparable
        else
          current == comparable
        end
      end

      def coerce_where_value(record, field, value, operator)
        attributes = schema_for_record_field(record, field)
        return value unless attributes
        return Array(value).map { |entry| coerce_scalar_where_value(entry, attributes) } if %w[in not_in].include?(operator)

        coerce_scalar_where_value(value, attributes)
      end

      def schema_for_record_field(record, field)
        db.each_key do |model|
          fields = Schema.auth_tables(options)[model]&.fetch(:fields, nil)
          next unless fields&.key?(field)
          return fields[field] if table_for(model).include?(record)
        end
        nil
      end

      def coerce_scalar_where_value(value, attributes)
        return value if value.nil?

        case attributes[:type]
        when "boolean"
          return false if value == false || value == 0 || value.to_s.downcase == "false" || value.to_s == "0"
          return true if value == true || value == 1 || value.to_s.downcase == "true" || value.to_s == "1"
        when "number"
          return coerce_number(value)
        when "date"
          return Time.parse(value) if value.is_a?(String)
        when "number[]"
          return Array(value).map { |entry| coerce_number(entry) }
        when "string[]"
          return Array(value).map(&:to_s)
        end

        value
      end

      def coerce_number(value)
        return value unless value.is_a?(String)
        return value.to_i if /\A-?\d+\z/.match?(value)
        return value.to_f if /\A-?\d+\.\d+\z/.match?(value)

        value
      end

      def sort_records(model, records, sort_by)
        field = Schema.storage_key(fetch_key(sort_by, :field))
        direction = fetch_key(sort_by, :direction).to_s
        records.sort_by { |record| sortable_value(record[field]) }.then do |sorted|
          if direction == "desc"
            sorted.reverse
          else
            sorted
          end
        end
      end

      def sortable_value(value)
        value.nil? ? "" : value
      end

      def select_fields(_model, record, select)
        fields = Array(select).map { |field| Schema.storage_key(field) }
        record.slice(*fields)
      end

      def apply_join(model, record, join)
        joined = record.dup
        join.each_key do |join_model|
          join_model = join_model.to_s
          joined[join_model] = case [model, join_model]
          when ["session", "user"], ["account", "user"]
            table_for("user").find { |user| user["id"] == record["userId"] }
          when ["user", "account"]
            table_for("account").select { |account| account["userId"] == record["id"] }
          end
        end
        joined
      end

      def stringify_keys(data)
        data.each_with_object({}) do |(key, value), result|
          result[Schema.storage_key(key)] = value
        end
      end

      def fetch_key(hash, key)
        [key, key.to_s, Schema.storage_key(key), Schema.storage_key(key).to_sym].each do |candidate|
          return hash[candidate] if hash.key?(candidate)
        end
        nil
      end
    end
  end
end

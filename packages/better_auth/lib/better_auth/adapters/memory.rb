# frozen_string_literal: true

require "securerandom"
require "time"

module BetterAuth
  module Adapters
    class Memory < Base
      include JoinSupport

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

          output[field] = coerce_value(value, field, attributes) if value_provided
        end

        output["id"] = generated_id(model) if action == "create" && (!output.key?("id") || output["id"].nil?)
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

      def generated_id(model)
        generator = options.advanced.dig(:database, :generate_id)
        return generator.call.to_s if generator.respond_to?(:call)
        return table_for(model).length + 1 if generator == "serial"
        return SecureRandom.uuid if generator == "uuid"

        SecureRandom.hex(16)
      end

      def resolve_default(default)
        default.respond_to?(:call) ? default.call : default
      end

      def coerce_value(value, field, attributes)
        return value if value.nil?
        return coerce_number(value) if serial_id_field?(field, attributes)
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
        mode = (fetch_key(clause, :mode) || "sensitive").to_s
        current = record[field]
        comparable = coerce_where_value(record, field, value, operator)
        current, comparable = insensitive_values(current, comparable) if insensitive_comparison?(mode, current, comparable)

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
        return Array(value).map { |entry| coerce_scalar_where_value(entry, field, attributes) } if %w[in not_in].include?(operator)

        coerce_scalar_where_value(value, field, attributes)
      end

      def schema_for_record_field(record, field)
        db.each_key do |model|
          fields = Schema.auth_tables(options)[model]&.fetch(:fields, nil)
          next unless fields&.key?(field)
          return fields[field] if table_for(model).include?(record)
        end
        nil
      end

      def coerce_scalar_where_value(value, field, attributes)
        return value if value.nil?
        return coerce_number(value) if serial_id_field?(field, attributes)

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

      def serial_id_field?(field, attributes)
        return false unless options.advanced.dig(:database, :generate_id) == "serial"
        return true if field.to_s == "id"

        reference = attributes[:references]
        return false unless reference

        (reference[:field] || reference["field"]).to_s == "id"
      end

      def insensitive_comparison?(mode, current, comparable)
        return false unless mode == "insensitive"

        current.is_a?(String) && (comparable.is_a?(String) || comparable.is_a?(Array))
      end

      def insensitive_values(current, comparable)
        normalized_current = current.downcase
        normalized_comparable = if comparable.is_a?(Array)
          comparable.map { |entry| entry.is_a?(String) ? entry.downcase : entry }
        else
          comparable.downcase
        end
        [normalized_current, normalized_comparable]
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
        normalized_join(model, join).each do |join_model, config|
          matches = table_for(join_model).select do |join_record|
            join_record[config.fetch(:to)] == record[config.fetch(:from)]
          end.map(&:dup)

          joined[join_model] = if one_to_one_join?(config)
            matches.first
          else
            matches.first(join_limit(config))
          end
        end
        joined
      end

      def one_to_one_join?(config)
        config[:relation] == "one-to-one" || config[:unique] == true
      end

      def join_limit(config)
        value = config[:limit]
        return 100 if value.nil?

        parsed = Integer(value)
        parsed.positive? ? parsed : 100
      rescue ArgumentError, TypeError
        100
      end

      def inferred_join_config(model, join_model)
        foreign_keys = schema_for(join_model).fetch(:fields).select do |_field, attributes|
          reference_model_matches?(attributes, model)
        end
        forward_join = true

        if foreign_keys.empty?
          foreign_keys = schema_for(model).fetch(:fields).select do |_field, attributes|
            reference_model_matches?(attributes, join_model)
          end
          forward_join = false
        end

        raise Error, "No foreign key found for model #{join_model} and base model #{model} while performing join operation." if foreign_keys.empty?
        raise Error, "Multiple foreign keys found for model #{join_model} and base model #{model} while performing join operation. Only one foreign key is supported." if foreign_keys.length > 1

        foreign_key, attributes = foreign_keys.first
        reference = attributes.fetch(:references)
        if forward_join
          unique = attributes[:unique] == true
          {from: reference.fetch(:field).to_s, to: foreign_key, relation: unique ? "one-to-one" : "one-to-many", unique: unique}
        else
          {from: foreign_key, to: reference.fetch(:field).to_s, relation: "one-to-one", unique: true}
        end
      end

      def schema_for(model)
        Schema.auth_tables(options).fetch(model.to_s)
      end

      def reference_model_matches?(attributes, model)
        reference = attributes[:references]
        return false unless reference

        reference_model = reference[:model] || reference["model"]
        reference_model.to_s == model.to_s || reference_model.to_s == schema_for(model).fetch(:model_name)
      end

      def storage_key(field)
        Schema.storage_key(field)
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

# frozen_string_literal: true

require "securerandom"
require "json"
require "time"
require "sequel"

module BetterAuth
  module Hanami
    class SequelAdapter < BetterAuth::Adapters::Base
      include BetterAuth::Adapters::JoinSupport

      WHERE_OPERATORS = %w[eq ne gt gte lt lte in not_in contains starts_with ends_with].freeze

      attr_reader :connection

      def self.from_hanami(options, container: nil, allow_memory_fallback: false)
        if container.nil? && defined?(::Hanami) && ::Hanami.respond_to?(:app)
          container = ::Hanami.app
        end
        return memory_fallback(options, allow_memory_fallback: allow_memory_fallback) unless container

        from_container(container, options, allow_memory_fallback: allow_memory_fallback)
      end

      def self.from_container(container, options, allow_memory_fallback: false)
        gateway = if container.respond_to?(:key?) && container.key?("db.gateway")
          container["db.gateway"]
        elsif container.respond_to?(:[]) && safe_fetch(container, "db.gateway")
          container["db.gateway"]
        end
        return memory_fallback(options, allow_memory_fallback: allow_memory_fallback) unless gateway

        connection = gateway.respond_to?(:connection) ? gateway.connection : gateway
        new(options, connection: connection)
      end

      def self.safe_fetch(container, key)
        container[key]
      rescue KeyError
        nil
      end

      def self.memory_fallback(options, allow_memory_fallback: false)
        if options.respond_to?(:production?) && options.production? && !allow_memory_fallback
          raise Error, "Hanami db.gateway is required in production. Set config.allow_memory_fallback = true to use volatile memory storage intentionally."
        end

        Kernel.warn(
          "[better_auth-hanami] SequelAdapter: using BetterAuth::Adapters::Memory " \
          "(no Hanami container or db.gateway). Persisted auth data will not survive process restart."
        )
        BetterAuth::Adapters::Memory.new(options)
      end

      def initialize(options, connection:)
        super(options)
        @connection = connection
      end

      def create(model:, data:, force_allow_id: false)
        model = model.to_s
        input = transform_input(model, data, "create", force_allow_id)
        table_dataset(model).insert(physical_attributes(model, input))
        lookup = create_lookup(model, input)
        lookup ? find_one(model: model, where: [lookup]) : input
      end

      def find_one(model:, where: [], select: nil, join: nil)
        find_many(model: model, where: where, select: select, join: join, limit: 1).first
      end

      def find_many(model:, where: [], sort_by: nil, limit: nil, offset: nil, select: nil, join: nil)
        model = model.to_s
        dataset = table_dataset(model)
        dataset = apply_where(model, dataset, where || [])
        join_config = normalized_join(model, join)
        requested_select = select ? Array(select).map { |field| storage_key(field) } : nil
        effective_select = select_fields_for_join(requested_select, join_config)
        dataset = apply_select(model, dataset, effective_select) if effective_select
        dataset = apply_order(model, dataset, sort_by) if sort_by
        dataset = dataset.limit(coerce_pagination(limit, "limit")) if limit
        dataset = dataset.offset(coerce_pagination(offset, "offset")) if offset

        records = dataset.all.map { |row| normalize_record(model, row) }
        records = attach_joins(model, records, join_config)
        trim_unrequested_select_fields(records, requested_select, join_config) if requested_select
        records
      end

      def update(model:, where:, update:)
        model = model.to_s
        existing = find_one(model: model, where: where)
        return nil unless existing

        update_many(model: model, where: where, update: update)
        lookup = record_lookup(model, existing)
        lookup ? find_one(model: model, where: [lookup]) : find_one(model: model, where: where)
      end

      def update_many(model:, where:, update:, returning: false)
        model = model.to_s
        existing = returning ? find_many(model: model, where: where) : []
        attributes = physical_attributes(model, transform_input(model, update, "update", true))
        apply_where(model, table_dataset(model), where || []).update(attributes)
        return unless returning

        existing.map do |record|
          lookup = record_lookup(model, record)
          lookup ? find_one(model: model, where: [lookup]) : record
        end
      end

      def delete(model:, where:)
        delete_many(model: model, where: where)
        nil
      end

      def delete_many(model:, where:)
        model = model.to_s
        apply_where(model, table_dataset(model), where || []).delete
      end

      def count(model:, where: nil)
        model = model.to_s
        apply_where(model, table_dataset(model), where || []).count
      end

      def transaction
        connection.transaction { yield self }
      end

      private

      def table_dataset(model)
        connection[table_for(model).to_sym]
      end

      def apply_where(model, dataset, where)
        expression = Array(where).each_with_index.reduce(nil) do |combined, (clause, index)|
          current = where_expression(model, clause)
          next current if index.zero?

          connector = fetch_key(clause, :connector).to_s.upcase
          (connector == "OR") ? Sequel.|(combined, current) : Sequel.&(combined, current)
        end
        expression ? dataset.where(expression) : dataset
      end

      def where_expression(model, clause)
        field = storage_key(fetch_key(clause, :field))
        column = storage_field(model, field)
        identifier = Sequel[column.to_sym]
        operator = (fetch_key(clause, :operator) || "eq").to_s
        raise APIError.new("BAD_REQUEST", message: "Invalid operator #{operator}") unless WHERE_OPERATORS.include?(operator)

        mode = (fetch_key(clause, :mode) || "sensitive").to_s
        attributes = schema_for(model).fetch(:fields).fetch(field)
        raw_value = fetch_key(clause, :value)
        value = coerce_where_value(raw_value, attributes)
        insensitive = insensitive_string_mode?(mode, attributes)
        comparable = insensitive ? Sequel.function(:lower, identifier) : identifier
        compare_value = insensitive ? downcase_where_value(value) : value

        case operator
        when "in"
          values = Array(raw_value).map { |entry| coerce_where_value(entry, attributes) }
          values = downcase_where_value(values) if insensitive
          insensitive ? Sequel.expr(comparable => values) : {column.to_sym => values}
        when "not_in"
          values = Array(raw_value).map { |entry| coerce_where_value(entry, attributes) }
          values = downcase_where_value(values) if insensitive
          Sequel.~(insensitive ? Sequel.expr(comparable => values) : {column.to_sym => values})
        when "ne" then insensitive ? Sequel.~(Sequel.expr(comparable => compare_value)) : Sequel.~(column.to_sym => value)
        when "gt" then comparable > compare_value
        when "gte" then comparable >= compare_value
        when "lt" then comparable < compare_value
        when "lte" then comparable <= compare_value
        when "contains" then Sequel.like(comparable, "%#{escape_like(compare_value)}%", escape: "\\")
        when "starts_with" then Sequel.like(comparable, "#{escape_like(compare_value)}%", escape: "\\")
        when "ends_with" then Sequel.like(comparable, "%#{escape_like(compare_value)}", escape: "\\")
        else insensitive ? Sequel.expr(comparable => compare_value) : {column.to_sym => value}
        end
      end

      def apply_select(model, dataset, select)
        dataset.select(*Array(select).map { |field| storage_field(model, storage_key(field)).to_sym })
      end

      def apply_order(model, dataset, sort_by)
        column = storage_field(model, storage_key(fetch_key(sort_by, :field))).to_sym
        direction = (fetch_key(sort_by, :direction).to_s.downcase == "desc") ? Sequel.desc(column) : column
        dataset.order(direction)
      end

      def attach_joins(_model, records, join_config)
        return records if join_config.empty? || records.empty?

        records.each do |record|
          join_config.each do |join_model, config|
            record[join_model] = one_to_one_join?(config) ? nil : []
          end
        end
        join_config.each do |join_model, config|
          attach_join(model_records: records, join_model: join_model, config: config)
        end
        records
      end

      def attach_join(model_records:, join_model:, config:)
        values = model_records.map { |record| record[config.fetch(:from)] }.compact.uniq
        return if values.empty?

        joined = if one_to_one_join?(config)
          find_many(model: join_model, where: [{field: config.fetch(:to), operator: "in", value: values}])
        else
          values.flat_map do |value|
            find_many(model: join_model, where: [{field: config.fetch(:to), value: value}], limit: join_limit(config))
          end
        end
        grouped = joined.group_by { |record| record[config.fetch(:to)] }
        model_records.each do |record|
          records = grouped.fetch(record[config.fetch(:from)], [])
          record[join_model] = if one_to_one_join?(config)
            records.first
          else
            records.first(join_limit(config))
          end
        end
      end

      def joined_records(record, join_model, config)
        local_value = record[config.fetch(:from)]
        where = [{field: config.fetch(:to), value: local_value}]
        if one_to_one_join?(config)
          find_one(model: join_model, where: where)
        else
          records = find_many(model: join_model, where: where)
          records.first(join_limit(config))
        end
      end

      def one_to_one_join?(config)
        config[:relation] == "one-to-one" || config[:unique] == true
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
          {from: reference.fetch(:field).to_s, to: foreign_key, relation: unique ? "one-to-one" : "one-to-many", unique: unique, limit: unique ? 1 : default_find_many_limit}
        else
          {from: foreign_key, to: reference.fetch(:field).to_s, relation: "one-to-one", unique: true, limit: 1}
        end
      end

      def transform_input(model, data, action, force_allow_id)
        fields = schema_for(model).fetch(:fields)
        input = stringify_keys(data)
        output = {}

        fields.each do |field, attributes|
          next if field == "id" && input.key?(field) && !force_allow_id

          value_provided = input.key?(field)
          value = input[field]
          if value_provided && attributes[:input] == false && value && !force_allow_id
            raise APIError.new("BAD_REQUEST", message: "#{field} is not allowed to be set")
          end

          if action == "create" && attributes.key?(:default_value) && (!value_provided || (attributes[:required] && value.nil?))
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

      def create_lookup(model, input)
        fields = schema_for(model).fetch(:fields)
        return {field: "id", value: input.fetch("id")} if fields.key?("id") && input.key?("id")

        unique_field = fields.find { |field, attributes| attributes[:unique] && input.key?(field) }
        return {field: unique_field.first, value: input.fetch(unique_field.first)} if unique_field

        nil
      end

      def record_lookup(model, record)
        fields = schema_for(model).fetch(:fields)
        return {field: "id", value: record.fetch("id")} if fields.key?("id") && record.key?("id")

        unique_field = fields.find { |field, attributes| attributes[:unique] && record.key?(field) }
        return {field: unique_field.first, value: record.fetch(unique_field.first)} if unique_field

        nil
      end

      def physical_attributes(model, logical)
        logical.each_with_object({}) do |(field, value), attributes|
          attributes[storage_field(model, field).to_sym] = value
        end
      end

      def normalize_record(model, row)
        return nil unless row

        schema_for(model).fetch(:fields).each_with_object({}) do |(field, attributes), output|
          column = (attributes[:field_name] || physical_name(field)).to_sym
          output[field] = coerce_output_value(row[column], attributes) if row.key?(column)
        end
      end

      def table_for(model)
        schema_for(model).fetch(:model_name)
      end

      def schema_for(model)
        BetterAuth::Schema.auth_tables(options).fetch(model.to_s)
      rescue KeyError
        raise APIError.new("BAD_REQUEST", message: "Invalid model #{model}")
      end

      def storage_field(model, field)
        fields = schema_for(model).fetch(:fields)
        attributes = fields[field.to_s]
        raise APIError.new("BAD_REQUEST", message: "Invalid field #{field} for model #{model}") unless attributes

        attributes.fetch(:field_name, physical_name(field))
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
        return parse_time_value(value) if attributes[:type] == "date" && value.is_a?(String)
        return JSON.generate(value) if json_like?(attributes) && !value.is_a?(String)

        value
      end

      def coerce_output_value(value, attributes)
        return value if value.nil?
        return coerce_boolean(value) if attributes[:type] == "boolean"
        return Time.parse(value.to_s) if attributes[:type] == "date" && !value.is_a?(Time)
        return parse_json_value(value) if json_like?(attributes) && value.is_a?(String)

        value
      end

      def coerce_where_value(value, attributes)
        return value if value.nil?

        case attributes[:type]
        when "boolean"
          return coerce_value(false, attributes) if value == false || value == 0 || value.to_s.downcase == "false" || value.to_s == "0"
          return coerce_value(true, attributes) if value == true || value == 1 || value.to_s.downcase == "true" || value.to_s == "1"
        when "number"
          return coerce_number(value)
        when "date"
          return parse_time_value(value) if value.is_a?(String)
        end

        coerce_value(value, attributes)
      end

      def json_like?(attributes)
        %w[json string[] number[]].include?(attributes[:type])
      end

      def parse_json_value(value)
        JSON.parse(value)
      rescue JSON::ParserError
        value
      end

      def coerce_boolean(value)
        return value if value == true || value == false
        return false if value == 0 || value.to_s == "0" || value.to_s.downcase == "f" || value.to_s.downcase == "false"
        return true if value == 1 || value.to_s == "1" || value.to_s.downcase == "t" || value.to_s.downcase == "true"

        value
      end

      def coerce_number(value)
        return value unless value.is_a?(String)
        return value.to_i if /\A-?\d+\z/.match?(value)
        return value.to_f if /\A-?\d+\.\d+\z/.match?(value)

        value
      end

      def coerce_pagination(value, label)
        Integer(value).tap do |integer|
          raise ArgumentError if integer.negative?
        end
      rescue ArgumentError, TypeError
        raise APIError.new("BAD_REQUEST", message: "Invalid #{label}")
      end

      def select_fields_for_join(select, join_config)
        return select unless select && !join_config.empty?

        join_config.each_value.with_object(select.dup) do |config, fields|
          from = storage_key(config.fetch(:from))
          fields << from unless fields.include?(from)
        end
      end

      def trim_unrequested_select_fields(records, requested_select, join_config)
        hidden = join_config.each_value.map { |config| storage_key(config.fetch(:from)) } - requested_select
        records.each { |record| hidden.each { |field| record.delete(field) } }
      end

      def insensitive_string_mode?(mode, attributes)
        mode == "insensitive" && attributes[:type].to_s == "string"
      end

      def downcase_where_value(value)
        return value.map { |entry| downcase_where_value(entry) } if value.is_a?(Array)
        return value.downcase if value.is_a?(String)

        value
      end

      def default_find_many_limit
        database_options = options.advanced[:database] || {}
        coerce_pagination(
          database_options[:default_find_many_limit] || database_options[:defaultFindManyLimit] || 100,
          "limit"
        )
      end

      def join_limit(config)
        coerce_pagination(config[:limit] || default_find_many_limit, "limit")
      end

      def parse_time_value(value)
        Time.parse(value)
      rescue ArgumentError
        raise APIError.new("BAD_REQUEST", message: "Invalid date")
      end

      def escape_like(value)
        value.to_s.gsub(/[\\%_]/) { |match| "\\#{match}" }
      end

      def stringify_keys(data)
        data.each_with_object({}) do |(key, value), result|
          result[storage_key(key)] = value
        end
      end

      def fetch_key(hash, key)
        [key, key.to_s, storage_key(key), storage_key(key).to_sym].each do |candidate|
          return hash[candidate] if hash.key?(candidate)
        end
        nil
      end

      def storage_key(value)
        parts = physical_name(value).split("_")
        ([parts.first] + parts.drop(1).map(&:capitalize)).join
      end

      def physical_name(value)
        value.to_s
          .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
          .tr("-", "_")
          .downcase
      end
    end
  end
end

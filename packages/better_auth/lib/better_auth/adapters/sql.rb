# frozen_string_literal: true

require "securerandom"
require "json"
require "monitor"
require "time"

module BetterAuth
  module Adapters
    class SQL < Base
      include JoinSupport

      attr_reader :connection, :dialect

      def initialize(options, connection:, dialect:)
        super(options)
        @connection = connection
        @dialect = dialect.to_sym
        @connection_lock = Monitor.new
      end

      def create(model:, data:, force_allow_id: false)
        model = model.to_s
        input = transform_input(model, data, "create", force_allow_id)
        table = table_for(model)
        columns = input.keys.map { |field| storage_field(model, field) }
        params = input.keys.map { |field| input[field] }
        placeholders = params.each_index.map { |index| placeholder(index + 1) }
        returning = (dialect == :postgres) ? " RETURNING *" : ""
        sql = "INSERT INTO #{quote(table)} (#{columns.map { |column| quote(column) }.join(", ")}) VALUES (#{placeholders.join(", ")})#{returning}"
        rows = execute(sql, params)
        row = rows.first
        return normalize_record(model, row) if row

        lookup = create_lookup(model, input)
        lookup ? find_one(model: model, where: [lookup]) : input
      end

      def find_one(model:, where: [], select: nil, join: nil)
        if collection_join?(model.to_s, join)
          find_many(model: model, where: where, select: select, join: join).first
        else
          find_many(model: model, where: where, select: select, join: join, limit: 1).first
        end
      end

      def find_many(model:, where: [], sort_by: nil, limit: nil, offset: nil, select: nil, join: nil)
        model = model.to_s
        params = []
        sql = +"SELECT "
        sql << "TOP (#{Integer(limit)}) " if dialect == :mssql && limit && !offset
        sql << select_sql(model, select, join)
        sql << " FROM "
        sql << quote(table_for(model))
        sql << join_sql(model, join)
        where_sql = build_where(model, where || [], params)
        sql << " WHERE #{where_sql}" unless where_sql.empty?
        sql << order_sql(model, sort_by) if sort_by
        append_pagination_sql(sql, model, sort_by, limit, offset)

        records = execute(sql, params).map { |row| normalize_record(model, row, join: join) }
        collection_join?(model, join) ? aggregate_collection_joins(model, records, join) : records
      end

      def update(model:, where:, update:)
        model = model.to_s
        ensure_update_input_has_fields!(model, update)
        if dialect == :postgres
          records = update_many(model: model, where: where, update: update, returning: true)
          return records.is_a?(Array) ? records.first : records
        end

        existing = find_one(model: model, where: where)
        return nil unless existing

        update_many(model: model, where: where, update: update)
        lookup = record_lookup(model, existing)
        lookup ? find_one(model: model, where: [lookup]) : find_one(model: model, where: where)
      end

      def update_many(model:, where:, update:, returning: false)
        model = model.to_s
        ensure_update_input_has_fields!(model, update)
        data = transform_input(model, update, "update", true)
        ensure_update_data!(data)
        params = []
        assignments = data.each_key.map do |field|
          params << data[field]
          "#{quote(storage_field(model, field))} = #{placeholder(params.length)}"
        end
        where_sql = build_where(model, where || [], params)
        sql = +"UPDATE "
        sql << quote(table_for(model))
        sql << " SET "
        sql << assignments.join(", ")
        sql << " WHERE #{where_sql}" unless where_sql.empty?
        sql << " RETURNING *" if dialect == :postgres
        rows = execute(sql, params).map { |row| normalize_record(model, row) }
        return rows if returning || dialect == :postgres

        affected_rows(rows)
      end

      def delete(model:, where:)
        delete_many(model: model, where: where)
        nil
      end

      def delete_many(model:, where:)
        model = model.to_s
        params = []
        where_sql = build_where(model, where || [], params)
        sql = +"DELETE FROM "
        sql << quote(table_for(model))
        sql << " WHERE #{where_sql}" unless where_sql.empty?
        result = execute(sql, params)
        affected_rows(result)
      end

      def count(model:, where: nil)
        model = model.to_s
        params = []
        where_sql = build_where(model, where || [], params)
        sql = +"SELECT COUNT(*) AS count FROM "
        sql << quote(table_for(model))
        sql << " WHERE #{where_sql}" unless where_sql.empty?
        row = execute(sql, params).first || {}
        (row["count"] || row[:count] || 0).to_i
      end

      def transaction
        @connection_lock.synchronize do
          execute("BEGIN", [])
          result = yield self
          execute("COMMIT", [])
          result
        rescue
          execute("ROLLBACK", [])
          raise
        end
      end

      private

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

      def ensure_update_data!(data)
        raise APIError.new("BAD_REQUEST", message: "No fields to update") if data.empty?
      end

      def ensure_update_input_has_fields!(model, update)
        raise APIError.new("BAD_REQUEST", message: "No fields to update") unless update.is_a?(Hash)

        fields = schema_for(model).fetch(:fields)
        input = stringify_keys(update)
        has_updatable_field = input.any? do |field, _value|
          next false if field == "id" || field == "_id"

          fields.key?(field) || fields.any? { |logical_field, attributes| storage_key(attributes[:field_name] || logical_field) == field }
        end
        raise APIError.new("BAD_REQUEST", message: "No fields to update") unless has_updatable_field
      end

      def select_sql(model, select, join)
        fields = Array(select).empty? ? schema_for(model).fetch(:fields).keys : Array(select).map { |field| storage_key(field) }
        columns = fields.map do |field|
          column = storage_field(model, field)
          "#{quote(table_for(model))}.#{quote(column)} AS #{quote(column)}"
        end
        columns.concat(join_select_sql(model, join)) if join
        columns.join(", ")
      end

      def join_select_sql(model, join)
        normalized_join(model, join).flat_map do |join_model, _config|
          schema_for(join_model).fetch(:fields).map do |field, attributes|
            column = attributes[:field_name] || physical_name(field)
            "#{quote(join_model)}.#{quote(column)} AS #{quote("#{join_model}__#{column}")}"
          end
        end
      end

      def join_sql(model, join)
        return "" unless join

        normalized_join(model, join).map do |join_model, config|
          local_field = storage_field(model, config.fetch(:from))
          foreign_field = storage_field(join_model, config.fetch(:to))
          " LEFT JOIN #{quote(table_for(join_model))} AS #{quote(join_model)} ON #{quote(join_model)}.#{quote(foreign_field)} = #{quote(table_for(model))}.#{quote(local_field)}"
        end.join
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

      def build_where(model, where, params)
        Array(where).each_with_index.map do |clause, index|
          field = storage_key(fetch_key(clause, :field))
          column = "#{quote(table_for(model))}.#{quote(storage_field(model, field))}"
          operator = (fetch_key(clause, :operator) || "eq").to_s
          value = fetch_key(clause, :value)
          attributes = schema_for(model).fetch(:fields).fetch(field)
          insensitive = insensitive_string_predicate?(clause, attributes)
          predicate_column = insensitive ? "LOWER(#{column})" : column

          expression = case operator
          when "in", "not_in"
            values = Array(value).map { |entry| insensitive ? entry.to_s.downcase : coerce_where_value(entry, attributes) }
            placeholders = values.map do |entry|
              params << entry
              placeholder(params.length)
            end.join(", ")
            sql_operator = (operator == "not_in") ? "NOT IN" : "IN"
            "#{predicate_column} #{sql_operator} (#{placeholders})"
          when "contains", "starts_with", "ends_with"
            escaped = escape_like(insensitive ? value.to_s.downcase : value)
            pattern = case operator
            when "starts_with" then "#{escaped}%"
            when "ends_with" then "%#{escaped}"
            else "%#{escaped}%"
            end
            params << pattern
            "#{predicate_column} LIKE #{placeholder(params.length)} ESCAPE #{escape_literal}"
          else
            params << (insensitive ? value.to_s.downcase : coerce_where_value(value, attributes))
            "#{predicate_column} #{sql_operator(operator)} #{placeholder(params.length)}"
          end

          connector = (index.positive? && fetch_key(clause, :connector).to_s.upcase == "OR") ? "OR" : "AND"
          index.zero? ? expression : "#{connector} #{expression}"
        end.join(" ")
      end

      def order_sql(model, sort_by)
        field = Schema.storage_key(fetch_key(sort_by, :field))
        direction = (fetch_key(sort_by, :direction).to_s.downcase == "desc") ? "DESC" : "ASC"
        " ORDER BY #{quote(table_for(model))}.#{quote(storage_field(model, field))} #{direction}"
      end

      def append_pagination_sql(sql, model, sort_by, limit, offset)
        if dialect == :mssql
          return if limit && !offset
          return unless offset

          sql << order_sql(model, {field: "id", direction: "asc"}) unless sort_by
          sql << " OFFSET #{Integer(offset)} ROWS"
          sql << " FETCH NEXT #{Integer(limit)} ROWS ONLY" if limit
          return
        end

        sql << " LIMIT #{Integer(limit)}" if limit
        sql << " OFFSET #{Integer(offset)}" if offset
      end

      def sql_operator(operator)
        {
          "ne" => "!=",
          "gt" => ">",
          "gte" => ">=",
          "lt" => "<",
          "lte" => "<="
        }.fetch(operator, "=")
      end

      def insensitive_string_predicate?(clause, attributes)
        fetch_key(clause, :mode).to_s == "insensitive" && attributes[:type] == "string"
      end

      def execute(sql, params)
        @connection_lock.synchronize do
          if connection.respond_to?(:exec_params)
            result = connection.exec_params(sql, params)
            return result.to_a if result.respond_to?(:to_a)

            result
          elsif connection.respond_to?(:query) && params.empty?
            result = connection.query(sql)
            result.respond_to?(:to_a) ? result.to_a : result
          elsif dialect == :sqlite && connection.respond_to?(:execute)
            result = connection.execute(sql, params)
            result.respond_to?(:to_a) ? result.to_a : result
          elsif connection.respond_to?(:prepare)
            statement = connection.prepare(sql)
            result = nil
            begin
              result = statement.execute(*params)
              rows = result.respond_to?(:to_a) ? result.to_a : result
              rows
            ensure
              if result.respond_to?(:close)
                result.close
              elsif statement.respond_to?(:close)
                statement.close
              end
            end
          elsif connection.respond_to?(:execute)
            result = connection.execute(sql, params)
            result.respond_to?(:to_a) ? result.to_a : result
          else
            raise Error, "SQL connection must respond to exec_params or prepare"
          end
        end
      end

      def affected_rows(result)
        return result.cmd_tuples if result.respond_to?(:cmd_tuples)
        return result.affected_rows if result.respond_to?(:affected_rows)
        return connection.affected_rows if connection.respond_to?(:affected_rows)
        return connection.changes if connection.respond_to?(:changes)
        return result.to_i if result.respond_to?(:to_i)

        0
      end

      def normalize_record(model, row, join: nil)
        return nil unless row

        fields = schema_for(model).fetch(:fields)
        record = fields.each_with_object({}) do |(field, attributes), output|
          column = attributes[:field_name] || physical_name(field)
          output[field] = coerce_output_value(fetch_row(row, column), attributes) if row_key?(row, column)
        end

        normalized_join(model, join).each_key do |join_model|
          record[join_model] = normalize_joined_record(join_model, row)
        end

        record
      end

      def normalize_joined_record(model, row)
        schema_for(model).fetch(:fields).each_with_object({}) do |(field, attributes), output|
          column = attributes[:field_name] || physical_name(field)
          key = "#{model}__#{column}"
          output[field] = coerce_output_value(fetch_row(row, key), attributes) if row_key?(row, key)
        end
      end

      def aggregate_collection_joins(model, records, join)
        join_config = normalized_join(model, join)
        grouped = {}
        records.each do |record|
          key = record.fetch("id")
          grouped[key] ||= begin
            base = record.reject { |field, _value| join_config.key?(field) }
            join_defaults = join_config.each_with_object({}) do |(join_model, config), defaults|
              defaults[join_model] = (config[:relation] == "one-to-one" || config[:unique] == true) ? nil : []
            end
            base.merge(join_defaults)
          end

          join_config.each do |join_model, config|
            joined = record[join_model]
            next unless joined&.values&.any?

            if config[:relation] == "one-to-one" || config[:unique] == true
              grouped[key][join_model] = joined
            else
              grouped[key][join_model] << joined
            end
          end
        end
        grouped.values
      end

      def row_key?(row, key)
        row.key?(key) || row.key?(key.to_sym)
      end

      def fetch_row(row, key)
        return row[key] if row.key?(key)

        row[key.to_sym]
      end

      def table_for(model)
        schema_for(model).fetch(:model_name)
      end

      def schema_for(model)
        Schema.auth_tables(options).fetch(model.to_s)
      end

      def storage_field(model, field)
        schema_for(model).fetch(:fields).fetch(field.to_s).fetch(:field_name, physical_name(field))
      end

      def quote(identifier)
        Schema::SQL.quote(identifier, dialect)
      end

      def placeholder(index)
        (dialect == :postgres) ? "$#{index}" : "?"
      end

      def generated_id
        generator = options.advanced.dig(:database, :generate_id)
        return generator.call.to_s if generator.respond_to?(:call)
        return SecureRandom.uuid if generator == "uuid"

        SecureRandom.hex(16)
      end

      def escape_like(value)
        value.to_s.gsub(/[\\%_]/) { |match| "\\#{match}" }
      end

      def escape_literal
        (dialect == :postgres) ? "'\\\\'" : "'\\'"
      end

      def resolve_default(default)
        default.respond_to?(:call) ? default.call : default
      end

      def coerce_value(value, attributes)
        return value if value.nil?
        return value ? 1 : 0 if dialect == :sqlite && attributes[:type] == "boolean"
        return value.iso8601(6) if dialect == :sqlite && attributes[:type] == "date" && value.respond_to?(:iso8601)
        return Time.parse(value) if attributes[:type] == "date" && value.is_a?(String)
        return JSON.generate(value) if json_like?(attributes) && !value.is_a?(String)
        return value.encode(Encoding::UTF_8) if attributes[:type] == "string" && value.is_a?(String) && value.encoding == Encoding::ASCII_8BIT

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
          return Time.parse(value) if value.is_a?(String)
        end

        coerce_value(value, attributes)
      end

      def coerce_output_value(value, attributes)
        return value if value.nil?
        return coerce_boolean(value) if attributes[:type] == "boolean"
        return Time.parse(value) if attributes[:type] == "date" && value.is_a?(String)
        return parse_json_value(value) if json_like?(attributes) && value.is_a?(String)

        value
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

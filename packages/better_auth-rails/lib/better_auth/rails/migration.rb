# frozen_string_literal: true

require "better_auth/sql_migration"

module BetterAuth
  module Rails
    module Migration
      BOUNDED_STRING_LIMIT = 191

      module_function

      def render(options, migration_version: nil, dialect: nil)
        migration_version ||= self.migration_version
        dialect ||= active_record_connection ? active_record_dialect(active_record_connection) : :rails
        tables = BetterAuth::Schema.auth_tables(options)
        lines = [
          "# frozen_string_literal: true",
          "",
          "class CreateBetterAuthTables < ActiveRecord::Migration[#{migration_version}]",
          "  def change"
        ]
        tables.each_value { |table| lines.concat(create_table_lines(table, dialect: dialect)) }
        tables.each_value { |table| lines.concat(index_lines(table)) }
        tables.each_value { |table| lines.concat(foreign_key_lines(table, options)) }
        lines.concat(["  end", "end", ""])
        lines.join("\n")
      end

      def render_pending(plan, class_name: "UpdateBetterAuthTables", migration_version: nil)
        migration_version ||= self.migration_version
        created_tables = plan.to_create.map(&:table_name).to_set
        lines = [
          "# frozen_string_literal: true",
          "",
          "class #{class_name} < ActiveRecord::Migration[#{migration_version}]",
          "  def change"
        ]
        plan.to_create.each { |change| lines.concat(create_table_lines(change.table, dialect: plan.dialect)) }
        plan.to_create.each { |change| lines.concat(index_lines(change.table)) }
        plan.to_create.each { |change| lines.concat(foreign_key_lines(change.table, plan.tables)) }
        plan.to_add.each { |change| lines.concat(add_column_lines(change, dialect: plan.dialect)) }
        plan.to_index.reject { |change| created_tables.include?(change.table_name) }.each do |change|
          lines << index_line(change.table_name, change.field_name, unique: change.unique)
        end
        plan.to_add.each do |change|
          lines.concat(foreign_key_lines({model_name: change.table_name, fields: change.fields}, plan.tables))
        end
        lines.concat(["  end", "end", ""])
        lines.join("\n")
      end

      def plan_pending(options, connection: active_record_connection)
        dialect = active_record_dialect(connection)
        BetterAuth::SQLMigration.plan_from_existing(
          options,
          existing: current_schema(connection),
          dialect: dialect
        )
      end

      def active_record_connection
        ::ActiveRecord::Base.connection if defined?(::ActiveRecord::Base)
      rescue
        nil
      end

      def active_record_dialect(connection)
        adapter = connection.respond_to?(:adapter_name) ? connection.adapter_name.to_s.downcase : ""
        case adapter
        when /postgres/
          :postgres
        when /mysql/
          :mysql
        when /sqlite/
          :sqlite
        when /sqlserver|sql_server|mssql/
          :mssql
        else
          :postgres
        end
      end

      def current_schema(connection)
        connection.tables.each_with_object({}) do |table_name, schema|
          columns = connection.columns(table_name).each_with_object({}) do |column, result|
            result[column.name.to_s] = column.respond_to?(:sql_type) ? column.sql_type.to_s : column.type.to_s
          end
          indexes = {names: Set.new, columns: Set.new, unique_columns: Set.new}
          connection.indexes(table_name).each do |index|
            indexes[:names] << index.name.to_s
            Array(index.columns).each do |column|
              column = column.to_s
              indexes[:columns] << column
              indexes[:unique_columns] << column if index.unique
            end
          end
          schema[table_name.to_s] = {name: table_name.to_s, columns: columns, indexes: indexes}
        end
      end

      def migration_version
        return ::ActiveRecord::Migration.current_version if defined?(::ActiveRecord::Migration)

        "7.0"
      end

      def create_table_lines(table, dialect: :rails)
        table_name = table.fetch(:model_name)
        lines = ["", "    create_table :#{table_name}, #{primary_key_options(table, dialect: dialect)} do |t|"]
        table.fetch(:fields).each do |logical_field, attributes|
          next if logical_field == "id"

          lines << column_line(logical_field, attributes, dialect: dialect)
        end
        lines << "    end"
      end

      def primary_key_options(table, dialect: :rails)
        attributes = table.fetch(:fields)["id"]
        return "id: false" unless attributes

        column = attributes[:field_name] || physical_name("id")
        parts = ["id: :#{rails_type("id", attributes, dialect)}"]
        parts << "limit: #{BOUNDED_STRING_LIMIT}" if limited_string?("id", attributes)
        parts << "primary_key: :#{column}" unless column == "id"
        parts.join(", ")
      end

      def column_line(logical_field, attributes, dialect: :rails)
        column = attributes[:field_name] || physical_name(logical_field)
        type = rails_type(logical_field, attributes, dialect)
        parts = if type == "timestamptz"
          ["t.column :#{column}, :timestamptz"]
        else
          ["t.#{type} :#{column}"]
        end
        parts.concat(column_options(logical_field, attributes))
        "      #{parts.join(", ")}"
      end

      def column_options(logical_field, attributes)
        parts = []
        parts << "limit: #{BOUNDED_STRING_LIMIT}" if limited_string?(logical_field, attributes)
        parts << "null: false" if attributes[:required]
        default = default_value(attributes)
        parts << "default: #{default}" unless default.nil?
        parts
      end

      def index_lines(table)
        table_name = table.fetch(:model_name)
        table.fetch(:fields).filter_map do |logical_field, attributes|
          next unless attributes[:unique] || attributes[:index]

          column = attributes[:field_name] || physical_name(logical_field)
          index_line(table_name, column, unique: attributes[:unique])
        end
      end

      def add_column_lines(change, dialect: :rails)
        change.fields.map do |logical_field, attributes|
          column = attributes[:field_name] || physical_name(logical_field)
          parts = ["    add_column :#{change.table_name}, :#{column}, :#{rails_type(logical_field, attributes, dialect)}"]
          parts.concat(column_options(logical_field, attributes))
          parts.join(", ")
        end
      end

      def index_line(table_name, column, unique: false)
        unique_option = unique ? ", unique: true" : ""
        "    add_index :#{table_name}, :#{column}#{unique_option}"
      end

      def foreign_key_lines(table, options)
        table_name = table.fetch(:model_name)
        tables = table_map(options)
        table.fetch(:fields).filter_map do |logical_field, attributes|
          reference = attributes[:references]
          next unless reference

          column = attributes[:field_name] || physical_name(logical_field)
          target_table = foreign_key_target_table(reference, tables)
          target = target_table&.fetch(:model_name) || reference.fetch(:model)
          target_field = foreign_key_target_field(reference, target_table)
          primary_key = (target_field.to_s == "id") ? "" : ", primary_key: :#{target_field}"
          on_delete = reference[:on_delete] ? ", on_delete: :#{reference[:on_delete]}" : ""
          "    add_foreign_key :#{table_name}, :#{target}, column: :#{column}#{primary_key}#{on_delete}"
        end
      end

      def rails_type(logical_field, attributes, dialect = :rails)
        case attributes[:type]
        when "boolean" then "boolean"
        when "date" then (dialect == :postgres) ? "timestamptz" : "datetime"
        when "number" then attributes[:bigint] ? "bigint" : "integer"
        when "json", "string[]", "number[]" then (dialect == :postgres) ? "jsonb" : "json"
        when "string" then bounded_string?(logical_field, attributes) ? "string" : "text"
        else "text"
        end
      end

      def bounded_string?(logical_field, attributes)
        logical_field.to_s == "id" ||
          logical_field.to_s.end_with?("Id") ||
          attributes[:unique] ||
          attributes[:index] ||
          attributes[:sortable] ||
          attributes[:references] ||
          attributes.key?(:default_value)
      end

      def limited_string?(logical_field, attributes)
        attributes[:type] == "string" && bounded_string?(logical_field, attributes)
      end

      def default_value(attributes)
        default = attributes[:default_value]
        return if default.respond_to?(:call)

        case default
        when true then "true"
        when false then "false"
        when Numeric then default.to_s
        when String then default.inspect
        end
      end

      def physical_name(value)
        BetterAuth::Schema.send(:physical_name, value)
      end

      def table_map(options)
        if options.respond_to?(:values) && options.values.all? { |value| value.respond_to?(:fetch) && value.key?(:fields) }
          options
        else
          BetterAuth::Schema.auth_tables(options)
        end
      end

      def foreign_key_target_table(reference, tables)
        model = reference.fetch(:model).to_s
        tables.fetch(model, nil) || tables.each_value.find { |table| table.fetch(:model_name).to_s == model }
      end

      def foreign_key_target_field(reference, target_table)
        field = reference.fetch(:field).to_s
        return field unless target_table

        fields = target_table.fetch(:fields)
        attributes = fields.fetch(field, nil)
        return attributes[:field_name] || physical_name(field) if attributes

        if fields.each_value.any? { |data| data[:field_name].to_s == field }
          field
        else
          physical_name(field)
        end
      end
    end
  end
end

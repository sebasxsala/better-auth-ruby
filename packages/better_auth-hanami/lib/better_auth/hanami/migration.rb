# frozen_string_literal: true

require "better_auth/sql_migration"

module BetterAuth
  module Hanami
    module Migration
      module_function

      def render(options)
        tables = BetterAuth::Schema.auth_tables(options)
        lines = [
          "# frozen_string_literal: true",
          "",
          "require \"date\"",
          "require \"rom-sql\"",
          "",
          "ROM::SQL.migration do",
          "  change do"
        ]
        tables.each_value { |table| lines.concat(create_table_lines(table, options)) }
        lines.concat(["  end", "end", ""])
        lines.join("\n")
      end

      def render_pending(plan)
        created_tables = plan.to_create.map(&:table_name).to_set
        lines = [
          "# frozen_string_literal: true",
          "",
          "require \"date\"",
          "require \"rom-sql\"",
          "",
          "ROM::SQL.migration do",
          "  change do"
        ]
        plan.to_create.each { |change| lines.concat(create_table_lines(change.table, plan.tables)) }
        plan.to_add.each { |change| lines.concat(alter_table_lines(change)) }
        plan.to_index.reject { |change| created_tables.include?(change.table_name) }.each do |change|
          lines.concat(alter_table_index_lines(change))
        end
        lines.concat(["  end", "end", ""])
        lines.join("\n")
      end

      def plan_pending(options)
        config = BetterAuth::SQLMigration.configuration_for(options)
        if config.database == :memory
          raise BetterAuth::SQLMigration::UnsupportedAdapterError, "Better Auth Hanami incremental migrations require a Sequel connection"
        end
        if default_hanami_database?(config.database) && !(defined?(::Hanami) && ::Hanami.respond_to?(:app))
          raise BetterAuth::SQLMigration::UnsupportedAdapterError, "Better Auth Hanami incremental migrations require a Sequel connection"
        end
        auth = BetterAuth.auth(config.to_h)
        adapter = auth.context.adapter
        connection = adapter.connection if adapter.respond_to?(:connection)
        raise BetterAuth::SQLMigration::UnsupportedAdapterError, "Better Auth Hanami incremental migrations require a Sequel connection" unless connection

        BetterAuth::SQLMigration.plan_from_existing(
          config,
          existing: current_schema(connection),
          dialect: sequel_dialect(connection)
        )
      end

      def sequel_dialect(connection)
        type = connection.respond_to?(:database_type) ? connection.database_type.to_s : ""
        case type
        when /postgres/
          :postgres
        when /mysql/
          :mysql
        when /sqlite/
          :sqlite
        when /mssql|sqlserver|sql_server/
          :mssql
        else
          :postgres
        end
      end

      def current_schema(connection)
        connection.tables.each_with_object({}) do |table_name, schema|
          columns = connection.schema(table_name).each_with_object({}) do |entry, result|
            column, metadata = entry
            result[column.to_s] = (metadata[:db_type] || metadata[:type]).to_s
          end
          indexes = {names: Set.new, columns: Set.new, unique_columns: Set.new}
          connection.indexes(table_name).each do |name, metadata|
            indexes[:names] << name.to_s
            Array(metadata[:columns]).each do |column|
              column = column.to_s
              indexes[:columns] << column
              indexes[:unique_columns] << column if metadata[:unique]
            end
          end
          schema[table_name.to_s] = {name: table_name.to_s, columns: columns, indexes: indexes}
        end
      end

      def default_hanami_database?(database)
        return false unless database.respond_to?(:source_location)

        path, = database.source_location
        path.to_s.end_with?("better_auth/hanami/configuration.rb")
      end

      def create_table_lines(table, options)
        table_name = table.fetch(:model_name)
        lines = ["", "    create_table :#{table_name} do"]
        table.fetch(:fields).each do |logical_field, attributes|
          lines << column_line(logical_field, attributes, options)
        end
        lines << "      primary_key [:id]" if table.fetch(:fields).key?("id")
        table.fetch(:fields).each do |logical_field, attributes|
          index = index_line(logical_field, attributes)
          lines << index if index
        end
        lines << "    end"
        lines
      end

      def column_line(logical_field, attributes, options)
        column = attributes[:field_name] || physical_name(logical_field)
        reference = attributes[:references]
        if reference
          target = foreign_key_target(reference.fetch(:model), options)
          parts = ["foreign_key :#{column}, :#{target}", "type: #{hanami_type(attributes)}"]
          parts << "null: false" if attributes[:required]
          parts << "on_delete: :#{reference[:on_delete]}" if reference[:on_delete]
          return "      #{parts.join(", ")}"
        end

        parts = ["column :#{column}", hanami_type(attributes)]
        parts << "null: false" if attributes[:required]
        default = default_value(attributes)
        parts << "default: #{default}" unless default.nil?
        "      #{parts.join(", ")}"
      end

      def index_line(logical_field, attributes)
        return unless attributes[:unique] || attributes[:index]

        column = attributes[:field_name] || physical_name(logical_field)
        unique = attributes[:unique] ? ", unique: true" : ""
        "      index :#{column}#{unique}"
      end

      def alter_table_lines(change)
        lines = ["", "    alter_table :#{change.table_name} do"]
        change.fields.each do |logical_field, attributes|
          lines << add_column_line(logical_field, attributes)
        end
        lines << "    end"
        lines
      end

      def add_column_line(logical_field, attributes)
        column = attributes[:field_name] || physical_name(logical_field)
        parts = ["add_column :#{column}", hanami_type(attributes)]
        parts << "null: false" if attributes[:required]
        default = default_value(attributes)
        parts << "default: #{default}" unless default.nil?
        "      #{parts.join(", ")}"
      end

      def alter_table_index_lines(change)
        unique = change.unique ? ", unique: true" : ""
        [
          "",
          "    alter_table :#{change.table_name} do",
          "      add_index :#{change.field_name}#{unique}",
          "    end"
        ]
      end

      def hanami_type(attributes)
        case attributes[:type]
        when "boolean" then "TrueClass"
        when "date" then "DateTime"
        when "number" then attributes[:bigint] ? ":Bignum" : "Integer"
        when "json", "string[]", "number[]" then "JSON"
        else "String"
        end
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

      def foreign_key_target(model, options)
        tables = BetterAuth::Schema.auth_tables(options)
        tables.fetch(model.to_s, nil)&.fetch(:model_name) || model
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

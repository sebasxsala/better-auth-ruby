# frozen_string_literal: true

require "fileutils"
require "json"
require "time"
require "better_auth"
require "better_auth/sql_migration"

module BetterAuthExamples
  module DatabaseProviders
    module_function

    def adapter_for(name, options, root_path:)
      case name.to_s
      when "memory"
        BetterAuth::Adapters::Memory.new(options)
      when "sqlite"
        FileUtils.mkdir_p(File.join(root_path, "tmp"))
        BetterAuth::Adapters::SQLite.new(options, path: File.join(root_path, "tmp", "better_auth_example.sqlite3"))
      when "postgres"
        BetterAuth::Adapters::Postgres.new(options, url: ENV.fetch("BETTER_AUTH_EXAMPLE_POSTGRES_URL", "postgres://user:password@127.0.0.1:15432/better_auth"))
      when "mysql"
        BetterAuth::Adapters::MySQL.new(options, url: ENV.fetch("BETTER_AUTH_EXAMPLE_MYSQL_URL", "mysql2://user:password@127.0.0.1:13306/better_auth"))
      when "mssql"
        BetterAuth::Adapters::MSSQL.new(options, url: ENV.fetch("BETTER_AUTH_EXAMPLE_MSSQL_URL", "tinytds://sa:Password123!@127.0.0.1:11433/better_auth"))
      when "mongodb"
        require "mongo"
        require "better_auth/mongodb"

        client = Mongo::Client.new(ENV.fetch("BETTER_AUTH_EXAMPLE_MONGODB_URL", "mongodb://127.0.0.1:27018/better_auth?directConnection=true"))
        BetterAuth::Adapters::MongoDB.new(options, database: client.database, client: client, transaction: false, use_plural: true)
      else
        raise ArgumentError, "Unsupported database provider: #{name}"
      end
    end

    def prepare!(auth, root_path:)
      adapter = auth.context.adapter
      if sql_adapter?(adapter)
        migrations_path = File.join(root_path, "tmp", "better_auth_migrations", adapter.dialect.to_s)
        FileUtils.mkdir_p(migrations_path)
        migration_file = File.join(migrations_path, "00000000000000_create_better_auth_tables.sql")
        migration_sql = BetterAuth::SQLMigration.render(auth.options, dialect: adapter.dialect, generator: "better-auth-examples")
        File.write(migration_file, migration_sql)
        ensure_sql_schema!(auth)
      elsif adapter.respond_to?(:ensure_indexes!)
        adapter.ensure_indexes!
      end
      true
    end

    def explore(auth, table: nil, limit: 50, offset: 0)
      limit = normalized_page_limit(limit)
      offset = normalized_page_offset(offset)
      selected_table = table.to_s.empty? ? nil : table.to_s
      adapter = auth.context.adapter
      tables = if adapter.is_a?(BetterAuth::Adapters::Memory)
        explore_memory(auth, selected_table, limit, offset)
      elsif sql_adapter?(adapter)
        explore_sql(auth, selected_table, limit, offset)
      elsif mongodb_adapter?(adapter)
        explore_mongodb(auth, selected_table, limit, offset)
      else
        []
      end

      {provider: provider_name(adapter), tables: tables, limit: limit, offset: offset}
    end

    def delete_records!(auth, table_name, ids)
      adapter = auth.context.adapter
      ids = Array(ids).map(&:to_s).reject(&:empty?)
      return {deleted: 0} if ids.empty?

      if adapter.is_a?(BetterAuth::Adapters::Memory)
        delete_memory_records!(auth, table_name, ids)
      elsif sql_adapter?(adapter)
        delete_sql_records!(auth, table_name, ids)
      elsif mongodb_adapter?(adapter)
        delete_mongodb_records!(auth, table_name, ids)
      else
        {deleted: 0}
      end
    end

    def reset!(auth, root_path:)
      adapter = auth.context.adapter
      if adapter.is_a?(BetterAuth::Adapters::Memory)
        return true
      elsif sql_adapter?(adapter)
        drop_sql_tables(auth)
      elsif mongodb_adapter?(adapter)
        drop_mongodb_collections(auth)
      end

      prepare!(auth, root_path: root_path)
    end

    def sql_adapter?(adapter)
      adapter.respond_to?(:connection) && adapter.respond_to?(:dialect)
    end

    def mongodb_adapter?(adapter)
      defined?(BetterAuth::Adapters::MongoDB) && adapter.is_a?(BetterAuth::Adapters::MongoDB)
    end

    def provider_name(adapter)
      case adapter.class.name
      when "BetterAuth::Adapters::Memory" then "memory"
      when "BetterAuth::Adapters::SQLite" then "sqlite"
      when "BetterAuth::Adapters::Postgres" then "postgres"
      when "BetterAuth::Adapters::MySQL" then "mysql"
      when "BetterAuth::Adapters::MSSQL" then "mssql"
      when "BetterAuth::Adapters::MongoDB" then "mongodb"
      else adapter.class.name
      end
    end

    def normalized_page_limit(limit)
      value = Integer(limit || 50)
      value.clamp(1, 200)
    rescue
      50
    end

    def normalized_page_offset(offset)
      [Integer(offset || 0), 0].max
    rescue
      0
    end

    def include_rows_for_table?(table_name, selected_table)
      selected_table.nil? || table_name.to_s == selected_table.to_s
    end

    def paginated_select_sql(quoted_table, dialect, limit, offset)
      if dialect == :mssql
        "SELECT * FROM #{quoted_table} ORDER BY (SELECT NULL) OFFSET #{offset.to_i} ROWS FETCH NEXT #{limit.to_i} ROWS ONLY;"
      else
        "SELECT * FROM #{quoted_table} LIMIT #{limit.to_i} OFFSET #{offset.to_i};"
      end
    end

    def explore_memory(auth, selected_table, limit, offset)
      memory_table_names(auth).map do |name|
        rows = memory_rows(auth, name)
        normalized_rows = if include_rows_for_table?(name, selected_table)
          rows.drop(offset).first(limit).map { |row| normalize_row(row) }
        else
          []
        end
        {
          name: name,
          columns: columns_for(normalized_rows, memory_schema_columns(auth.options, name)),
          count: rows.length,
          rows: normalized_rows
        }
      end
    end

    def explore_sql(auth, selected_table, limit, offset)
      adapter = auth.context.adapter
      dialect = adapter.dialect
      sql_table_names(auth).map do |table_name|
        quoted = BetterAuth::Schema::SQL.quote(table_name, dialect)
        rows = if include_rows_for_table?(table_name, selected_table)
          execute_adapter_sql(adapter, paginated_select_sql(quoted, dialect, limit, offset)).map { |row| normalize_row(row) }
        else
          []
        end
        count_row = execute_adapter_sql(adapter, "SELECT COUNT(*) AS count FROM #{quoted};").first || {}
        {
          name: table_name,
          columns: columns_for(rows, sql_columns(adapter, table_name)),
          count: (count_row["count"] || count_row[:count] || rows.length).to_i,
          rows: rows
        }
      rescue => error
        {
          name: table_name,
          columns: [],
          count: 0,
          rows: [],
          error: "#{error.class}: #{error.message}"
        }
      end
    end

    def explore_mongodb(auth, selected_table, limit, offset)
      adapter = auth.context.adapter
      mongodb_collection_names(auth).map do |collection_name|
        collection = adapter.database.collection(collection_name)
        rows = if include_rows_for_table?(collection_name, selected_table)
          collection.find.skip(offset).limit(limit).map { |row| normalize_row(row) }
        else
          []
        end
        {
          name: collection_name,
          columns: columns_for(rows, memory_schema_columns(auth.options, collection_name)),
          count: collection.count_documents({}),
          rows: rows
        }
      rescue => error
        {
          name: collection_name,
          columns: [],
          count: 0,
          rows: [],
          error: "#{error.class}: #{error.message}"
        }
      end
    end

    def ensure_sql_schema!(auth)
      adapter = auth.context.adapter
      dialect = adapter.dialect
      sql = BetterAuth::SQLMigration.render_pending(
        auth.options,
        connection: adapter.connection,
        dialect: dialect,
        generator: "better-auth-examples"
      )
      return if sql.empty?

      execute_adapter_sql(adapter, sql)
    end

    def execute_adapter_sql(adapter, sql)
      if adapter.dialect == :mssql && adapter.connection.respond_to?(:fetch)
        sql_statements(sql).each_with_object([]) do |statement, results|
          dataset = adapter.connection.fetch(statement)
          results.concat(dataset.all.map { |row| stringify_keys(row) }) if dataset.respond_to?(:all)
        end
      else
        BetterAuth::SQLMigration.execute_sql(adapter.connection, sql)
      end
    end

    def sql_statements(sql)
      BetterAuth::SQLMigration.statements(sql)
    rescue
      sql.to_s.split(";").map(&:strip).reject(&:empty?)
    end

    def stringify_keys(row)
      row.each_with_object({}) { |(key, value), result| result[key.to_s.downcase] = value }
    end

    def index_statement?(statement)
      statement.match?(/\bCREATE\s+INDEX\b/i)
    end

    def index_exists?(adapter, statement)
      name = statement[/CREATE\s+INDEX(?:\s+IF\s+NOT\s+EXISTS)?\s+[`"\[]?([^`"\]\s]+)[`"\]]?/i, 1]
      return false if name.to_s.empty?

      dialect = adapter.dialect
      sql = case dialect
      when :sqlite
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name = #{BetterAuth::SQLMigration.literal(name)};"
      when :postgres
        "SELECT indexname AS name FROM pg_indexes WHERE schemaname = 'public' AND indexname = #{BetterAuth::SQLMigration.literal(name)};"
      when :mysql
        "SELECT index_name AS name FROM information_schema.statistics WHERE table_schema = DATABASE() AND index_name = #{BetterAuth::SQLMigration.literal(name)} LIMIT 1;"
      when :mssql
        "SELECT name FROM sys.indexes WHERE name = #{BetterAuth::SQLMigration.literal(name)};"
      else
        return false
      end
      execute_adapter_sql(adapter, sql).any?
    rescue
      false
    end

    def memory_table_names(auth)
      adapter = auth.context.adapter
      schema_names = schema_table_names(auth.options)
      logical_names = memory_logical_table_names(auth.options).values
      legacy_names = legacy_schema_names(auth.options)
      extra_names = adapter.db.keys.map(&:to_s).reject { |name| schema_names.include?(name) || logical_names.include?(name) || legacy_names.include?(name) }
      (schema_names + extra_names).uniq
    end

    def schema_table_names(options)
      BetterAuth::Schema.auth_tables(options).values.map { |table| table.fetch(:model_name).to_s }
    rescue
      %w[users sessions accounts verifications]
    end

    def memory_schema_columns(options, table_name)
      table = BetterAuth::Schema.auth_tables(options).values.find { |candidate| candidate.fetch(:model_name).to_s == table_name.to_s }
      return [] unless table

      table.fetch(:fields).map { |logical_name, field| field[:field_name] || field["field_name"] || BetterAuth::Schema.send(:physical_name, logical_name) }.compact
    rescue
      []
    end

    def memory_rows(auth, table_name)
      adapter = auth.context.adapter
      logical_name = memory_logical_table_names(auth.options).fetch(table_name.to_s, table_name.to_s)
      adapter.db.fetch(logical_name, adapter.db.fetch(table_name.to_s, []))
    end

    def memory_logical_table_names(options)
      BetterAuth::Schema.auth_tables(options).each_with_object({}) do |(logical_name, table), result|
        result[table.fetch(:model_name).to_s] = logical_name.to_s
      end
    rescue
      {}
    end

    def actual_sql_tables(adapter)
      rows = execute_adapter_sql(adapter, table_list_sql(adapter.dialect))
      names = rows.map { |row| (row["name"] || row[:name] || row.values.first).to_s }
      names.reject { |name| name.empty? || ignored_table?(name) }
    end

    def sql_table_names(auth)
      adapter = auth.context.adapter
      schema_names = BetterAuth::Schema.auth_tables(auth.options).values.map { |table| table.fetch(:model_name).to_s }
      legacy_names = legacy_schema_names(auth.options)
      actual_names = actual_sql_tables(adapter).reject { |name| legacy_names.include?(name) }
      (schema_names + actual_names).uniq.reject { |name| ignored_table?(name) }
    end

    def table_list_sql(dialect)
      case dialect
      when :sqlite
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
      when :postgres
        "SELECT tablename AS name FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;"
      when :mysql
        "SELECT table_name AS name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name;"
      when :mssql
        "SELECT TABLE_NAME AS name FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME;"
      else
        raise ArgumentError, "Unsupported SQL dialect: #{dialect}"
      end
    end

    def sql_columns(adapter, table_name)
      rows = execute_adapter_sql(adapter, column_list_sql(adapter.dialect, table_name))
      rows.map { |row| (row["name"] || row[:name] || row.values.first).to_s }.reject(&:empty?)
    rescue
      []
    end

    def delete_memory_records!(auth, table_name, ids)
      adapter = auth.context.adapter
      logical_name = memory_logical_table_names(auth.options).fetch(table_name.to_s, table_name.to_s)
      rows = adapter.db.fetch(logical_name, [])
      before = rows.length
      rows.reject! { |row| ids.include?((row["id"] || row[:id]).to_s) }
      {deleted: before - rows.length}
    end

    def delete_sql_records!(auth, table_name, ids)
      adapter = auth.context.adapter
      allowed = sql_table_names(auth)
      raise ArgumentError, "Unknown table: #{table_name}" unless allowed.include?(table_name.to_s)

      quoted_table = BetterAuth::Schema::SQL.quote(table_name, adapter.dialect)
      quoted_id = BetterAuth::Schema::SQL.quote("id", adapter.dialect)
      id_list = ids.map { |id| BetterAuth::SQLMigration.literal(id) }.join(", ")
      count_row = execute_adapter_sql(adapter, "SELECT COUNT(*) AS count FROM #{quoted_table} WHERE #{quoted_id} IN (#{id_list});").first || {}
      count = (count_row["count"] || count_row[:count] || count_row.values.first || 0).to_i
      execute_adapter_sql(adapter, "DELETE FROM #{quoted_table} WHERE #{quoted_id} IN (#{id_list});")
      {deleted: count}
    end

    def delete_mongodb_records!(auth, table_name, ids)
      adapter = auth.context.adapter
      allowed = mongodb_collection_names(auth)
      raise ArgumentError, "Unknown collection: #{table_name}" unless allowed.include?(table_name.to_s)

      object_ids = ids.map { |id| bson_object_id(id) }
      result = adapter.database.collection(table_name.to_s).delete_many("_id" => {"$in" => object_ids})
      {deleted: result.deleted_count}
    end

    def bson_object_id(value)
      BSON::ObjectId.from_string(value)
    rescue BSON::ObjectId::Invalid
      value
    end

    def column_list_sql(dialect, table_name)
      escaped = table_name.to_s.gsub("'", "''")
      case dialect
      when :sqlite
        "PRAGMA table_info(#{BetterAuth::Schema::SQL.quote(table_name, dialect)});"
      when :postgres, :mysql, :mssql
        "SELECT column_name AS name FROM information_schema.columns WHERE table_name = '#{escaped}' ORDER BY ordinal_position;"
      else
        raise ArgumentError, "Unsupported SQL dialect: #{dialect}"
      end
    end

    def mongodb_collection_names(auth)
      adapter = auth.context.adapter
      tables = BetterAuth::Schema.auth_tables(auth.options)
      logical_names = tables.keys.map(&:to_s)
      schema_names = tables.values.map { |table| table.fetch(:model_name).to_s }
      actual_names = adapter.database.collection_names.map(&:to_s)
      legacy_names = legacy_schema_names(auth.options)
      (schema_names + actual_names)
        .uniq
        .reject { |name| ignored_table?(name) || legacy_names.include?(name) || legacy_mongodb_collection?(name, logical_names, schema_names) }
        .sort
    end

    def legacy_mongodb_collection?(name, logical_names, schema_names)
      logical_names.include?(name.to_s) && schema_names.include?("#{name}s")
    end

    def ignored_table?(name)
      name.to_s == "better_auth_schema_migrations"
    end

    def drop_sql_tables(auth)
      adapter = auth.context.adapter
      dialect = adapter.dialect
      names = BetterAuth::Schema.auth_tables(auth.options).values.map { |table| table.fetch(:model_name).to_s }
      names.concat(actual_sql_tables(adapter).select { |name| legacy_schema_names(auth.options).include?(name) })
      names = names.uniq.reverse
      names << "better_auth_schema_migrations"
      statements = names.map { |name| drop_table_statement(name, dialect) }
      statements.unshift(mssql_drop_foreign_keys_statement(names)) if dialect == :mssql
      statements.unshift("SET FOREIGN_KEY_CHECKS=0") if dialect == :mysql
      statements << "SET FOREIGN_KEY_CHECKS=1" if dialect == :mysql
      statements.unshift("PRAGMA foreign_keys = OFF") if dialect == :sqlite
      statements << "PRAGMA foreign_keys = ON" if dialect == :sqlite
      execute_adapter_sql(adapter, statements.join(";\n"))
    end

    def mssql_drop_foreign_keys_statement(table_names)
      quoted_names = table_names.map { |name| BetterAuth::SQLMigration.literal(name) }.join(", ")
      <<~SQL
        DECLARE @sql NVARCHAR(MAX) = N''
        SELECT @sql = @sql + N'ALTER TABLE ' + QUOTENAME(SCHEMA_NAME(parent_table.schema_id)) + N'.' + QUOTENAME(parent_table.name) + N' DROP CONSTRAINT ' + QUOTENAME(foreign_key.name) + CHAR(10)
        FROM sys.foreign_keys AS foreign_key
        INNER JOIN sys.tables AS parent_table ON foreign_key.parent_object_id = parent_table.object_id
        INNER JOIN sys.tables AS referenced_table ON foreign_key.referenced_object_id = referenced_table.object_id
        WHERE parent_table.name IN (#{quoted_names}) OR referenced_table.name IN (#{quoted_names})
        EXEC sp_executesql @sql
      SQL
    end

    def drop_table_statement(name, dialect)
      quoted = BetterAuth::Schema::SQL.quote(name, dialect)
      case dialect
      when :postgres
        "DROP TABLE IF EXISTS #{quoted} CASCADE"
      else
        "DROP TABLE IF EXISTS #{quoted}"
      end
    end

    def drop_mongodb_collections(auth)
      adapter = auth.context.adapter
      mongodb_auth_collection_names(auth).each do |collection_name|
        adapter.database.collection(collection_name).drop
      rescue Mongo::Error::OperationFailure
        next
      end
    end

    def mongodb_auth_collection_names(auth)
      tables = BetterAuth::Schema.auth_tables(auth.options)
      schema_names = tables.values.map { |table| table.fetch(:model_name).to_s }
      adapter = auth.context.adapter
      actual_legacy_names = if mongodb_adapter?(adapter)
        adapter.database.collection_names.map(&:to_s).select { |name| legacy_schema_names(auth.options).include?(name) }
      else
        []
      end
      (schema_names + actual_legacy_names).map(&:to_s).uniq
    end

    def legacy_schema_names(options)
      BetterAuth::Schema.auth_tables(options).flat_map do |logical_name, table|
        current = table.fetch(:model_name).to_s
        singular = singular_table_name(current)
        [
          logical_name.to_s,
          underscore(logical_name),
          camelize_lower(current),
          singular,
          camelize_lower(singular)
        ].compact.reject { |name| name.empty? || name == current }
      end.uniq
    rescue
      []
    end

    def singular_table_name(name)
      value = name.to_s
      return "api_key" if value == "api_keys"
      return "#{value[0...-3]}y" if value.end_with?("ies")
      return value[0...-2] if value.match?(/(ses|xes|zes|ches|shes)\z/)
      return value[0...-1] if value.end_with?("s")

      value
    end

    def camelize_lower(value)
      parts = underscore(value).split("_")
      ([parts.first] + parts.drop(1).map(&:capitalize)).join
    end

    def underscore(value)
      value.to_s
        .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
        .tr("-", "_")
        .downcase
    end

    def columns_for(rows, fallback = [])
      (Array(fallback) + rows.flat_map(&:keys)).map(&:to_s).uniq
    end

    def normalize_row(row)
      row.each_with_object({}) do |(key, value), result|
        result[key.to_s] = normalize_value(value)
      end
    end

    def normalize_value(value)
      case value
      when Time
        value.iso8601
      else
        if defined?(BSON::ObjectId) && value.is_a?(BSON::ObjectId)
          value.to_s
        else
          value
        end
      end
    end
  end
end

# frozen_string_literal: true

require "better_auth"
require "mongo"
require "securerandom"
require "time"
require_relative "mongodb/version"

module BetterAuth
  module Adapters
    class MongoDB < Base
      class MongoAdapterError < Error
        attr_reader :code

        def initialize(code, message)
          @code = code
          super(message)
        end
      end

      attr_reader :database, :client, :use_plural

      def initialize(options = nil, database:, client: nil, transaction: nil, use_plural: false, session: nil)
        require "mongo" unless database

        super(options || Configuration.new(secret: Configuration::DEFAULT_SECRET, database: :memory))
        @database = database
        @client = client
        @transaction_enabled = transaction.nil? ? !client.nil? : !!transaction
        @use_plural = !!use_plural
        @session = session
      end

      def create(model:, data:, force_allow_id: false)
        model = model.to_s
        record = transform_input(model, data, "create", force_allow_id)
        document = to_document(model, record)
        collection_for(model).insert_one(document, session_options)
        from_document(model, document)
      end

      def find_one(model:, where: [], select: nil, join: nil)
        find_many(model: model, where: where, select: select, join: join, limit: 1).first
      end

      def find_many(model:, where: [], sort_by: nil, limit: nil, offset: nil, select: nil, join: nil)
        model = model.to_s
        pipeline = [{"$match" => mongo_filter(model, where || [])}]
        pipeline << {"$sort" => {sort_field(model, sort_by) => sort_direction(sort_by)}} if sort_by
        pipeline << {"$skip" => non_negative_integer!(offset, "offset")} unless offset.nil?
        effective_limit = limit.nil? ? default_find_many_limit : positive_integer!(limit, "limit")
        pipeline << {"$limit" => effective_limit}
        pipeline.concat(join_stages(model, join)) if join
        pipeline << {"$project" => projection_for(model, select, join)} if select && !select.empty?

        collection_for(model)
          .aggregate(pipeline, session_options)
          .to_a
          .map { |document| from_document(model, stringify_document(document), join: join) }
      end

      def update(model:, where:, update:)
        model = model.to_s
        ensure_update_input_has_fields!(model, update)
        data = transform_input(model, update, "update", true)
        document = to_document(model, data)
        document.delete("_id")
        ensure_update_document!(document)
        result = collection_for(model).find_one_and_update(
          mongo_filter(model, where || []),
          {"$set" => document},
          session_options.merge(return_document: :after)
        )
        result = unwrap_update_result(result)
        result ? from_document(model, stringify_document(result)) : nil
      end

      def update_many(model:, where:, update:)
        model = model.to_s
        ensure_update_input_has_fields!(model, update)
        data = transform_input(model, update, "update", true)
        document = to_document(model, data)
        document.delete("_id")
        ensure_update_document!(document)
        result = collection_for(model).update_many(
          mongo_filter(model, where || []),
          {"$set" => document},
          session_options
        )
        result.respond_to?(:modified_count) ? result.modified_count : result.to_i
      end

      def delete(model:, where:)
        collection_for(model.to_s).delete_one(mongo_filter(model.to_s, where || []), session_options)
        nil
      end

      def delete_many(model:, where:)
        result = collection_for(model.to_s).delete_many(mongo_filter(model.to_s, where || []), session_options)
        result.respond_to?(:deleted_count) ? result.deleted_count : result.to_i
      end

      def count(model:, where: nil)
        pipeline = [
          {"$match" => mongo_filter(model.to_s, where || [])},
          {"$count" => "total"}
        ]
        row = collection_for(model.to_s).aggregate(pipeline, session_options).to_a.first
        return 0 unless row

        (row["total"] || row[:total] || 0).to_i
      end

      def ensure_indexes!
        Schema.auth_tables(options).flat_map do |model, table|
          table.fetch(:fields).filter_map do |field, attributes|
            next if field == "id"
            next unless attributes[:unique] || attributes[:index]

            collection = collection_for(model)
            key = storage_field(model, field)
            index_options = attributes[:unique] ? {unique: true} : {}
            collection.indexes.create_one({key => 1}, index_options)
            {
              collection: collection_name(model),
              field: field,
              keys: {key => 1},
              unique: attributes[:unique] == true
            }
          end
        end
      end

      def transaction
        return yield self unless client && @transaction_enabled && client.respond_to?(:start_session)

        session = client.start_session
        begin
          session.start_transaction
          adapter = self.class.new(options, database: database, client: client, transaction: @transaction_enabled, use_plural: use_plural, session: session)
          result = yield adapter
          session.commit_transaction
          result
        rescue
          session.abort_transaction
          raise
        ensure
          session.end_session
        end
      end

      private

      def transform_input(model, data, action, force_allow_id)
        fields = fields_for(model)
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

        output["id"] = generated_id if action == "create" && !output.key?("id")
        output
      end

      def mongo_filter(model, where)
        clauses = validate_where!(where)
        return {} if clauses.empty?

        conditions = clauses.map do |clause|
          connector = if fetch_key(clause, :connector).to_s.upcase == "OR"
            "OR"
          else
            "AND"
          end
          {condition: condition_for(model, clause), connector: connector}
        end
        return conditions.first.fetch(:condition) if conditions.one?

        result = {}
        and_conditions = conditions.select { |entry| entry.fetch(:connector) == "AND" }.map { |entry| entry.fetch(:condition) }
        or_conditions = conditions.select { |entry| entry.fetch(:connector) == "OR" }.map { |entry| entry.fetch(:condition) }
        result["$and"] = and_conditions if and_conditions.any?
        result["$or"] = or_conditions if or_conditions.any?
        result
      end

      def default_find_many_limit
        value = options.advanced.dig(:database, :default_find_many_limit)
        return 100 if value.nil?

        parsed = Integer(value)
        parsed.positive? ? parsed : 100
      rescue ArgumentError, TypeError
        100
      end

      def array_operator_values(value)
        value.is_a?(Array) ? value : [value]
      end

      def condition_for(model, clause)
        operator = (fetch_key(clause, :operator) || "eq").to_s.downcase
        value = fetch_key(clause, :value)

        requested_field = fetch_key(clause, :field)
        bad_request!("where field is required") if requested_field.nil? || requested_field.to_s.empty?

        field = resolve_field(model, requested_field)
        attributes = fields_for(model).fetch(field)
        key = (field == "id") ? "_id" : storage_field(model, field)
        mode = (fetch_key(clause, :mode) || "sensitive").to_s
        id_field = id_field?(field, attributes)
        insensitive = !id_field && mode == "insensitive" && insensitive_value?(value)
        value = coerce_where_value(value, attributes)

        case operator
        when "eq"
          (insensitive && value.is_a?(String)) ? regex_condition(key, value, :eq, insensitive: true) : {key => store_value(field, value, attributes, strict_id: true)}
        when "in"
          bad_request!("where value must be an array for in operator") unless value.is_a?(Array)

          (insensitive && value.is_a?(Array)) ? insensitive_in_condition(key, value) : {key => {"$in" => array_operator_values(value).map { |entry| store_value(field, entry, attributes, strict_id: true) }}}
        when "not_in"
          (insensitive && value.is_a?(Array)) ? insensitive_not_in_condition(key, value) : {key => {"$nin" => array_operator_values(value).map { |entry| store_value(field, entry, attributes, strict_id: true) }}}
        when "ne"
          (insensitive && value.is_a?(String)) ? {key => {"$not" => regex_for(value, :eq, insensitive: true)}} : {key => {"$ne" => store_value(field, value, attributes, strict_id: true)}}
        when "gt", "gte", "lt", "lte"
          {key => {"$#{operator}" => store_value(field, value, attributes, strict_id: true)}}
        when "contains", "starts_with", "ends_with"
          regex_condition(key, value.to_s, operator.to_sym, insensitive: insensitive)
        else
          raise MongoAdapterError.new("UNSUPPORTED_OPERATOR", "Unsupported operator: #{operator}")
        end
      end

      def insensitive_value?(value)
        value.is_a?(String) || (value.is_a?(Array) && value.all? { |entry| entry.is_a?(String) })
      end

      def insensitive_in_condition(key, values)
        return {"$expr" => {"$eq" => [1, 0]}} if values.empty?

        {"$or" => values.map { |value| regex_condition(key, value, :eq, insensitive: true) }}
      end

      def insensitive_not_in_condition(key, values)
        return {} if values.empty?

        {"$nor" => values.map { |value| regex_condition(key, value, :eq, insensitive: true) }}
      end

      def regex_condition(key, value, operator, insensitive:)
        {key => regex_for(value, operator, insensitive: insensitive)}
      end

      def regex_for(value, operator, insensitive:)
        escaped = Regexp.escape(value.to_s[0, 256])
        pattern = case operator.to_s
        when "eq" then "\\A#{escaped}\\z"
        when "starts_with" then "\\A#{escaped}"
        when "ends_with" then "#{escaped}\\z"
        else escaped
        end
        Regexp.new(pattern, insensitive ? Regexp::IGNORECASE : nil)
      end

      def join_stages(model, join)
        normalized_join(model, join).flat_map do |join_model, config|
          local_field = storage_field_for_join(model, config.fetch(:from))
          foreign_field = storage_field_for_join(join_model, config.fetch(:to))
          relation = config[:relation]
          limit = config.key?(:limit) ? config[:limit] : nil
          effective_limit = limit.nil? ? default_find_many_limit : positive_integer!(limit, "join limit")
          unique = relation == "one-to-one" || config[:unique]
          should_limit = !unique

          lookup = if should_limit
            {
              "$lookup" => {
                "from" => collection_name(join_model),
                "let" => {"localFieldValue" => "$#{local_field}"},
                "pipeline" => [
                  {"$match" => {"$expr" => {"$eq" => ["$#{foreign_field}", "$$localFieldValue"]}}},
                  {"$limit" => effective_limit}
                ],
                "as" => join_model
              }
            }
          else
            {
              "$lookup" => {
                "from" => collection_name(join_model),
                "localField" => local_field,
                "foreignField" => foreign_field,
                "as" => join_model
              }
            }
          end

          unique ? [lookup, {"$unwind" => {"path" => "$#{join_model}", "preserveNullAndEmptyArrays" => true}}] : [lookup]
        end
      end

      def normalized_join(model, join)
        bad_request!("join must be a hash") unless join.is_a?(Hash)

        join.each_with_object({}) do |(join_model, config), result|
          join_model = join_model.to_s
          bad_request!("join model is required") if join_model.empty?

          result[join_model] = normalize_join_config(model, join_model, config)
        end
      end

      def normalize_join_config(model, join_model, config)
        bad_request!("join config must be true or a hash") unless config == true || config.is_a?(Hash)

        if config.is_a?(Hash) && (config.key?(:on) || config.key?("on"))
          on = config[:on] || config["on"]
          bad_request!("join on must be a hash") unless on.is_a?(Hash)

          relation = config[:relation] || config["relation"]
          limit = config[:limit] || config["limit"]
          from = fetch_key(on, :from)
          to = fetch_key(on, :to)
          bad_request!("join on.from is required") if from.nil? || from.to_s.empty?
          bad_request!("join on.to is required") if to.nil? || to.to_s.empty?

          return {from: Schema.storage_key(from), to: Schema.storage_key(to), relation: relation, limit: limit, unique: unique_join_field?(join_model, to)}
        end

        inferred = inferred_join_config(model, join_model)
        if config.is_a?(Hash)
          limit = config[:limit] || config["limit"]
          relation = config[:relation] || config["relation"]
          inferred = inferred.merge(limit: limit) if limit
          inferred = inferred.merge(relation: relation) if relation
        end
        inferred
      end

      def inferred_join_config(model, join_model)
        base_model = default_model_name(model)
        target_model = default_model_name(join_model)
        foreign_keys = fields_for(target_model).select do |_field, attributes|
          reference_model_matches?(attributes, base_model)
        end
        forward_join = true

        if foreign_keys.empty?
          foreign_keys = fields_for(base_model).select do |_field, attributes|
            reference_model_matches?(attributes, target_model)
          end
          forward_join = false
        end

        if foreign_keys.empty?
          raise Error, "No foreign key found for model #{join_model} and base model #{model} while performing join operation."
        end
        if foreign_keys.length > 1
          raise Error, "Multiple foreign keys found for model #{join_model} and base model #{model} while performing join operation. Only one foreign key is supported."
        end

        foreign_key, attributes = foreign_keys.first
        reference = attributes.fetch(:references)
        if forward_join
          unique = attributes[:unique] == true
          {from: reference.fetch(:field).to_s, to: foreign_key, relation: unique ? "one-to-one" : "one-to-many", unique: unique}
        else
          {from: foreign_key, to: reference.fetch(:field).to_s, relation: "one-to-one", unique: true}
        end
      end

      def reference_model_matches?(attributes, model)
        reference = attributes[:references]
        return false unless reference

        default_model_name(reference[:model] || reference["model"]) == model
      end

      def unique_join_field?(model, field)
        field = resolve_field(model, field)
        field == "id" || fields_for(model).dig(field, :unique) == true
      end

      def storage_field_for_join(model, field)
        field = resolve_field(model, field)
        (field == "id") ? "_id" : storage_field(model, field)
      end

      def projection_for(model, select, join)
        selected_fields = Array(select).map { |field| storage_field_for_join(model, field) }
        Array(select).each_with_object({}) do |field, projection|
          projection[storage_field_for_join(model, field)] = 1
        end.tap do |projection|
          projection["_id"] = 0 unless selected_fields.include?("_id")
          normalized_join(model, join).each_key { |join_model| projection[join_model] = 1 } if join
        end
      end

      def sort_field(model, sort_by)
        field = resolve_field(model, fetch_key(sort_by, :field))
        storage_field_for_join(model, field)
      end

      def sort_direction(sort_by)
        (fetch_key(sort_by, :direction).to_s == "desc") ? -1 : 1
      end

      def collection_for(model)
        database.collection(collection_name(model))
      end

      def collection_name(model)
        model = default_model_name(model)
        configured = configured_model_name(model)
        return "#{configured}s" if configured && use_plural
        return configured if configured
        return schema_for(model).fetch(:model_name) if use_plural

        model.to_s
      end

      def to_document(model, record)
        fields_for(model).each_with_object({}) do |(field, attributes), document|
          next unless record.key?(field)

          key = (field == "id") ? "_id" : storage_field(model, field)
          document[key] = store_value(field, record[field], attributes)
        end
      end

      def from_document(model, document, join: nil)
        fields = fields_for(model)
        record = fields.each_with_object({}) do |(field, attributes), output|
          key = (field == "id") ? "_id" : storage_field(model, field)
          output[field] = output_value(field, fetch_document(document, key), attributes) if document_key?(document, key)
        end

        if join
          normalized_join(model, join).each do |join_model, config|
            next unless document_key?(document, join_model)

            joined_value = fetch_document(document, join_model)
            record[join_model] = if joined_value.is_a?(Array)
              joined_value.map { |entry| from_document(join_model, stringify_document(entry)) }
            elsif joined_value
              from_document(join_model, stringify_document(joined_value))
            elsif config[:relation] == "one-to-one"
              nil
            else
              []
            end
          end
        end

        record
      end

      def stringify_document(document)
        document.each_with_object({}) { |(key, value), result| result[key.to_s] = value }
      end

      def unwrap_update_result(result)
        return result unless result.is_a?(Hash)
        return result if document_key?(result, "_id")

        if result.key?("value") && (result.key?("ok") || result.key?("lastErrorObject"))
          return result["value"]
        end
        if result.key?(:value) && (result.key?(:ok) || result.key?(:last_error_object))
          return result[:value]
        end

        result
      end

      def store_value(field, value, attributes, strict_id: false)
        return nil if value.nil?
        return Array(value).map { |entry| store_value(field, entry, attributes, strict_id: strict_id) } if value.is_a?(Array)

        if id_field?(field, attributes)
          return value if custom_id_generator?
          return bson_id(value, strict: strict_id)
        end

        input_value(value, attributes)
      end

      def output_value(field, value, attributes)
        return nil if value.nil?
        if id_field?(field, attributes)
          return value.to_uuid if bson_uuid?(value)
          return value.to_s if value.is_a?(BSON::ObjectId)
          return value.map { |entry| output_value(field, entry, attributes) } if value.is_a?(Array)
          return value
        end

        output_scalar_value(value, attributes)
      end

      def id_field?(field, attributes)
        field.to_s == "id" || attributes.dig(:references, :field) == "id"
      end

      def bson_id(value, strict:)
        if use_uuid_ids?
          return value if bson_uuid?(value)
          return BSON::Binary.from_uuid(value.to_s) if value.is_a?(String)
          raise MongoAdapterError.new("INVALID_ID", "Invalid id value") if strict

          return value
        end

        return value if value.is_a?(BSON::ObjectId)
        return BSON::ObjectId.from_string(value.to_s) if value.is_a?(String)
        raise MongoAdapterError.new("INVALID_ID", "Invalid id value") if strict

        value
      rescue BSON::Error::InvalidObjectId, ArgumentError
        value
      end

      def bson_uuid?(value)
        defined?(BSON::Binary) && value.is_a?(BSON::Binary) && value.respond_to?(:to_uuid) && value.type == :uuid
      end

      def generated_id
        generator = options.advanced.dig(:database, :generate_id)
        return generator.call if generator.respond_to?(:call)
        return SecureRandom.uuid if use_uuid_ids?
        return BSON::ObjectId.new.to_s if defined?(BSON::ObjectId)

        SecureRandom.hex(12)
      end

      def use_uuid_ids?
        options.advanced.dig(:database, :generate_id) == "uuid"
      end

      def custom_id_generator?
        options.advanced.dig(:database, :generate_id).respond_to?(:call)
      end

      def resolve_default(default)
        default.respond_to?(:call) ? default.call : default
      end

      def coerce_value(value, attributes)
        return value if value.nil?
        return parse_date_value(value) if attributes[:type] == "date" && value.is_a?(String)

        value
      end

      def input_value(value, attributes)
        value = coerce_value(value, attributes)
        return JSON.generate(value) if attributes[:type] == "json" && (value.is_a?(Hash) || value.is_a?(Array))

        value
      end

      def output_scalar_value(value, attributes)
        return JSON.parse(value) if attributes[:type] == "json" && value.is_a?(String)

        coerce_value(value, attributes)
      rescue JSON::ParserError
        value
      end

      def coerce_where_value(value, attributes)
        return value.map { |entry| coerce_where_value(entry, attributes) } if value.is_a?(Array)
        return value == "true" if attributes[:type] == "boolean" && value.is_a?(String)
        if attributes[:type] == "number" && value.is_a?(String) && !value.strip.empty?
          parsed = Float(value)
          return parsed.to_i if parsed.to_i == parsed

          return parsed
        end
        return JSON.generate(value) if attributes[:type] == "json" && (value.is_a?(Hash) || value.is_a?(Array))

        value
      rescue ArgumentError
        value
      end

      def session_options
        @session ? {session: @session} : {}
      end

      def document_key?(document, key)
        document.key?(key) || document.key?(key.to_sym)
      end

      def fetch_document(document, key)
        return document[key] if document.key?(key)

        document[key.to_sym]
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

      def validate_where!(where)
        bad_request!("where must be an array") unless where.is_a?(Array)

        where.each do |clause|
          bad_request!("where entries must be hashes") unless clause.is_a?(Hash)
        end

        where
      end

      def positive_integer!(value, name)
        parsed = Integer(value)
        bad_request!("#{name} must be a positive integer") unless parsed.positive?

        parsed
      rescue ArgumentError, TypeError
        bad_request!("#{name} must be a positive integer")
      end

      def non_negative_integer!(value, name)
        parsed = Integer(value)
        bad_request!("#{name} must be zero or a positive integer") if parsed.negative?

        parsed
      rescue ArgumentError, TypeError
        bad_request!("#{name} must be zero or a positive integer")
      end

      def ensure_update_document!(document)
        bad_request!("No fields to update") if document.empty?
      end

      def ensure_update_input_has_fields!(model, update)
        bad_request!("update must be a hash") unless update.is_a?(Hash)

        fields = fields_for(model)
        input = stringify_keys(update)
        has_updatable_field = input.any? do |field_key, _value|
          next false if field_key == "id" || field_key == "_id"

          fields.key?(field_key) || fields.any? { |_field, attributes| attributes[:field_name].to_s == field_key }
        end
        bad_request!("No fields to update") unless has_updatable_field
      end

      def parse_date_value(value)
        Time.parse(value)
      rescue ArgumentError
        bad_request!("Invalid date value")
      end

      def bad_request!(message)
        raise APIError.new("BAD_REQUEST", message: message)
      end

      def schema_for(model)
        Schema.auth_tables(options).fetch(default_model_name(model))
      end

      def fields_for(model)
        schema_for(model).fetch(:fields).merge("id" => {type: "string", required: true})
      end

      def default_model_name(model)
        model = model.to_s
        tables = Schema.auth_tables(options)
        return model if tables.key?(model)

        pluraless = model.end_with?("s") ? model[0...-1] : nil
        return pluraless if pluraless && tables.key?(pluraless)

        matched = tables.find { |_key, table| table[:model_name].to_s == model }
        return matched.first if matched

        raise Error, "Model \"#{model}\" not found in schema"
      end

      def configured_model_name(model)
        configured = configured_model_option(model, :model_name)
        return configured.to_s if configured

        return nil if core_model?(model)

        table_model_name = schema_for(model).fetch(:model_name).to_s
        (table_model_name == physical_name(model)) ? nil : table_model_name
      end

      def configured_model_option(model, key)
        data = options.respond_to?(model.to_sym) ? options.public_send(model.to_sym) : nil
        data[key] || data[key.to_s] if data.respond_to?(:[])
      end

      def core_model?(model)
        ["user", "session", "account", "verification", "rateLimit"].include?(model.to_s)
      end

      def resolve_field(model, field)
        field = Schema.storage_key(field)
        return "id" if field == "id" || field == "_id"

        fields = fields_for(model)
        return field if fields.key?(field)

        matched = fields.find { |_key, attributes| attributes[:field_name].to_s == field.to_s }
        return matched.first if matched

        raise Error, "Field #{field} not found in model #{model}"
      end

      def storage_field(model, field)
        fields_for(model).fetch(field.to_s).fetch(:field_name, physical_name(field))
      end

      def physical_name(value)
        value.to_s
          .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
          .tr("-", "_")
          .downcase
      end
    end
  end

  MongoAdapter = MongoDB unless const_defined?(:MongoAdapter, false)
end

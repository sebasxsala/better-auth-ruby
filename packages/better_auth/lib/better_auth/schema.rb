# frozen_string_literal: true

module BetterAuth
  module Schema
    module_function

    def auth_tables(options)
      plugin_schema = plugin_tables(options)

      tables = {
        "user" => user_table(options, plugin_schema.delete("user")),
        "session" => session_table(options, plugin_schema.delete("session")),
        "account" => account_table(options, plugin_schema.delete("account")),
        "verification" => verification_table(options, plugin_schema.delete("verification"))
      }

      tables.delete("session") if secondary_storage?(options) && !session_option(options, :store_session_in_database)
      tables.delete("verification") if secondary_storage?(options) && !verification_option(options, :store_in_database)
      tables.merge!(plugin_schema)
      tables["rateLimit"] = rate_limit_table(options) if rate_limit_option(options, :storage) == "database"
      ensure_id_fields!(tables)
      tables.sort_by { |_name, table| table[:order] || Float::INFINITY }.to_h
    end

    def storage_model_name(options, model)
      table = auth_tables(options).fetch(model.to_s)
      table[:model_name]
    end

    def storage_field_name(options, model, field)
      table = auth_tables(options).fetch(model.to_s)
      data = table[:fields].fetch(field.to_s)
      data[:field_name] || field.to_s
    end

    def parse_output(options, model, data)
      return nil unless data

      table = auth_tables(options).fetch(model.to_s)
      table[:fields].each_with_object({}) do |(field, attributes), result|
        next if attributes[:returned] == false && field != "id"
        next unless data.key?(field)

        result[field] = data[field]
      end.tap do |result|
        data.each { |key, value| result[key] = value unless result.key?(key) || table[:fields].key?(key) }
      end
    rescue KeyError
      data
    end

    private_class_method def self.user_table(options, plugin_table)
      table(
        model_name: model_option(options, :user, :model_name) || "users",
        order: 1,
        fields: id_field.merge(
          "name" => field("string", required: true, sortable: true, field_name: mapped_field(options, :user, "name")),
          "email" => field("string", required: true, unique: true, sortable: true, field_name: mapped_field(options, :user, "email")),
          "emailVerified" => field("boolean", required: true, input: false, default_value: false, field_name: mapped_field(options, :user, "emailVerified")),
          "image" => field("string", required: false, field_name: mapped_field(options, :user, "image"))
        ).merge(timestamp_fields),
        extra_fields: [plugin_table&.fetch(:fields, nil), additional_fields(options, :user)]
      )
    end

    private_class_method def self.session_table(options, plugin_table)
      table(
        model_name: model_option(options, :session, :model_name) || "sessions",
        order: 2,
        fields: base_fields.merge(
          "expiresAt" => field("date", required: true, field_name: mapped_field(options, :session, "expiresAt")),
          "token" => field("string", required: true, unique: true, field_name: mapped_field(options, :session, "token")),
          "ipAddress" => field("string", required: false, field_name: mapped_field(options, :session, "ipAddress")),
          "userAgent" => field("string", required: false, field_name: mapped_field(options, :session, "userAgent")),
          "userId" => field("string", required: true, index: true, field_name: mapped_field(options, :session, "userId"), references: {model: model_option(options, :user, :model_name) || "users", field: "id", on_delete: "cascade"})
        ),
        extra_fields: [plugin_table&.fetch(:fields, nil), additional_fields(options, :session)]
      )
    end

    private_class_method def self.account_table(options, plugin_table)
      table(
        model_name: model_option(options, :account, :model_name) || "accounts",
        order: 3,
        fields: base_fields.merge(
          "accountId" => field("string", required: true, field_name: mapped_field(options, :account, "accountId")),
          "providerId" => field("string", required: true, field_name: mapped_field(options, :account, "providerId")),
          "userId" => field("string", required: true, index: true, field_name: mapped_field(options, :account, "userId"), references: {model: model_option(options, :user, :model_name) || "users", field: "id", on_delete: "cascade"}),
          "accessToken" => field("string", required: false, returned: false, field_name: mapped_field(options, :account, "accessToken")),
          "refreshToken" => field("string", required: false, returned: false, field_name: mapped_field(options, :account, "refreshToken")),
          "idToken" => field("string", required: false, returned: false, field_name: mapped_field(options, :account, "idToken")),
          "accessTokenExpiresAt" => field("date", required: false, returned: false, field_name: mapped_field(options, :account, "accessTokenExpiresAt")),
          "refreshTokenExpiresAt" => field("date", required: false, returned: false, field_name: mapped_field(options, :account, "refreshTokenExpiresAt")),
          "scope" => field("string", required: false, field_name: mapped_field(options, :account, "scope")),
          "password" => field("string", required: false, returned: false, field_name: mapped_field(options, :account, "password"))
        ),
        extra_fields: [plugin_table&.fetch(:fields, nil), additional_fields(options, :account)]
      )
    end

    private_class_method def self.verification_table(options, plugin_table)
      table(
        model_name: model_option(options, :verification, :model_name) || "verifications",
        order: 4,
        fields: base_fields.merge(
          "identifier" => field("string", required: true, index: true, field_name: mapped_field(options, :verification, "identifier")),
          "value" => field("string", required: true, field_name: mapped_field(options, :verification, "value")),
          "expiresAt" => field("date", required: true, field_name: mapped_field(options, :verification, "expiresAt"))
        ),
        extra_fields: [plugin_table&.fetch(:fields, nil), additional_fields(options, :verification)]
      )
    end

    private_class_method def self.rate_limit_table(options)
      {
        model_name: rate_limit_option(options, :model_name) || "rate_limits",
        fields: {
          "key" => field("string", required: true, unique: true, field_name: rate_limit_field(options, "key")),
          "count" => field("number", required: true, field_name: rate_limit_field(options, "count")),
          "lastRequest" => field("number", required: true, bigint: true, default_value: -> { current_millis }, field_name: rate_limit_field(options, "lastRequest"))
        }
      }
    end

    private_class_method def self.ensure_id_fields!(tables)
      tables.each_value do |table|
        fields = table.fetch(:fields)
        next if fields.key?("id")

        table[:fields] = id_field.merge(fields)
      end
    end

    private_class_method def self.base_fields
      id_field.merge(timestamp_fields)
    end

    private_class_method def self.id_field
      {
        "id" => field("string", required: true)
      }
    end

    private_class_method def self.timestamp_fields
      {
        "createdAt" => field("date", required: true, default_value: -> { Time.now }, field_name: physical_name("createdAt")),
        "updatedAt" => field("date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }, field_name: physical_name("updatedAt"))
      }
    end

    private_class_method def self.table(model_name:, fields:, extra_fields:, order:)
      {
        model_name: model_name,
        fields: merge_fields(fields, *extra_fields),
        order: order
      }
    end

    private_class_method def self.merge_fields(base, *extras)
      extras.compact.each_with_object(base.dup) do |extra, fields|
        normalize_fields(extra).each { |key, value| fields[key] = value }
      end
    end

    private_class_method def self.field(type, **attributes)
      {type: type}.merge(attributes).compact
    end

    private_class_method def self.plugin_tables(options)
      plugins_for(options).each_with_object({}) do |plugin, tables|
        schema = fetch_hash(plugin, :schema) || {}
        schema.each do |raw_key, raw_table|
          key = storage_key(raw_key)
          table_data = symbolize_hash(raw_table || {})
          existing = tables[key] || {model_name: table_data[:model_name] || physical_table_name(key), fields: {}}
          existing[:model_name] = table_data[:model_name] || existing[:model_name] || physical_table_name(key)
          existing[:fields] = existing[:fields].merge(normalize_fields(table_data[:fields] || {}))
          tables[key] = existing
        end
      end
    end

    private_class_method def self.normalize_fields(fields)
      fields.each_with_object({}) do |(raw_key, raw_value), result|
        key = storage_key(raw_key)
        result[key] = normalize_field(raw_value, key)
      end
    end

    private_class_method def self.normalize_field(value, key)
      data = symbolize_hash(value || {})
      data[:field_name] ||= physical_name(key)
      data[:references] = normalize_reference(data[:references]) if data[:references]
      data
    end

    private_class_method def self.normalize_reference(value)
      reference = symbolize_hash(value || {})
      reference[:on_delete] ||= "cascade"
      reference
    end

    private_class_method def self.mapped_field(options, model, field)
      fields = fetch_hash(model_options(options, model), :fields) || {}
      fetch_mapped_value(fields, field) || physical_name(field)
    end

    private_class_method def self.rate_limit_field(options, field)
      fields = fetch_hash(rate_limit_options(options), :fields) || {}
      fetch_mapped_value(fields, field) || physical_name(field)
    end

    private_class_method def self.fetch_mapped_value(hash, field)
      hash[storage_key(field).to_sym] || hash[storage_key(field)] || hash[underscore(field).to_sym] || hash[underscore(field)]
    end

    private_class_method def self.additional_fields(options, model)
      fetch_hash(model_options(options, model), :additional_fields) || {}
    end

    private_class_method def self.model_option(options, model, key)
      fetch_hash(model_options(options, model), key)
    end

    private_class_method def self.session_option(options, key)
      fetch_hash(session_options(options), key)
    end

    private_class_method def self.rate_limit_option(options, key)
      fetch_hash(rate_limit_options(options), key)
    end

    private_class_method def self.verification_option(options, key)
      fetch_hash(verification_options(options), key)
    end

    private_class_method def self.model_options(options, model)
      options.respond_to?(model) ? options.public_send(model) : fetch_hash(options, model)
    end

    private_class_method def self.session_options(options)
      options.respond_to?(:session) ? options.session : fetch_hash(options, :session)
    end

    private_class_method def self.rate_limit_options(options)
      options.respond_to?(:rate_limit) ? options.rate_limit : fetch_hash(options, :rate_limit)
    end

    private_class_method def self.verification_options(options)
      options.respond_to?(:verification) ? options.verification : fetch_hash(options, :verification)
    end

    private_class_method def self.secondary_storage?(options)
      options.respond_to?(:secondary_storage) ? !!options.secondary_storage : !!fetch_hash(options, :secondary_storage)
    end

    private_class_method def self.plugins_for(options)
      options.respond_to?(:plugins) ? options.plugins : Array(fetch_hash(options, :plugins))
    end

    private_class_method def self.fetch_hash(hash, key)
      return nil unless hash.respond_to?(:[])

      hash[key] || hash[key.to_s] || hash[underscore(key.to_s).to_sym] || hash[underscore(key.to_s)]
    end

    private_class_method def self.symbolize_hash(value)
      return {} unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object), result|
        result[underscore(key.to_s).to_sym] = object.is_a?(Hash) ? symbolize_hash(object) : object
      end
    end

    private_class_method def self.storage_key(value)
      camelize_lower(value.to_s)
    end

    private_class_method def self.physical_name(value)
      underscore(value.to_s)
    end

    private_class_method def self.physical_table_name(value)
      pluralize_table_name(physical_name(value))
    end

    private_class_method def self.pluralize_table_name(value)
      special = {
        "apikey" => "api_keys",
        "api_key" => "api_keys",
        "wallet_address" => "wallet_addresses"
      }
      return special.fetch(value) if special.key?(value)
      return value if value.end_with?("s")
      return "#{value[0...-1]}ies" if value.end_with?("y") && value.match?(/[^aeiou]y\z/)
      return "#{value}es" if value.match?(/(s|x|z|ch|sh)\z/)

      "#{value}s"
    end

    private_class_method def self.camelize_lower(value)
      parts = underscore(value).split("_")
      ([parts.first] + parts.drop(1).map(&:capitalize)).join
    end

    private_class_method def self.underscore(value)
      value
        .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
        .tr("-", "_")
        .downcase
    end

    private_class_method def self.current_millis
      (Time.now.to_f * 1000).to_i
    end

    public_class_method :storage_key
  end
end

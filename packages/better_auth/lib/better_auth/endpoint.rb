# frozen_string_literal: true

require "json"

module BetterAuth
  class Endpoint
    attr_reader :path,
      :body_schema,
      :query_schema,
      :params_schema,
      :headers_schema,
      :metadata,
      :options,
      :use,
      :disable_body,
      :handler

    def initialize(path: nil, method: nil, body_schema: nil, query_schema: nil, params_schema: nil, headers_schema: nil, metadata: {}, use: [], disable_body: false, &handler)
      @path = path
      @methods = Array(method || "*").map { |value| value.to_s.upcase }
      @body_schema = body_schema
      @query_schema = query_schema
      @params_schema = params_schema
      @headers_schema = headers_schema
      @metadata = metadata || {}
      apply_default_open_api_metadata!
      apply_open_api_defaults!
      apply_open_api_schemas!
      @options = endpoint_options
      @use = Array(use)
      @disable_body = !!disable_body
      @handler = handler || ->(_ctx) {}
    end

    def methods
      @methods.empty? ? ["*"] : @methods
    end

    def matches_method?(method)
      methods.include?("*") || methods.include?(method.to_s.upcase)
    end

    def call(context)
      use.each do |middleware|
        middleware_result = middleware.call(context)
        return Result.from_value(middleware_result, context) if middleware_result
      end

      apply_schemas!(context)
      Result.from_value(handler.call(context), context)
    end

    private

    def endpoint_options
      {
        method: (methods.length == 1) ? methods.first : methods,
        body: body_schema,
        query: query_schema,
        params: params_schema,
        headers: headers_schema,
        disableBody: disable_body,
        metadata: metadata
      }.compact
    end

    def apply_default_open_api_metadata!
      return unless path
      return if metadata[:openapi] || metadata[:hide] || metadata[:SERVER_ONLY] || metadata[:server_only]
      return unless defined?(BetterAuth::OpenAPI)

      metadata[:openapi] = BetterAuth::OpenAPI.default_metadata(path, methods)
    end

    def apply_open_api_defaults!
      return unless path
      return unless defined?(BetterAuth::OpenAPI)

      openapi = fetch_key(metadata, :openapi)
      return unless openapi.is_a?(Hash)

      defaults = BetterAuth::OpenAPI.default_metadata(path, methods)
      openapi[:operationId] = defaults[:operationId] if fetch_key(openapi, :operationId).to_s.empty?
      openapi[:description] = defaults[:description] if default_open_api_description?(fetch_key(openapi, :description))
      openapi[:parameters] = merge_open_api_parameters(defaults[:parameters], fetch_key(openapi, :parameters))
      openapi[:responses] = defaults[:responses].merge(fetch_key(openapi, :responses) || {})
      if request_body_method? && !fetch_key(openapi, :requestBody).is_a?(Hash)
        openapi[:requestBody] = defaults[:requestBody] || BetterAuth::OpenAPI.default_request_body
      end
    end

    def default_open_api_description?(description)
      methods.any? { |method| description.to_s == "#{method} #{path}" }
    end

    def request_body_method?
      methods.any? { |method| %w[POST PUT PATCH].include?(method) }
    end

    def merge_open_api_parameters(default_parameters, custom_parameters)
      merged = Array(custom_parameters).dup
      Array(default_parameters).each do |parameter|
        next if merged.any? { |entry| fetch_key(entry, :name).to_s == fetch_key(parameter, :name).to_s && fetch_key(entry, :in).to_s == fetch_key(parameter, :in).to_s }

        merged << parameter
      end
      merged
    end

    def apply_open_api_schemas!
      openapi = fetch_key(metadata, :openapi)
      return unless openapi.is_a?(Hash)

      @body_schema ||= schema_for_open_api_request_body(openapi)
      @query_schema ||= schema_for_open_api_parameters(openapi, "query")
      @headers_schema ||= schema_for_open_api_parameters(openapi, "header")
    end

    def apply_schemas!(context)
      context.body = validate_schema(:body, body_schema, context.body)
      context.query = validate_schema(:query, query_schema, context.query)
      context.params = validate_schema(:params, params_schema, context.params)
      context.headers = context.send(:normalize_headers, validate_schema(:headers, headers_schema, context.headers))
    end

    def validate_schema(_label, schema, value)
      return value unless schema

      parsed = parse_schema(schema, value)
      return value if parsed.nil?
      raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VALIDATION_ERROR"]) if parsed == false

      parsed
    rescue APIError
      raise
    rescue => error
      raise APIError.new("BAD_REQUEST", message: error.message.empty? ? BASE_ERROR_CODES["VALIDATION_ERROR"] : error.message)
    end

    def parse_schema(schema, value)
      if schema.respond_to?(:parse)
        schema.parse(value)
      elsif schema.respond_to?(:call)
        normalize_schema_result(schema.call(value))
      else
        value
      end
    end

    def normalize_schema_result(result)
      if result.respond_to?(:success?)
        return result.to_h if result.success? && result.respond_to?(:to_h)
        return false unless result.success?
      end

      result
    end

    def schema_for_open_api_request_body(openapi)
      schema = fetch_key(fetch_key(fetch_key(fetch_key(openapi, :requestBody), :content), "application/json"), :schema)
      required = Array(fetch_key(schema, :required)).map(&:to_s)
      return nil if required.empty?

      ->(value) { validate_required_open_api_fields(value, required) }
    end

    def schema_for_open_api_parameters(openapi, location)
      required = Array(fetch_key(openapi, :parameters))
        .select { |parameter| parameter.is_a?(Hash) && fetch_key(parameter, :in).to_s == location && fetch_key(parameter, :required) == true }
        .filter_map { |parameter| fetch_key(parameter, :name) }
        .map(&:to_s)
      return nil if required.empty?

      ->(value) { validate_required_open_api_fields(value, required) }
    end

    def validate_required_open_api_fields(value, required)
      data = normalize_open_api_input(value)
      return false unless required.all? { |key| data.key?(open_api_storage_key(key)) && !data[open_api_storage_key(key)].nil? }

      value
    end

    def normalize_open_api_input(value)
      return {} unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object_value), result|
        result[open_api_storage_key(key)] = object_value
      end
    end

    def open_api_storage_key(key)
      key.to_s
        .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
        .tr("-", "_")
        .downcase
        .split("_")
        .then { |parts| ([parts.first] + parts.drop(1).map(&:capitalize)).join }
    end

    def fetch_key(hash, key)
      return nil unless hash.respond_to?(:[])

      hash[key] || hash[key.to_s]
    end

    class Result
      attr_accessor :response, :status, :headers

      def initialize(response:, status: 200, headers: {}, raw_response: nil)
        @response = response
        @status = status
        @headers = normalize_headers(headers)
        @raw_response = raw_response
      end

      def self.from_value(value, context)
        return value if value.is_a?(self)

        if value.is_a?(APIError)
          return new(response: value, status: value.status_code, headers: merge_headers(context.response_headers, value.headers))
        end

        if rack_response?(value)
          return new(response: nil, status: value[0], headers: value[1], raw_response: value)
        end

        headers = context.response_headers.dup
        if value.is_a?(self)
          headers = merge_headers(headers, value.headers)
          return new(response: value.response, status: value.status, headers: headers)
        end

        new(response: value, status: context.status, headers: headers)
      end

      def self.rack_response?(value)
        value.is_a?(Array) && value.length == 3 && value[0].is_a?(Integer) && value[1].is_a?(Hash)
      end

      def self.merge_headers(base, extra)
        extra.each_with_object(base.dup) do |(key, value), result|
          normalized = key.to_s.downcase
          result[normalized] = if normalized == "set-cookie" && result[normalized]
            [result[normalized], value].join("\n")
          else
            value
          end
        end
      end

      def raw_response?
        !@raw_response.nil?
      end

      def to_rack_response
        to_response.to_a
      end

      def to_response
        return Response.from_rack(@raw_response) if raw_response?

        body = if response.nil?
          [JSON.generate(nil)]
        elsif response.is_a?(String)
          [response]
        else
          [JSON.generate(response)]
        end
        response_headers = {"content-type" => "application/json"}.merge(headers)
        Response.new(status: status, headers: response_headers, body: body)
      end

      private

      def normalize_headers(headers)
        headers.each_with_object({}) do |(key, value), result|
          result[key.to_s.downcase] = value
        end
      end
    end

    class Context
      attr_accessor :path,
        :method,
        :query,
        :body,
        :params,
        :headers,
        :raw_body,
        :context,
        :request,
        :status,
        :returned,
        :response_headers

      def initialize(path:, method:, query:, body:, params:, headers:, context:, request: nil, raw_body: nil)
        @path = path
        @method = method.to_s.upcase
        @query = query || {}
        @body = body || {}
        @params = params || {}
        @headers = normalize_headers(headers || {})
        @raw_body = raw_body
        @context = context
        @request = request
        @status = 200
        @response_headers = {}
        @returned = nil
      end

      def set_status(value)
        @status = value
      end

      def set_header(key, value)
        normalized = safe_header_name(key)
        safe_value = safe_header_value(value)
        response_headers[normalized] = if normalized == "set-cookie" && response_headers[normalized]
          [response_headers[normalized], safe_value].join("\n")
        else
          safe_value
        end
      end

      def set_cookie(name, value, options = {})
        attributes = cookie_attributes(options)
        cookie = (["#{name}=#{value}"] + attributes).join("; ")
        set_header("set-cookie", cookie)
      end

      def get_cookie(name)
        cookies[name.to_s]
      end

      def cookies
        BetterAuth::Cookies.parse_cookies(headers["cookie"])
      end

      def set_signed_cookie(name, value, secret, options = {})
        signature = BetterAuth::Crypto.hmac_signature(value, secret, encoding: :base64url)
        set_cookie(name, "#{value}.#{signature}", options)
      end

      def get_signed_cookie(name, secret)
        value = get_cookie(name)
        return nil unless value

        payload, signature = value.rpartition(".").values_at(0, 2)
        return nil if payload.empty? || signature.empty?

        BetterAuth::Crypto.verify_hmac_signature(payload, signature, secret, encoding: :base64url) ? payload : nil
      end

      def json(value, status: nil, headers: {})
        set_status(status) if status
        headers.each { |key, header_value| set_header(key, header_value) }
        Result.new(response: value, status: self.status, headers: response_headers)
      end

      def error(status, message: nil, headers: {})
        APIError.new(status, message: message, headers: headers)
      end

      def redirect(location, status: 302)
        code = (status == 302) ? "FOUND" : status
        APIError.new(code, message: "Redirect", headers: {"location" => location})
      end

      def merge_context!(data)
        data.each do |key, value|
          case key.to_sym
          when :query
            @query = deep_merge(query, value)
          when :body
            @body = deep_merge(body, value)
          when :params
            @params = deep_merge(params, value)
          when :headers
            @headers = normalize_headers(deep_merge(headers, value))
          else
            public_send("#{key}=", value) if respond_to?("#{key}=")
          end
        end
      end

      private

      def normalize_headers(value)
        value.each_with_object({}) do |(key, header_value), result|
          result[key.to_s.downcase.tr("_", "-")] = header_value
        end
      end

      def deep_merge(base, override)
        return override unless base.is_a?(Hash) && override.is_a?(Hash)

        base.merge(override) do |_key, old_value, new_value|
          if old_value.is_a?(Hash) && new_value.is_a?(Hash)
            deep_merge(old_value, new_value)
          else
            new_value
          end
        end
      end

      def safe_header_name(value)
        name = value.to_s.downcase
        raise APIError.new("INTERNAL_SERVER_ERROR", message: "Invalid header name") if name.match?(/[\r\n]/)

        name
      end

      def safe_header_value(value)
        header_value = value.to_s
        raise APIError.new("INTERNAL_SERVER_ERROR", message: "Invalid header value") if header_value.match?(/[\r\n]/)

        header_value
      end

      def cookie_attributes(options)
        options.compact.filter_map do |key, option_value|
          next if option_value == false

          name = cookie_attribute_name(key)
          if option_value == true
            name
          else
            "#{name}=#{cookie_attribute_value(key, option_value)}"
          end
        end
      end

      def cookie_attribute_name(key)
        case key.to_sym
        when :max_age then "Max-Age"
        when :http_only, :httponly then "HttpOnly"
        when :same_site, :samesite then "SameSite"
        else
          key.to_s.split("_").map(&:capitalize).join("-")
        end
      end

      def cookie_attribute_value(key, value)
        if [:same_site, :samesite].include?(key.to_sym)
          return value.to_s.capitalize
        end

        value
      end
    end
  end
end

# frozen_string_literal: true

require "json"
require "stringio"

module RackRateLimitHelpers
  def rack_json_env(method, path, body: {}, cookie: nil)
    payload = JSON.generate(body)
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(payload),
      "CONTENT_TYPE" => "application/json",
      "CONTENT_LENGTH" => payload.bytesize.to_s,
      "HTTP_COOKIE" => cookie,
      "HTTP_ORIGIN" => "http://localhost:3000"
    }.compact
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  class CustomRateLimitStorage
    attr_reader :data

    def initialize
      @data = {}
    end

    def get(key)
      data[key]
    end

    def set(key, value, ttl: nil, update: false)
      data[key] = value.merge(ttl: ttl, update: update)
    end
  end

  class SecondaryRateLimitStorage
    attr_reader :data, :ttls

    def initialize
      @data = {}
      @ttls = {}
    end

    def get(key)
      data[key]
    end

    def set(key, value, ttl)
      data[key] = value
      ttls[key] = ttl
    end

    def delete(key)
      data.delete(key)
      ttls.delete(key)
    end
  end
end

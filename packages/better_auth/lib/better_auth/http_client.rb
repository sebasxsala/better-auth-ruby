# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module BetterAuth
  module HTTPClient
    DEFAULT_OPEN_TIMEOUT = 5
    DEFAULT_READ_TIMEOUT = 5

    module_function

    def request(uri, request, open_timeout: DEFAULT_OPEN_TIMEOUT, read_timeout: DEFAULT_READ_TIMEOUT)
      Net::HTTP.start(
        uri.hostname || uri.host,
        uri.port,
        use_ssl: uri.scheme == "https",
        open_timeout: open_timeout,
        read_timeout: read_timeout
      ) do |http|
        http.request(request)
      end
    end

    def get_response(uri, headers = {})
      request = Net::HTTP::Get.new(uri)
      headers.each { |key, value| request[key.to_s] = value.to_s }
      request(uri, request)
    end

    def post_form(uri, form_body, headers = {})
      request = Net::HTTP::Post.new(uri)
      headers.each { |key, value| request[key.to_s] = value.to_s }
      request["Content-Type"] ||= "application/x-www-form-urlencoded"
      request.body = form_body
      request(uri, request)
    end

    def get_json(url, headers = {})
      uri = url.is_a?(URI) ? url : URI.parse(url.to_s)
      response = get_response(uri, headers)
      response.is_a?(Net::HTTPSuccess) ? JSON.parse(response.body.to_s) : nil
    end
  end
end

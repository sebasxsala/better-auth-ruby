# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthHTTPClientTest < Minitest::Test
  def test_request_applies_default_open_and_read_timeouts
    uri = URI.parse("https://provider.example/token")
    request = Net::HTTP::Post.new(uri)
    options = nil
    response = Object.new
    http = Object.new
    http.define_singleton_method(:request) { |_request| response }

    Net::HTTP.stub(:start, ->(_host, _port, **kwargs, &block) {
      options = kwargs
      block.call(http)
    }) do
      assert_same response, BetterAuth::HTTPClient.request(uri, request)
    end

    assert_equal true, options.fetch(:use_ssl)
    assert_equal 5, options.fetch(:open_timeout)
    assert_equal 5, options.fetch(:read_timeout)
  end
end

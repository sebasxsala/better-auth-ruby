# frozen_string_literal: true

require "json"
require_relative "../../test_helper"
require_relative "support/rack_rate_limit_helpers"

class BetterAuthPluginsRateLimitMatrixTest < Minitest::Test
  include RackRateLimitHelpers

  SECRET = "plugin-rate-limit-secret-with-enough-entropy"

  def test_magic_link_rate_limit_uses_custom_storage
    storage = CustomRateLimitStorage.new
    auth = build_auth(
      rate_limit: {enabled: true, window: 60, max: 100, custom_storage: storage},
      plugins: [
        BetterAuth::Plugins.magic_link(
          rate_limit: {window: 60, max: 1},
          send_magic_link: ->(_data, _ctx = nil) {}
        )
      ]
    )

    first_status, = auth.call(rack_json_env("POST", "/api/auth/sign-in/magic-link", body: {email: "magic-rate@example.com"}))
    second_status, second_headers, second_body = auth.call(rack_json_env("POST", "/api/auth/sign-in/magic-link", body: {email: "magic-rate@example.com"}))

    assert_equal 200, first_status
    assert_equal 429, second_status
    assert_match(/\A\d+\z/, second_headers.fetch("x-retry-after"))
    assert_equal({"message" => "Too many requests. Please try again later."}, JSON.parse(second_body.join))
    assert_equal ["127.0.0.1|/sign-in/magic-link"], storage.data.keys
    assert_equal 60, storage.data.fetch("127.0.0.1|/sign-in/magic-link").fetch(:ttl)
  end

  def test_phone_number_rate_limit_uses_secondary_storage_with_upstream_window
    storage = SecondaryRateLimitStorage.new
    auth = build_auth(
      secondary_storage: storage,
      rate_limit: {enabled: true, window: 60, max: 100, storage: "secondary-storage"},
      plugins: [
        BetterAuth::Plugins.phone_number(send_otp: ->(_data, _ctx = nil) {})
      ]
    )

    statuses = 11.times.map do |index|
      auth.call(rack_json_env("POST", "/api/auth/phone-number/send-otp", body: {phoneNumber: "+14155550#{100 + index}"})).first
    end

    assert_equal [200] * 10 + [429], statuses
    stored = JSON.parse(storage.data.fetch("127.0.0.1|/phone-number/send-otp"))
    assert_equal 10, stored.fetch("count")
    assert_equal 60, storage.ttls.fetch("127.0.0.1|/phone-number/send-otp")
  end

  def test_two_factor_rate_limit_uses_database_storage
    auth = build_auth(
      rate_limit: {enabled: true, window: 60, max: 100, storage: "database"},
      plugins: [BetterAuth::Plugins.two_factor]
    )
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "two-factor-rate@example.com", password: "password123", name: "Rate"},
      as_response: true
    )
    cookie = cookie_header(headers.fetch("set-cookie"))

    statuses = 4.times.map do
      auth.call(rack_json_env("POST", "/api/auth/two-factor/enable", body: {password: "wrong-password"}, cookie: cookie)).first
    end

    assert_equal [400, 400, 400, 429], statuses
    stored = auth.context.adapter.find_one(model: "rateLimit", where: [{field: "key", value: "127.0.0.1|/two-factor/enable"}])
    assert_equal 3, stored.fetch("count")
    assert_kind_of Integer, stored.fetch("lastRequest")
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true}
    }.merge(options))
  end
end

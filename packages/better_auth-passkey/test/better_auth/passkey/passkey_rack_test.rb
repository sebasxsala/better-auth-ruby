# frozen_string_literal: true

require "json"
require "rack/mock_request"
require_relative "support"

class BetterAuthPasskeyRackTest < Minitest::Test
  include BetterAuthPasskeyTestSupport

  def test_pre_auth_registration_options_set_cookie_and_store_context_over_rack
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false,
            resolve_user: ->(data) { {id: "rack-user", name: data.fetch(:context), display_name: "Rack User"} }
          }
        )
      ]
    )

    response = Rack::MockRequest.new(auth).get("/api/auth/passkey/generate-register-options?context=rack-context")
    body = JSON.parse(response.body)
    verification = auth.context.adapter.find_many(model: "verification").last
    stored = JSON.parse(verification.fetch("value"))

    assert_equal 200, response.status
    assert_includes response["set-cookie"], "better-auth-passkey"
    assert_equal "rack-context", body.fetch("user").fetch("name")
    assert_equal "Rack User", body.fetch("user").fetch("displayName")
    assert_equal "rack-context", stored.fetch("context")
    assert_equal "rack-user", stored.fetch("userData").fetch("id")
  end
end

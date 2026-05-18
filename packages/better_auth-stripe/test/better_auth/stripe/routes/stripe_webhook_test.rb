# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthStripeRoutesStripeWebhookTest < Minitest::Test
  def test_endpoint_matches_upstream_path_and_method
    endpoint = BetterAuth::Stripe::Routes::StripeWebhook.endpoint({})

    assert_equal "/stripe/webhook", endpoint.path
    assert_equal ["POST"], endpoint.methods
    assert_equal true, endpoint.metadata.fetch(:hide)
  end
end

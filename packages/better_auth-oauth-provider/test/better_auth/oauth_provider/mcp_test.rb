# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderMcpTest < Minitest::Test
  def test_www_authenticate_points_to_protected_resource_metadata
    header = BetterAuth::Plugins::OAuthProvider::MCP.www_authenticate(
      ["http://localhost:5000", "http://localhost:5000/resource1"]
    )

    assert_equal(
      'Bearer resource_metadata="http://localhost:5000/.well-known/oauth-protected-resource", Bearer resource_metadata="http://localhost:5000/.well-known/oauth-protected-resource/resource1"',
      header
    )
  end

  def test_handle_mcp_errors_adds_www_authenticate_header
    error = BetterAuth::APIError.new("UNAUTHORIZED", message: "missing authorization header")

    wrapped = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins::OAuthProvider::MCP.handle_mcp_errors(error, "urn:api", resource_metadata_mappings: {"urn:api" => "https://api.example/.well-known/oauth-protected-resource"})
    end

    assert_equal 401, wrapped.status_code
    assert_equal 'Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource"', wrapped.headers["www-authenticate"]
  end

  def test_mcp_handler_normalizes_verifier_decode_errors_to_challenge
    request = Struct.new(:headers).new({"authorization" => "Bearer bad-token"})
    handler = BetterAuth::Plugins::OAuthProvider::MCP.mcp_handler(
      resource: "urn:api",
      resource_metadata_mappings: {"urn:api" => "https://api.example/.well-known/oauth-protected-resource"},
      verifier: ->(_token) { raise JWT::DecodeError, "bad token" }
    ) { |_request, jwt| jwt }

    wrapped = assert_raises(BetterAuth::APIError) { handler.call(request) }

    assert_equal 401, wrapped.status_code
    assert_equal 'Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource"', wrapped.headers["www-authenticate"]
  end
end

# frozen_string_literal: true

require "base64"
require "json"
require "rack/mock"
require_relative "../test_helper"

module SCIMTestHelper
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def build_auth(options = nil, plugins: nil, **kwargs)
    options = (options || {}).merge(kwargs)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: plugins || [BetterAuth::Plugins.scim(options)]
    )
  end

  def sign_up_cookie(auth, email = "owner@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def bearer(token)
    {"authorization" => "Bearer " + token}
  end

  def token_without_organization(token)
    token_parts = Base64.urlsafe_decode64(token).split(":")
    Base64.urlsafe_encode64(token_parts[0, 2].join(":"), padding: false)
  end
end

# frozen_string_literal: true

require "openauth"
require "better_auth/oauth_provider"

module OpenAuth
  OAuthProvider = BetterAuth::OAuthProvider unless const_defined?(:OAuthProvider, false)
end

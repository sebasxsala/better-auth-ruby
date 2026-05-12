# frozen_string_literal: true

require "openauth"
require "better_auth/api_key"

module OpenAuth
  APIKey = BetterAuth::APIKey unless const_defined?(:APIKey, false)
end

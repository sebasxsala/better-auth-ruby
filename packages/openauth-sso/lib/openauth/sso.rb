# frozen_string_literal: true

require "openauth"
require "better_auth/sso"

module OpenAuth
  SSO = BetterAuth::SSO unless const_defined?(:SSO, false)
end

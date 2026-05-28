# frozen_string_literal: true

require "openauth"
require "better_auth/oidc"

module OpenAuth
  OIDC = BetterAuth::SSO::OIDC unless const_defined?(:OIDC, false)
  alias_better_auth_constants!
end

# frozen_string_literal: true

require "openauth"
require "better_auth/saml"

module OpenAuth
  SAML = BetterAuth::SSO::SAML unless const_defined?(:SAML, false)
  alias_better_auth_constants!
end

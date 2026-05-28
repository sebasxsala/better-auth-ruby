# frozen_string_literal: true

require "better_auth"
require "better_auth/oidc"
require_relative "sso/version"
require_relative "sso/load"
require_relative "sso/client"
require_relative "sso/types"
require_relative "plugins/sso"
require_relative "sso/utils"
require_relative "sso/domain_verification"
require_relative "sso/linking"
require_relative "sso/linking/types"
require_relative "sso/linking/org_assignment"
require_relative "sso/routes/helpers"
require_relative "sso/routes/providers"
require_relative "sso/routes/schemas"
require_relative "sso/routes/domain_verification"
require_relative "sso/routes/sso"
BetterAuth::SSO.load_saml! if BetterAuth::SSO.eager_load_saml?

module BetterAuth
  module SSO
  end
end

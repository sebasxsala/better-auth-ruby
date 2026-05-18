# frozen_string_literal: true

require "openauth"
require "better_auth/roda"

module OpenAuth
  Roda = BetterAuth::Roda unless const_defined?(:Roda, false)
  alias_better_auth_constants!
end

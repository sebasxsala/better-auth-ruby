# frozen_string_literal: true

require "openauth"
require "better_auth/passkey"

module OpenAuth
  Passkey = BetterAuth::Passkey unless const_defined?(:Passkey, false)
end

# frozen_string_literal: true

require "openauth"
require "better_auth/hanami"

module OpenAuth
  Hanami = BetterAuth::Hanami unless const_defined?(:Hanami, false)
end

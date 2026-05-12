# frozen_string_literal: true

require "openauth"
require "better_auth/rails"

module OpenAuth
  Rails = BetterAuth::Rails unless const_defined?(:Rails, false)
end

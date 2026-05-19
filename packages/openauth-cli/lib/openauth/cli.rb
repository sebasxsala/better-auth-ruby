# frozen_string_literal: true

require "better_auth/cli"

module OpenAuth
  CLI = BetterAuth::CLI unless const_defined?(:CLI, false)
end

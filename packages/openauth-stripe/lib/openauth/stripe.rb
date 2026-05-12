# frozen_string_literal: true

require "openauth"
require "better_auth/stripe"

module OpenAuth
  Stripe = BetterAuth::Stripe unless const_defined?(:Stripe, false)
end

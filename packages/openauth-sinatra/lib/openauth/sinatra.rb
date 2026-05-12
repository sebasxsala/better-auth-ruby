# frozen_string_literal: true

require "openauth"
require "better_auth/sinatra"

module OpenAuth
  Sinatra = BetterAuth::Sinatra unless const_defined?(:Sinatra, false)
end

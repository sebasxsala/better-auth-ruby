# frozen_string_literal: true

require "openauth"
require "better_auth/mongo_adapter"

module OpenAuth
  MongoAdapter = BetterAuth::MongoAdapter unless const_defined?(:MongoAdapter, false)
  MongoDB = BetterAuth::MongoAdapter unless const_defined?(:MongoDB, false)
end

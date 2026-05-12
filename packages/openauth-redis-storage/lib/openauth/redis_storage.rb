# frozen_string_literal: true

require "openauth"
require "better_auth/redis_storage"

module OpenAuth
  RedisStorage = BetterAuth::RedisStorage unless const_defined?(:RedisStorage, false)
end

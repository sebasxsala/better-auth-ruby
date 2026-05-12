# frozen_string_literal: true

require "better_auth"

module OpenAuth
  VERSION = BetterAuth::VERSION unless const_defined?(:VERSION, false)

  def self.auth(...)
    BetterAuth.auth(...)
  end

  def self.const_missing(name)
    BetterAuth.const_get(name)
  rescue NameError
    super
  end
end

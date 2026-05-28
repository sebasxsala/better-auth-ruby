# frozen_string_literal: true

module BetterAuth
  module SSO
    module OIDC
      class DiscoveryError < StandardError
        attr_reader :code, :details

        def initialize(code, message, details: {})
          @code = code
          @details = details
          super(message)
        end
      end

      module Errors
        module_function

        def api_error(error)
          return error if error.is_a?(APIError)

          APIError.new("BAD_REQUEST", message: error.message)
        end
      end
    end
  end
end

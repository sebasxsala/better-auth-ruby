# frozen_string_literal: true

require_relative "oidc/discovery"
require_relative "oidc/errors"

module BetterAuth
  module SSO
    module OIDC
      module_function

      def discover_config(**kwargs)
        Discovery.discover_oidc_config(**kwargs)
      end

      def needs_runtime_discovery?(oidc_config)
        Discovery.needs_runtime_discovery?(oidc_config)
      end
    end
  end
end

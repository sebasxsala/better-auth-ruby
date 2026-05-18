# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def scim_parse_filter(filter)
      match = filter.to_s.match(/\A\s*([^\s]+)\s+(eq|ne|co|sw|ew|pr)\s*(?:"([^"]*)"|([^\s]+))?\s*\z/i)
      raise scim_error("BAD_REQUEST", "Invalid filter expression", scim_type: "invalidFilter") unless match

      field = match[1]
      operator = match[2].downcase
      value = match[3] || match[4]
      raise scim_error("BAD_REQUEST", "Invalid filter expression", scim_type: "invalidFilter") if value.nil?
      raise scim_error("BAD_REQUEST", "The operator \"#{operator}\" is not supported", scim_type: "invalidFilter") unless operator == "eq"
      raise scim_error("BAD_REQUEST", "The attribute \"#{field}\" is not supported", scim_type: "invalidFilter") unless field == "userName"

      [field, value]
    end
  end
end

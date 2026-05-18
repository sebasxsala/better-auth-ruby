# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    SCIM_MAX_PATCH_OPERATIONS = 100
    SCIM_MAX_PATCH_VALUE_DEPTH = 5

    def scim_validate_user_body!(body)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) unless body[:user_name].is_a?(String)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body[:user_name].empty?
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body.key?(:external_id) && !body[:external_id].is_a?(String)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body.key?(:name) && !body[:name].is_a?(Hash)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body.key?(:emails) && !body[:emails].is_a?(Array)
      normalize_hash(body[:name] || {}).each_value do |value|
        raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) unless value.is_a?(String)
      end

      Array(body[:emails]).each do |email|
        email = normalize_hash(email)
        value = email[:value]
        raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if email.key?(:primary) && ![true, false].include?(email[:primary])
        raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) unless value.to_s.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
      end
    end

    def scim_validate_patch_body!(body)
      schemas = Array(body[:schemas])
      raise scim_error("BAD_REQUEST", "Invalid schemas for PatchOp") unless schemas.include?("urn:ietf:params:scim:api:messages:2.0:PatchOp")

      operations = body[:operations]
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) unless operations.is_a?(Array)
      raise scim_error("BAD_REQUEST", "Too many SCIM patch operations") if operations.length > SCIM_MAX_PATCH_OPERATIONS

      operations.each_with_index do |operation, index|
        normalized = normalize_hash(operation)
        op = normalized[:op]
        next if op.nil? || op.to_s.empty?

        unless op.is_a?(String)
          raise scim_patch_validation_error("[body.Operations.#{index}.op] Invalid input: expected string")
        end

        next if %w[replace add remove].include?(op.downcase)

        raise scim_patch_validation_error("[body.Operations.#{index}.op] Invalid option: expected one of \"replace\"|\"add\"|\"remove\"")
      end

      operations.each { |operation| scim_validate_patch_value_depth!(normalize_hash(operation)[:value]) }
    end

    def scim_validate_patch_value_depth!(value, depth = 0)
      return unless value.is_a?(Hash)
      raise scim_error("BAD_REQUEST", "SCIM patch value is too deeply nested") if depth > SCIM_MAX_PATCH_VALUE_DEPTH

      value.each_value { |nested| scim_validate_patch_value_depth!(nested, depth + 1) }
    end

    def scim_patch_validation_error(message)
      scim_error("BAD_REQUEST", message)
    end
  end
end

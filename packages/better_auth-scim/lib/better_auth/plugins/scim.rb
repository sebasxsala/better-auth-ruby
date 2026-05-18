# frozen_string_literal: true

require_relative "../scim/version"
require_relative "../scim/scim_metadata"
require_relative "../scim/scim_error"
require_relative "../scim/utils"
require_relative "../scim/client"
require_relative "../scim/user_schemas"
require_relative "../scim/scim_resources"
require_relative "../scim/mappings"
require_relative "../scim/scim_filters"
require_relative "../scim/patch_operations"
require_relative "../scim/scim_tokens"
require_relative "../scim/middlewares"
require_relative "../scim/provider_management"
require_relative "../scim/validation"
require_relative "../scim/routes"

module BetterAuth
  module Plugins
    module_function

    remove_method :scim if method_defined?(:scim) || private_method_defined?(:scim)
    singleton_class.remove_method(:scim) if singleton_class.method_defined?(:scim) || singleton_class.private_method_defined?(:scim)

    def scim(options = {})
      config = {store_scim_token: "hashed", provider_ownership: {enabled: true}}.merge(normalize_hash(options))
      Plugin.new(
        id: "scim",
        version: BetterAuth::SCIM::VERSION,
        client: scim_client,
        schema: scim_schema(config),
        endpoints: {
          generate_scim_token: scim_generate_token_endpoint(config),
          list_scim_provider_connections: scim_list_provider_connections_endpoint(config),
          get_scim_provider_connection: scim_get_provider_connection_endpoint(config),
          delete_scim_provider_connection: scim_delete_provider_connection_endpoint(config),
          create_scim_user: scim_create_user_endpoint(config),
          update_scim_user: scim_update_user_endpoint(config),
          patch_scim_user: scim_patch_user_endpoint(config),
          delete_scim_user: scim_delete_user_endpoint(config),
          list_scim_users: scim_list_users_endpoint(config),
          get_scim_user: scim_get_user_endpoint(config),
          get_scim_service_provider_config: scim_service_provider_config_endpoint,
          get_scim_schemas: scim_schemas_endpoint,
          get_scim_schema: scim_schema_endpoint,
          get_scim_resource_types: scim_resource_types_endpoint,
          get_scim_resource_type: scim_resource_type_endpoint
        },
        options: config
      )
    end

    def scim_schema(config = {})
      scim_provider_fields = {
        providerId: {type: "string", required: true, unique: true},
        scimToken: {type: "string", required: true, unique: true},
        organizationId: {type: "string", required: false}
      }
      scim_provider_fields[:userId] = {type: "string", required: false} if scim_provider_ownership_enabled?(config)

      {
        scimProvider: {
          fields: scim_provider_fields
        }
      }
    end
  end
end

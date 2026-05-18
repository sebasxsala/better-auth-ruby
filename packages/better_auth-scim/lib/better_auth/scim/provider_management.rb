# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def scim_has_organization_plugin?(ctx)
      Array(ctx.context.options.plugins).any? { |plugin| plugin.id == "organization" }
    end

    def scim_organization_plugin(ctx)
      Array(ctx.context.options.plugins).find { |plugin| plugin.id == "organization" }
    end

    def scim_required_roles(ctx, config)
      configured = config[:required_role] || config[:required_roles]
      return Array(configured).map(&:to_s) if configured

      creator_role = scim_organization_plugin(ctx)&.options&.fetch(:creator_role, nil)
      ["admin", creator_role || "owner"].uniq
    end

    def scim_provider_ownership_enabled?(config)
      normalize_hash(config[:provider_ownership] || {})[:enabled] == true
    end

    def scim_find_organization_member(ctx, user_id, organization_id)
      ctx.context.adapter.find_one(
        model: "member",
        where: [
          {field: "userId", value: user_id},
          {field: "organizationId", value: organization_id}
        ]
      )
    end

    def scim_parse_roles(role)
      Array(role).flat_map { |entry| entry.to_s.split(",") }.map(&:strip).reject(&:empty?)
    end

    def scim_has_required_role?(role, required_roles)
      required = Array(required_roles).map(&:to_s)
      required.empty? || scim_parse_roles(role).any? { |candidate| required.include?(candidate) }
    end

    def scim_user_org_memberships(ctx, user_id)
      ctx.context.adapter.find_many(model: "member", where: [{field: "userId", value: user_id}]).each_with_object({}) do |member, result|
        result[member.fetch("organizationId")] = member
      end
    end

    def scim_assert_provider_access!(ctx, user_id, provider, required_roles, config = {})
      return unless provider

      organization_id = provider["organizationId"]
      if organization_id
        raise APIError.new("FORBIDDEN", message: "Organization plugin is required to access this SCIM provider") unless scim_has_organization_plugin?(ctx)

        member = scim_find_organization_member(ctx, user_id, organization_id)
        raise APIError.new("FORBIDDEN", message: "You must be a member of the organization to access this provider") unless member
        raise APIError.new("FORBIDDEN", message: "Insufficient role for this operation") unless scim_has_required_role?(member.fetch("role", ""), required_roles)
      elsif scim_provider_ownership_enabled?(config)
        raise APIError.new("FORBIDDEN", message: "You must be the owner to access this provider") unless provider["userId"] == user_id
      elsif provider.key?("userId") && provider["userId"] && provider["userId"] != user_id
        raise APIError.new("FORBIDDEN", message: "You must be the owner to access this provider")
      end
    end

    def scim_provider_by_provider_id!(ctx, provider_id)
      raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VALIDATION_ERROR"]) unless provider_id.is_a?(String)

      provider = ctx.context.adapter.find_one(model: "scimProvider", where: [{field: "providerId", value: provider_id.to_s}])
      raise APIError.new("NOT_FOUND", message: "SCIM provider not found") unless provider

      provider
    end

    def scim_provider_id_query(ctx)
      ctx.query[:providerId] || ctx.query[:provider_id] || ctx.query["providerId"] || ctx.query["provider_id"]
    end

    def scim_normalized_provider(provider)
      {
        id: provider.fetch("id"),
        providerId: provider.fetch("providerId"),
        organizationId: provider["organizationId"]
      }
    end

    def scim_call_token_hook(callback, payload)
      callback.call(payload) if callback.respond_to?(:call)
    end

    def scim_create_org_membership(ctx, user_id, organization_id)
      return unless organization_id
      return if ctx.context.adapter.find_one(model: "member", where: [{field: "organizationId", value: organization_id}, {field: "userId", value: user_id}])

      ctx.context.adapter.create(model: "member", data: {userId: user_id, organizationId: organization_id, role: "member", createdAt: Time.now})
    end
  end
end

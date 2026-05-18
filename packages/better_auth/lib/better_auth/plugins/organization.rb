# frozen_string_literal: true

require "json"

module BetterAuth
  module Plugins
    ORGANIZATION_ERROR_CODES = {
      "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION" => "You are not allowed to create a new organization",
      "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS" => "You have reached the maximum number of organizations",
      "ORGANIZATION_ALREADY_EXISTS" => "Organization already exists",
      "ORGANIZATION_SLUG_ALREADY_TAKEN" => "Organization slug already taken",
      "ORGANIZATION_NOT_FOUND" => "Organization not found",
      "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION" => "User is not a member of the organization",
      "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION" => "You are not allowed to update this organization",
      "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION" => "You are not allowed to delete this organization",
      "NO_ACTIVE_ORGANIZATION" => "No active organization",
      "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION" => "User is already a member of this organization",
      "MEMBER_NOT_FOUND" => "Member not found",
      "ROLE_NOT_FOUND" => "Role not found",
      "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM" => "You are not allowed to create a new team",
      "TEAM_ALREADY_EXISTS" => "Team already exists",
      "TEAM_NOT_FOUND" => "Team not found",
      "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER" => "You cannot leave the organization as the only owner",
      "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER" => "You cannot leave the organization without an owner",
      "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER" => "You are not allowed to delete this member",
      "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION" => "You are not allowed to invite users to this organization",
      "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION" => "User is already invited to this organization",
      "INVITATION_NOT_FOUND" => "Invitation not found",
      "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION" => "You are not the recipient of the invitation",
      "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION" => "Email verification required before accepting or rejecting invitation",
      "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION" => "You are not allowed to cancel this invitation",
      "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION" => "Inviter is no longer a member of the organization",
      "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE" => "You are not allowed to invite a user with this role",
      "FAILED_TO_RETRIEVE_INVITATION" => "Failed to retrieve invitation",
      "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS" => "You have reached the maximum number of teams",
      "UNABLE_TO_REMOVE_LAST_TEAM" => "Unable to remove last team",
      "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER" => "You are not allowed to update this member",
      "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED" => "Organization membership limit reached",
      "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION" => "You are not allowed to create teams in this organization",
      "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION" => "You are not allowed to delete teams in this organization",
      "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM" => "You are not allowed to update this team",
      "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM" => "You are not allowed to delete this team",
      "INVITATION_LIMIT_REACHED" => "Invitation limit reached",
      "TEAM_MEMBER_LIMIT_REACHED" => "Team member limit reached",
      "USER_IS_NOT_A_MEMBER_OF_THE_TEAM" => "User is not a member of the team",
      "YOU_CAN_NOT_ACCESS_THE_MEMBERS_OF_THIS_TEAM" => "You are not allowed to list the members of this team",
      "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM" => "You do not have an active team",
      "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER" => "You are not allowed to create a new member",
      "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER" => "You are not allowed to remove a team member",
      "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION" => "You are not allowed to access this organization as an owner",
      "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION" => "You are not a member of this organization",
      "MISSING_AC_INSTANCE" => "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information",
      "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE" => "You must be in an organization to create a role",
      "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE" => "You are not allowed to create a role",
      "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE" => "You are not allowed to update a role",
      "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE" => "You are not allowed to delete a role",
      "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE" => "You are not allowed to read a role",
      "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE" => "You are not allowed to list a role",
      "YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE" => "You are not allowed to get a role",
      "TOO_MANY_ROLES" => "This organization has too many roles",
      "INVALID_RESOURCE" => "The provided permission includes an invalid resource",
      "ROLE_NAME_IS_ALREADY_TAKEN" => "That role name is already taken",
      "CANNOT_DELETE_A_PRE_DEFINED_ROLE" => "Cannot delete a pre-defined role",
      "ROLE_IS_ASSIGNED_TO_MEMBERS" => "Cannot delete a role that is assigned to members. Please reassign the members to a different role first"
    }.freeze

    ORGANIZATION_DEFAULT_STATEMENTS = {
      organization: ["update", "delete"],
      member: ["create", "update", "delete"],
      invitation: ["create", "cancel"],
      team: ["create", "update", "delete"],
      ac: ["create", "read", "update", "delete"]
    }.freeze

    module_function

    def organization(options = {})
      config = organization_config(options)
      endpoints = {
        create_organization: organization_create_endpoint(config),
        update_organization: organization_update_endpoint(config),
        delete_organization: organization_delete_endpoint(config),
        check_organization_slug: organization_check_slug_endpoint,
        set_active_organization: organization_set_active_endpoint,
        get_full_organization: organization_get_full_endpoint(config),
        list_organizations: organization_list_endpoint,
        create_invitation: organization_invite_endpoint(config),
        cancel_invitation: organization_cancel_invitation_endpoint(config),
        accept_invitation: organization_accept_invitation_endpoint(config),
        reject_invitation: organization_reject_invitation_endpoint(config),
        get_invitation: organization_get_invitation_endpoint,
        list_invitations: organization_list_invitations_endpoint(config),
        list_user_invitations: organization_list_user_invitations_endpoint,
        add_member: organization_add_member_endpoint(config),
        remove_member: organization_remove_member_endpoint(config),
        update_member_role: organization_update_member_role_endpoint(config),
        get_active_member: organization_get_active_member_endpoint(config),
        leave_organization: organization_leave_endpoint(config),
        list_members: organization_list_members_endpoint(config),
        get_active_member_role: organization_get_active_member_role_endpoint(config),
        has_permission: organization_has_permission_endpoint(config)
      }

      if org_truthy?(config.dig(:teams, :enabled))
        endpoints.merge!(
          create_team: organization_create_team_endpoint(config),
          remove_team: organization_remove_team_endpoint(config),
          update_team: organization_update_team_endpoint(config),
          list_organization_teams: organization_list_teams_endpoint(config),
          set_active_team: organization_set_active_team_endpoint(config),
          list_user_teams: organization_list_user_teams_endpoint,
          list_team_members: organization_list_team_members_endpoint(config),
          add_team_member: organization_add_team_member_endpoint(config),
          remove_team_member: organization_remove_team_member_endpoint(config)
        )
      end

      if org_truthy?(config.dig(:dynamic_access_control, :enabled))
        endpoints.merge!(
          create_org_role: organization_create_role_endpoint(config),
          delete_org_role: organization_delete_role_endpoint(config),
          list_org_roles: organization_list_roles_endpoint(config),
          get_org_role: organization_get_role_endpoint(config),
          update_org_role: organization_update_role_endpoint(config)
        )
      end

      Plugin.new(
        id: "organization",
        schema: OrganizationSchema.build(config),
        endpoints: endpoints,
        error_codes: ORGANIZATION_ERROR_CODES,
        options: config
      )
    end

    def organization_config(options)
      config = normalize_hash(options)
      config[:allow_user_to_create_organization] = true unless config.key?(:allow_user_to_create_organization)
      config[:creator_role] ||= "owner"
      config[:membership_limit] ||= 100
      config[:invitation_expires_in] ||= 60 * 60 * 48
      config[:invitation_limit] ||= 100
      config[:ac] ||= create_access_control(ORGANIZATION_DEFAULT_STATEMENTS)
      config[:roles] ||= organization_default_roles(config)
      config
    end

    def organization_default_roles(config = {})
      ac = config[:ac] || create_access_control(ORGANIZATION_DEFAULT_STATEMENTS)
      {
        "admin" => ac.new_role(organization: ["update"], invitation: ["create", "cancel"], member: ["create", "update", "delete"], team: ["create", "update", "delete"], ac: ["create", "read", "update", "delete"]),
        "owner" => ac.new_role(organization: ["update", "delete"], member: ["create", "update", "delete"], invitation: ["create", "cancel"], team: ["create", "update", "delete"], ac: ["create", "read", "update", "delete"]),
        "member" => ac.new_role(organization: [], member: [], invitation: [], team: [], ac: ["read"])
      }
    end

    def organization_create_endpoint(config)
      Endpoint.new(path: "/organization/create", method: "POST", metadata: organization_openapi("createOrganization", "Create an organization", response: organization_ref_schema("Organization"))) do |ctx|
        body = normalize_hash(ctx.body)
        session = Routes.current_session(ctx, allow_nil: true)
        user = session ? session[:user] : ctx.context.internal_adapter.find_user_by_id(body[:user_id])
        raise APIError.new("UNAUTHORIZED") unless user
        name = body[:name].to_s
        slug = body[:slug].to_s
        raise APIError.new("BAD_REQUEST", message: "name is required") if name.empty?
        raise APIError.new("BAD_REQUEST", message: "slug is required") if slug.empty?

        allowed = config[:allow_user_to_create_organization]
        allowed = allowed.call(user) if allowed.respond_to?(:call)
        raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION")) unless allowed

        if config[:organization_limit]
          limit_reached = config[:organization_limit].respond_to?(:call) ? config[:organization_limit].call(user) : organization_created_count(ctx, user["id"]) >= config[:organization_limit].to_i
          raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS")) if limit_reached
        end

        if organization_by_slug(ctx, slug)
          raise APIError.new("CONFLICT", message: ORGANIZATION_ERROR_CODES.fetch("ORGANIZATION_ALREADY_EXISTS"))
        end

        data = {
          name: name,
          slug: slug,
          logo: body[:logo],
          metadata: serialize_metadata(body[:metadata]),
          createdAt: Time.now
        }.merge(additional_input(body, :name, :slug, :logo, :metadata, :keep_current_active_organization, :user_id))
        merge_hook_data!(data, run_org_hook(config, :before_create_organization, {organization: data, user: user}, ctx))
        organization = ctx.context.adapter.create(model: "organization", data: data, force_allow_id: true)
        member_data = {organizationId: organization["id"], userId: user["id"], role: config[:creator_role], createdAt: Time.now}
        merge_hook_data!(member_data, run_org_hook(config, :before_add_member, {member: member_data, user: user, organization: organization_wire(ctx, organization)}, ctx))
        member = ctx.context.adapter.create(model: "member", data: member_data)
        run_org_hook(config, :after_add_member, {member: member_wire(ctx, member), user: user, organization: organization_wire(ctx, organization)}, ctx)
        default_team = create_default_team(ctx, config, organization, {user: user}) if org_truthy?(config.dig(:teams, :enabled)) && config.dig(:teams, :default_team, :enabled) != false
        run_org_hook(config, :after_create_organization, {organization: organization_wire(ctx, organization), member: member, user: user}, ctx)
        if session && !org_truthy?(body[:keep_current_active_organization])
          update = {activeOrganizationId: organization["id"], activeTeamId: default_team && default_team["id"]}
          updated_session = ctx.context.internal_adapter.update_session(session[:session]["token"], update)
          Cookies.set_session_cookie(ctx, {session: updated_session || session[:session].merge(update.transform_keys(&:to_s)), user: user})
        end
        ctx.json(organization_wire(ctx, organization).merge(members: [member_wire(ctx, member)]))
      end
    end

    def organization_check_slug_endpoint
      Endpoint.new(path: "/organization/check-slug", method: "POST", metadata: organization_openapi("checkOrganizationSlug", "Check if an organization slug is available", response: OpenAPI.status_response_schema)) do |ctx|
        Routes.request_only_session(ctx)
        slug = normalize_hash(ctx.body)[:slug].to_s
        if slug.empty? || organization_by_slug(ctx, slug)
          raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ORGANIZATION_SLUG_ALREADY_TAKEN"))
        end
        ctx.json({status: true})
      end
    end

    def organization_list_endpoint
      Endpoint.new(path: "/organization/list", method: "GET", metadata: organization_openapi("listOrganizations", "List organizations", response: organization_array_schema("Organization"))) do |ctx|
        session = Routes.current_session(ctx)
        members = ctx.context.adapter.find_many(model: "member", where: [{field: "userId", value: session[:user]["id"]}])
        organizations = members.filter_map { |member| organization_by_id(ctx, member["organizationId"]) }
        ctx.json(organizations.map { |entry| organization_wire(ctx, entry) })
      end
    end

    def organization_update_endpoint(config)
      Endpoint.new(path: "/organization/update", method: "POST", metadata: organization_openapi("updateOrganization", "Update an organization", response: organization_ref_schema("Organization"))) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        id = body[:organization_id] || body[:organizationId]
        data = normalize_hash(body[:data] || body)
        organization = organization_by_id(ctx, id) || organization_by_slug(ctx, body[:organization_slug])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ORGANIZATION_NOT_FOUND")) unless organization
        require_org_permission!(ctx, config, session, organization["id"], {organization: ["update"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION"))
        if data[:slug] && data[:slug].to_s.empty?
          raise APIError.new("BAD_REQUEST", message: "slug is required")
        end
        if data[:name] && data[:name].to_s.empty?
          raise APIError.new("BAD_REQUEST", message: "name is required")
        end
        existing = data[:slug] ? organization_by_slug(ctx, data[:slug]) : nil
        raise APIError.new("CONFLICT", message: ORGANIZATION_ERROR_CODES.fetch("ORGANIZATION_SLUG_ALREADY_TAKEN")) if existing && existing["id"] != organization["id"]
        update = additional_input(data, :organization_id, :organizationId, :organization_slug, :data)
        update[:metadata] = serialize_metadata(update[:metadata]) if update.key?(:metadata)
        updated = ctx.context.adapter.update(model: "organization", where: [{field: "id", value: organization["id"]}], update: update)
        run_org_hook(config, :after_update_organization, {organization: organization_wire(ctx, updated), user: session[:user]}, ctx)
        ctx.json(organization_wire(ctx, updated))
      end
    end

    def organization_delete_endpoint(config)
      Endpoint.new(path: "/organization/delete", method: "POST", metadata: organization_openapi("deleteOrganization", "Delete an organization", response: OpenAPI.status_response_schema)) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        organization = organization_by_id(ctx, body[:organization_id]) || organization_by_slug(ctx, body[:organization_slug])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ORGANIZATION_NOT_FOUND")) unless organization
        require_org_permission!(ctx, config, session, organization["id"], {organization: ["delete"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION"))
        run_org_hook(config, :before_delete_organization, {organization: organization_wire(ctx, organization), user: session[:user]}, ctx)
        if org_truthy?(config.dig(:teams, :enabled))
          team_ids = ctx.context.adapter.find_many(model: "team", where: [{field: "organizationId", value: organization["id"]}]).map { |team| team["id"] }
          ctx.context.adapter.delete_many(model: "teamMember", where: [{field: "teamId", value: team_ids, operator: "in"}]) if team_ids.any?
          ctx.context.adapter.delete_many(model: "team", where: [{field: "organizationId", value: organization["id"]}])
        end
        ctx.context.adapter.delete_many(model: "invitation", where: [{field: "organizationId", value: organization["id"]}])
        ctx.context.adapter.delete_many(model: "member", where: [{field: "organizationId", value: organization["id"]}])
        ctx.context.adapter.delete_many(model: "organizationRole", where: [{field: "organizationId", value: organization["id"]}]) if org_truthy?(config.dig(:dynamic_access_control, :enabled))
        ctx.context.adapter.delete(model: "organization", where: [{field: "id", value: organization["id"]}])
        ctx.json({status: true})
      end
    end

    def organization_set_active_endpoint
      Endpoint.new(path: "/organization/set-active", method: "POST", metadata: organization_openapi("setActiveOrganization", "Set the active organization", response: organization_nullable_schema("Organization"))) do |ctx|
        session = Routes.current_session(ctx, sensitive: true)
        body = normalize_hash(ctx.body)
        if body.key?(:organization_id) && body[:organization_id].nil?
          updated_session = ctx.context.internal_adapter.update_session(session[:session]["token"], {activeOrganizationId: nil, activeTeamId: nil})
          Cookies.set_session_cookie(ctx, {session: updated_session || session[:session].merge("activeOrganizationId" => nil, "activeTeamId" => nil), user: session[:user]})
          next ctx.json(nil)
        end

        organization = organization_by_id(ctx, body[:organization_id]) || organization_by_slug(ctx, body[:organization_slug])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ORGANIZATION_NOT_FOUND")) unless organization
        require_member!(ctx, session[:user]["id"], organization["id"])
        updated_session = ctx.context.internal_adapter.update_session(session[:session]["token"], {activeOrganizationId: organization["id"], activeTeamId: nil})
        Cookies.set_session_cookie(ctx, {session: updated_session || session[:session].merge("activeOrganizationId" => organization["id"], "activeTeamId" => nil), user: session[:user]})
        ctx.json(organization_wire(ctx, organization))
      end
    end

    def organization_get_full_endpoint(config)
      Endpoint.new(path: "/organization/get-full-organization", method: "GET", metadata: organization_openapi("getOrganization", "Get the full organization", response: organization_nullable_schema("Organization"))) do |ctx|
        session = Routes.current_session(ctx)
        query = normalize_hash(ctx.query)
        explicit_lookup = query.key?(:organization_slug) || query.key?(:organization_id)
        organization = organization_by_slug(ctx, query[:organization_slug]) || organization_by_id(ctx, query[:organization_id] || session[:session]["activeOrganizationId"])
        unless organization
          raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ORGANIZATION_NOT_FOUND")) if explicit_lookup

          next ctx.json(nil)
        end

        require_member!(ctx, session[:user]["id"], organization["id"])
        members = list_members_for(ctx, organization["id"], {limit: query[:members_limit] || config[:membership_limit]})
        invitations = ctx.context.adapter.find_many(model: "invitation", where: [{field: "organizationId", value: organization["id"]}])
        result = organization_wire(ctx, organization).merge(
          members: members.fetch(:members),
          invitations: invitations.map { |entry| invitation_wire(ctx, entry) }
        )
        if org_truthy?(config.dig(:teams, :enabled))
          teams = ctx.context.adapter.find_many(model: "team", where: [{field: "organizationId", value: organization["id"]}])
          result[:teams] = teams.map { |team| team_wire(ctx, team) }
        end
        ctx.json(result)
      end
    end

    def organization_invite_endpoint(config)
      Endpoint.new(path: "/organization/invite-member", method: "POST", metadata: organization_openapi("createOrganizationInvitation", "Create an organization invitation", response: organization_ref_schema("Invitation"))) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        organization = organization_by_id(ctx, body[:organization_id] || session[:session]["activeOrganizationId"]) || organization_by_slug(ctx, body[:organization_slug])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ORGANIZATION_NOT_FOUND")) unless organization
        require_org_permission!(ctx, config, session, organization["id"], {invitation: ["create"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION"))
        email = body[:email].to_s.downcase
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES.fetch("INVALID_EMAIL")) unless Routes::EMAIL_PATTERN.match?(email)
        role = parse_roles(body[:role] || "member")
        role.split(",").each do |entry|
          unless organization_roles(config).key?(entry) || organization_role_by_name(ctx, organization["id"], entry)
            raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ROLE_NOT_FOUND"))
          end
        end
        existing_member = find_member_by_email(ctx, organization["id"], email)
        raise APIError.new("CONFLICT", message: ORGANIZATION_ERROR_CODES.fetch("USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION")) if existing_member
        pending = ctx.context.adapter.find_many(model: "invitation", where: [{field: "organizationId", value: organization["id"]}, {field: "email", value: email}, {field: "status", value: "pending"}])
        if pending.any?
          if config[:cancel_pending_invitations_on_re_invite]
            pending.each { |entry| ctx.context.adapter.update(model: "invitation", where: [{field: "id", value: entry["id"]}], update: {status: "canceled"}) }
          else
            raise APIError.new("CONFLICT", message: ORGANIZATION_ERROR_CODES.fetch("USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION"))
          end
        end
        pending_count = ctx.context.adapter.count(model: "invitation", where: [{field: "organizationId", value: organization["id"]}, {field: "status", value: "pending"}])
        limit = config[:invitation_limit]
        if limit && pending_count >= limit.to_i
          raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("INVITATION_LIMIT_REACHED"))
        end
        team_ids = organization_team_ids(body[:team_id] || body[:team_ids])
        ensure_team_member_capacity!(ctx, config, team_ids)
        invitation_data = {
          organizationId: organization["id"],
          email: email,
          role: role,
          status: "pending",
          expiresAt: Time.now + config[:invitation_expires_in].to_i,
          inviterId: session[:user]["id"],
          teamId: team_ids.any? ? team_ids.join(",") : nil,
          createdAt: Time.now
        }.merge(additional_input(body, :organization_id, :organization_slug, :email, :role, :team_id, :team_ids))
        merge_hook_data!(invitation_data, run_org_hook(config, :before_create_invitation, {invitation: invitation_data, inviter: session[:user], organization: organization_wire(ctx, organization)}, ctx))
        invitation = ctx.context.adapter.create(
          model: "invitation",
          data: invitation_data,
          force_allow_id: true
        )
        sender = config[:send_invitation_email]
        sender.call({id: invitation["id"], role: role, email: email, organization: organization_wire(ctx, organization), invitation: invitation_wire(ctx, invitation), inviter: require_member!(ctx, session[:user]["id"], organization["id"])}, ctx.request) if sender.respond_to?(:call)
        run_org_hook(config, :after_create_invitation, {invitation: invitation_wire(ctx, invitation), inviter: session[:user], organization: organization_wire(ctx, organization)}, ctx)
        ctx.json(invitation_wire(ctx, invitation))
      end
    end

    def organization_accept_invitation_endpoint(config)
      Endpoint.new(path: "/organization/accept-invitation", method: "POST", metadata: organization_openapi("acceptOrganizationInvitation", "Accept an organization invitation", response: organization_accept_invitation_schema)) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        invitation = invitation_by_id(ctx, body[:invitation_id] || body[:id])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("INVITATION_NOT_FOUND")) unless invitation
        raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION")) unless invitation["email"].to_s.downcase == session[:user]["email"].to_s.downcase
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("INVITATION_NOT_FOUND")) unless invitation["status"] == "pending"
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("INVITATION_NOT_FOUND")) if invitation["expiresAt"] && Time.parse(invitation["expiresAt"].to_s) < Time.now
        if config[:require_email_verification_on_invitation] && !session[:user]["emailVerified"]
          raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION"))
        end
        ensure_team_member_capacity!(ctx, config, organization_team_ids(invitation["teamId"]))
        member = ctx.context.adapter.create(model: "member", data: {organizationId: invitation["organizationId"], userId: session[:user]["id"], role: invitation["role"], createdAt: Time.now})
        organization_team_ids(invitation["teamId"]).each do |team_id|
          ctx.context.adapter.create(model: "teamMember", data: {teamId: team_id, userId: session[:user]["id"], createdAt: Time.now})
        end
        updated = ctx.context.adapter.update(model: "invitation", where: [{field: "id", value: invitation["id"]}], update: {status: "accepted"})
        organization = organization_by_id(ctx, invitation["organizationId"])
        run_org_hook(config, :after_accept_invitation, {invitation: invitation_wire(ctx, updated), member: member_wire(ctx, member), user: session[:user], organization: organization_wire(ctx, organization)}, ctx)
        ctx.json({invitation: invitation_wire(ctx, updated), member: member_wire(ctx, member)})
      end
    end

    def organization_reject_invitation_endpoint(_config)
      Endpoint.new(path: "/organization/reject-invitation", method: "POST", metadata: organization_openapi("rejectOrganizationInvitation", "Reject an organization invitation", response: organization_ref_schema("Invitation"))) do |ctx|
        session = Routes.current_session(ctx)
        invitation = invitation_by_id(ctx, normalize_hash(ctx.body)[:invitation_id])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("INVITATION_NOT_FOUND")) unless invitation
        raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION")) unless invitation["email"].to_s.downcase == session[:user]["email"].to_s.downcase
        updated = ctx.context.adapter.update(model: "invitation", where: [{field: "id", value: invitation["id"]}], update: {status: "rejected"})
        ctx.json(invitation_wire(ctx, updated))
      end
    end

    def organization_cancel_invitation_endpoint(config)
      Endpoint.new(path: "/organization/cancel-invitation", method: "POST", metadata: organization_openapi("cancelOrganizationInvitation", "Cancel an organization invitation", response: organization_ref_schema("Invitation"))) do |ctx|
        session = Routes.current_session(ctx)
        invitation = invitation_by_id(ctx, normalize_hash(ctx.body)[:invitation_id])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("INVITATION_NOT_FOUND")) unless invitation
        require_org_permission!(ctx, config, session, invitation["organizationId"], {invitation: ["cancel"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION"))
        updated = ctx.context.adapter.update(model: "invitation", where: [{field: "id", value: invitation["id"]}], update: {status: "canceled"})
        ctx.json(invitation_wire(ctx, updated))
      end
    end

    def organization_get_invitation_endpoint
      Endpoint.new(path: "/organization/get-invitation", method: "GET", metadata: organization_openapi("getOrganizationInvitation", "Get an organization invitation", response: organization_ref_schema("Invitation"))) do |ctx|
        invitation = invitation_by_id(ctx, normalize_hash(ctx.query)[:id] || normalize_hash(ctx.query)[:invitation_id])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("INVITATION_NOT_FOUND")) unless invitation
        ctx.json(invitation_wire(ctx, invitation))
      end
    end

    def organization_list_invitations_endpoint(config)
      Endpoint.new(path: "/organization/list-invitations", method: "GET", metadata: organization_openapi("listOrganizationInvitations", "List organization invitations", response: organization_array_schema("Invitation"))) do |ctx|
        session = Routes.current_session(ctx)
        organization_id = normalize_hash(ctx.query)[:organization_id] || session[:session]["activeOrganizationId"]
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("NO_ACTIVE_ORGANIZATION")) unless organization_id
        require_org_permission!(ctx, config, session, organization_id, {invitation: ["create"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION"))
        invitations = ctx.context.adapter.find_many(model: "invitation", where: [{field: "organizationId", value: organization_id}])
        ctx.json(invitations.map { |entry| invitation_wire(ctx, entry) })
      end
    end

    def organization_list_user_invitations_endpoint
      Endpoint.new(path: "/organization/list-user-invitations", method: "GET", metadata: organization_openapi("listUserInvitations", "List user invitations", response: organization_array_schema("Invitation"))) do |ctx|
        session = Routes.current_session(ctx)
        invitations = ctx.context.adapter.find_many(model: "invitation", where: [{field: "email", value: session[:user]["email"].to_s.downcase}, {field: "status", value: "pending"}])
        ctx.json(invitations.map { |entry| invitation_wire(ctx, entry) })
      end
    end

    def organization_add_member_endpoint(config)
      Endpoint.new(path: "/organization/add-member", method: "POST", metadata: organization_openapi("addOrganizationMember", "Add an organization member", response: organization_ref_schema("Member"))) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        organization_id = body[:organization_id]
        require_org_permission!(ctx, config, session, organization_id, {member: ["create"]}, ORGANIZATION_ERROR_CODES.fetch("ORGANIZATION_MEMBERSHIP_LIMIT_REACHED"))
        user_id = body[:user_id].to_s
        raise APIError.new("BAD_REQUEST", message: "userId is required") if user_id.empty?
        if require_member(ctx, user_id, organization_id)
          raise APIError.new("CONFLICT", message: ORGANIZATION_ERROR_CODES.fetch("USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION"))
        end
        organization = organization_by_id(ctx, organization_id)
        user = ctx.context.internal_adapter.find_user_by_id(user_id)
        member_data = {organizationId: organization_id, userId: user_id, role: parse_roles(body[:role] || "member"), createdAt: Time.now}.merge(additional_input(body, :organization_id, :user_id, :role))
        merge_hook_data!(member_data, run_org_hook(config, :before_add_member, {member: member_data, user: user, organization: organization_wire(ctx, organization)}, ctx))
        member = ctx.context.adapter.create(model: "member", data: member_data)
        run_org_hook(config, :after_add_member, {member: member_wire(ctx, member), user: user, organization: organization_wire(ctx, organization)}, ctx)
        ctx.json(member_wire(ctx, member))
      end
    end

    def organization_remove_member_endpoint(config)
      Endpoint.new(path: "/organization/remove-member", method: "POST", metadata: organization_openapi("removeOrganizationMember", "Remove an organization member", response: OpenAPI.status_response_schema)) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        member = member_by_id(ctx, body[:member_id]) || require_member(ctx, body[:user_id], body[:organization_id])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("MEMBER_NOT_FOUND")) unless member
        require_org_permission!(ctx, config, session, member["organizationId"], {member: ["delete"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER"))
        ensure_not_last_owner!(ctx, member)
        organization = organization_by_id(ctx, member["organizationId"])
        user = ctx.context.internal_adapter.find_user_by_id(member["userId"])
        ctx.context.adapter.delete(model: "member", where: [{field: "id", value: member["id"]}])
        ctx.context.adapter.delete_many(model: "teamMember", where: [{field: "userId", value: member["userId"]}]) if org_truthy?(config.dig(:teams, :enabled))
        run_org_hook(config, :after_remove_member, {member: member_wire(ctx, member), user: user, organization: organization_wire(ctx, organization)}, ctx)
        ctx.json({status: true})
      end
    end

    def organization_update_member_role_endpoint(config)
      Endpoint.new(path: "/organization/update-member-role", method: "POST", metadata: organization_openapi("updateOrganizationMemberRole", "Update an organization member role", response: organization_ref_schema("Member"))) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        member = member_by_id(ctx, body[:member_id]) || require_member(ctx, body[:user_id], body[:organization_id])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("MEMBER_NOT_FOUND")) unless member
        require_org_permission!(ctx, config, session, member["organizationId"], {member: ["update"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER"))
        updated = ctx.context.adapter.update(model: "member", where: [{field: "id", value: member["id"]}], update: {role: parse_roles(body[:role])})
        ctx.json(member_wire(ctx, updated))
      end
    end

    def organization_get_active_member_endpoint(_config)
      Endpoint.new(path: "/organization/get-active-member", method: "GET", metadata: organization_openapi("getActiveOrganizationMember", "Get the active organization member", response: organization_ref_schema("Member"))) do |ctx|
        session = Routes.current_session(ctx)
        organization_id = normalize_hash(ctx.query)[:organization_id] || session[:session]["activeOrganizationId"]
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("NO_ACTIVE_ORGANIZATION")) unless organization_id
        member = require_member!(ctx, session[:user]["id"], organization_id)
        ctx.json(member_wire(ctx, member))
      end
    end

    def organization_get_active_member_role_endpoint(_config)
      Endpoint.new(path: "/organization/get-active-member-role", method: "GET", metadata: organization_openapi("getActiveOrganizationMemberRole", "Get the active organization member role", response: organization_active_member_role_schema)) do |ctx|
        session = Routes.current_session(ctx)
        query = normalize_hash(ctx.query)
        organization_id = query[:organization_id] || session[:session]["activeOrganizationId"]
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("NO_ACTIVE_ORGANIZATION")) unless organization_id
        require_member!(ctx, session[:user]["id"], organization_id)
        member = require_member!(ctx, query[:user_id] || session[:user]["id"], organization_id)
        ctx.json({role: member["role"], member: member_wire(ctx, member)})
      end
    end

    def organization_leave_endpoint(config)
      Endpoint.new(path: "/organization/leave", method: "POST", metadata: organization_openapi("leaveOrganization", "Leave an organization", response: OpenAPI.status_response_schema)) do |ctx|
        session = Routes.current_session(ctx)
        organization_id = normalize_hash(ctx.body)[:organization_id]
        member = require_member!(ctx, session[:user]["id"], organization_id)
        ensure_not_last_owner!(ctx, member)
        ctx.context.adapter.delete(model: "member", where: [{field: "id", value: member["id"]}])
        ctx.context.adapter.delete_many(model: "teamMember", where: [{field: "userId", value: session[:user]["id"]}]) if org_truthy?(config.dig(:teams, :enabled))
        ctx.json({status: true})
      end
    end

    def organization_list_members_endpoint(config)
      Endpoint.new(path: "/organization/list-members", method: "GET", metadata: organization_openapi("listOrganizationMembers", "List organization members", response: organization_members_response_schema)) do |ctx|
        session = Routes.current_session(ctx)
        query = normalize_hash(ctx.query)
        organization_id = query[:organization_id] || organization_by_slug(ctx, query[:organization_slug])&.fetch("id") || session[:session]["activeOrganizationId"]
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("NO_ACTIVE_ORGANIZATION")) unless organization_id
        require_member!(ctx, session[:user]["id"], organization_id)
        ctx.json(list_members_for(ctx, organization_id, query, config, session[:user]))
      end
    end

    def organization_has_permission_endpoint(config)
      Endpoint.new(path: "/organization/has-permission", method: "POST", metadata: organization_openapi("hasOrganizationPermission", "Check if the member has organization permission", response: organization_permission_response_schema)) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        organization_id = body[:organization_id] || session[:session]["activeOrganizationId"]
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("NO_ACTIVE_ORGANIZATION")) unless organization_id
        member = require_member!(ctx, session[:user]["id"], organization_id)
        permissions = body[:permissions] || body[:permission]
        ctx.json({error: nil, success: organization_permission?(ctx, config, member["role"], permissions, organization_id)})
      end
    end

    def organization_create_team_endpoint(config)
      Endpoint.new(path: "/organization/create-team", method: "POST", metadata: organization_openapi("createOrganizationTeam", "Create an organization team", response: organization_ref_schema("Team"))) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        organization_id = body[:organization_id] || session[:session]["activeOrganizationId"]
        require_org_permission!(ctx, config, session, organization_id, {team: ["create"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION"))
        organization = organization_by_id(ctx, organization_id)
        max_teams = config.dig(:teams, :maximum_teams)
        if max_teams && ctx.context.adapter.count(model: "team", where: [{field: "organizationId", value: organization_id}]) >= max_teams.to_i
          raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS"))
        end
        team_data = {organizationId: organization_id, name: body[:name].to_s, createdAt: Time.now}.merge(additional_input(body, :organization_id, :name))
        merge_hook_data!(team_data, run_org_hook(config, :before_create_team, {team: team_data, user: session[:user], organization: organization_wire(ctx, organization)}, ctx))
        team = ctx.context.adapter.create(model: "team", data: team_data, force_allow_id: true)
        ctx.context.adapter.create(model: "teamMember", data: {teamId: team["id"], userId: session[:user]["id"], createdAt: Time.now})
        run_org_hook(config, :after_create_team, {team: team_wire(ctx, team), user: session[:user], organization: organization_wire(ctx, organization)}, ctx)
        ctx.json(team_wire(ctx, team))
      end
    end

    def organization_list_teams_endpoint(_config)
      Endpoint.new(path: "/organization/list-teams", method: "GET", metadata: organization_openapi("listOrganizationTeams", "List organization teams", response: organization_array_schema("Team"))) do |ctx|
        session = Routes.current_session(ctx)
        organization_id = normalize_hash(ctx.query)[:organization_id] || session[:session]["activeOrganizationId"]
        require_member!(ctx, session[:user]["id"], organization_id)
        teams = ctx.context.adapter.find_many(model: "team", where: [{field: "organizationId", value: organization_id}])
        ctx.json(teams.map { |team| team_wire(ctx, team) })
      end
    end

    def organization_update_team_endpoint(config)
      Endpoint.new(path: "/organization/update-team", method: "POST", metadata: organization_openapi("updateOrganizationTeam", "Update an organization team", response: organization_ref_schema("Team"))) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        team = team_by_id(ctx, body[:team_id])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("TEAM_NOT_FOUND")) unless team
        require_org_permission!(ctx, config, session, team["organizationId"], {team: ["update"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM"))
        updated = ctx.context.adapter.update(model: "team", where: [{field: "id", value: team["id"]}], update: additional_input(body, :team_id, :organization_id))
        ctx.json(team_wire(ctx, updated))
      end
    end

    def organization_remove_team_endpoint(config)
      Endpoint.new(path: "/organization/remove-team", method: "POST", metadata: organization_openapi("removeOrganizationTeam", "Remove an organization team", response: OpenAPI.status_response_schema)) do |ctx|
        session = Routes.current_session(ctx)
        team = team_by_id(ctx, normalize_hash(ctx.body)[:team_id])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("TEAM_NOT_FOUND")) unless team
        require_org_permission!(ctx, config, session, team["organizationId"], {team: ["delete"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM"))
        teams = ctx.context.adapter.find_many(model: "team", where: [{field: "organizationId", value: team["organizationId"]}])
        if teams.length <= 1 && config.dig(:teams, :allow_removing_all_teams) != true
          raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("UNABLE_TO_REMOVE_LAST_TEAM"))
        end
        ctx.context.adapter.delete_many(model: "teamMember", where: [{field: "teamId", value: team["id"]}])
        ctx.context.adapter.delete(model: "team", where: [{field: "id", value: team["id"]}])
        ctx.json({status: true})
      end
    end

    def organization_set_active_team_endpoint(_config)
      Endpoint.new(path: "/organization/set-active-team", method: "POST", metadata: organization_openapi("setActiveOrganizationTeam", "Set the active organization team", response: organization_nullable_schema("Team"))) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        if body.key?(:team_id) && body[:team_id].nil?
          updated_session = ctx.context.internal_adapter.update_session(session[:session]["token"], {activeTeamId: nil})
          Cookies.set_session_cookie(ctx, {session: updated_session || session[:session].merge("activeTeamId" => nil), user: session[:user]})
          next ctx.json({status: true})
        end
        team = team_by_id(ctx, body[:team_id])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("TEAM_NOT_FOUND")) unless team
        require_team_member!(ctx, session[:user]["id"], team["id"])
        updated_session = ctx.context.internal_adapter.update_session(session[:session]["token"], {activeOrganizationId: team["organizationId"], activeTeamId: team["id"]})
        Cookies.set_session_cookie(ctx, {session: updated_session || session[:session].merge("activeOrganizationId" => team["organizationId"], "activeTeamId" => team["id"]), user: session[:user]})
        ctx.json(team_wire(ctx, team))
      end
    end

    def organization_list_user_teams_endpoint
      Endpoint.new(path: "/organization/list-user-teams", method: "GET", metadata: organization_openapi("listUserTeams", "List user teams", response: organization_array_schema("Team"))) do |ctx|
        session = Routes.current_session(ctx)
        memberships = ctx.context.adapter.find_many(model: "teamMember", where: [{field: "userId", value: session[:user]["id"]}])
        ctx.json(memberships.filter_map { |entry| team_by_id(ctx, entry["teamId"]) }.map { |team| team_wire(ctx, team) })
      end
    end

    def organization_list_team_members_endpoint(_config)
      Endpoint.new(path: "/organization/list-team-members", method: "GET", metadata: organization_openapi("listTeamMembers", "List team members", response: organization_array_schema("TeamMember"))) do |ctx|
        session = Routes.current_session(ctx)
        team_id = normalize_hash(ctx.query)[:team_id] || session[:session]["activeTeamId"]
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM")) unless team_id
        team = team_by_id(ctx, team_id)
        require_member!(ctx, session[:user]["id"], team["organizationId"])
        members = ctx.context.adapter.find_many(model: "teamMember", where: [{field: "teamId", value: team_id}])
        ctx.json(members.map { |entry| team_member_wire(ctx, entry) })
      end
    end

    def organization_add_team_member_endpoint(config)
      Endpoint.new(path: "/organization/add-team-member", method: "POST", metadata: organization_openapi("addTeamMember", "Add a team member", response: organization_ref_schema("TeamMember"))) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        team = team_by_id(ctx, body[:team_id])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("TEAM_NOT_FOUND")) unless team
        require_org_permission!(ctx, config, session, team["organizationId"], {team: ["update"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER"))
        user_id = body[:user_id].to_s
        require_member!(ctx, user_id, team["organizationId"])
        max_members = config.dig(:teams, :maximum_members_per_team)
        if max_members && ctx.context.adapter.count(model: "teamMember", where: [{field: "teamId", value: team["id"]}]) >= max_members.to_i
          raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("TEAM_MEMBER_LIMIT_REACHED"))
        end
        existing = ctx.context.adapter.find_one(model: "teamMember", where: [{field: "teamId", value: team["id"]}, {field: "userId", value: user_id}])
        next ctx.json(team_member_wire(ctx, existing)) if existing

        member = ctx.context.adapter.create(model: "teamMember", data: {teamId: team["id"], userId: user_id, createdAt: Time.now})
        ctx.json(team_member_wire(ctx, member))
      end
    end

    def organization_remove_team_member_endpoint(config)
      Endpoint.new(path: "/organization/remove-team-member", method: "POST", metadata: organization_openapi("removeTeamMember", "Remove a team member", response: OpenAPI.status_response_schema)) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        team = team_by_id(ctx, body[:team_id])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("TEAM_NOT_FOUND")) unless team
        require_org_permission!(ctx, config, session, team["organizationId"], {team: ["update"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER"))
        ctx.context.adapter.delete_many(model: "teamMember", where: [{field: "teamId", value: team["id"]}, {field: "userId", value: body[:user_id]}])
        ctx.json({status: true})
      end
    end

    def organization_create_role_endpoint(config)
      Endpoint.new(path: "/organization/create-role", method: "POST", metadata: organization_openapi("createOrganizationRole", "Create an organization role", response: organization_role_action_schema)) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        organization_id = body[:organization_id] || session[:session]["activeOrganizationId"]
        require_org_permission!(ctx, config, session, organization_id, {ac: ["create"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE"))
        role_name = (body[:role] || body[:role_name]).to_s
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ROLE_NAME_IS_ALREADY_TAKEN")) if organization_roles(config).key?(role_name) || organization_role_by_name(ctx, organization_id, role_name)
        permission = stringify_permission(body[:permission] || body[:permissions])
        validate_permission_resources!(config, permission)
        unless organization_permission?(ctx, config, require_member!(ctx, session[:user]["id"], organization_id)["role"], permission, organization_id)
          raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE"))
        end
        role = ctx.context.adapter.create(model: "organizationRole", data: {organizationId: organization_id, role: role_name, permission: JSON.generate(permission), createdAt: Time.now}.merge(additional_input(body, :organization_id, :role, :role_name, :permission, :permissions)))
        wired = organization_role_wire(role)
        ctx.json({success: true, roleData: wired, statements: (config[:ac] || create_access_control(ORGANIZATION_DEFAULT_STATEMENTS)).new_role(permission).statements})
      end
    end

    def organization_list_roles_endpoint(config)
      Endpoint.new(path: "/organization/list-roles", method: "GET", metadata: organization_openapi("listOrganizationRoles", "List organization roles", response: {type: "array", items: organization_role_schema})) do |ctx|
        session = Routes.current_session(ctx)
        organization_id = normalize_hash(ctx.query)[:organization_id] || session[:session]["activeOrganizationId"]
        require_org_permission!(ctx, config, session, organization_id, {ac: ["read"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE"))
        defaults = organization_roles(config).keys.map { |role| {"role" => role, "permission" => {}} }
        dynamic = ctx.context.adapter.find_many(model: "organizationRole", where: [{field: "organizationId", value: organization_id}]).map { |role| organization_role_wire(role) }
        ctx.json(defaults + dynamic)
      end
    end

    def organization_get_role_endpoint(config)
      Endpoint.new(path: "/organization/get-role", method: "GET", metadata: organization_openapi("getOrganizationRole", "Get an organization role", response: organization_role_schema)) do |ctx|
        session = Routes.current_session(ctx)
        query = normalize_hash(ctx.query)
        organization_id = query[:organization_id] || session[:session]["activeOrganizationId"]
        require_org_permission!(ctx, config, session, organization_id, {ac: ["read"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE"))
        role = organization_role_by_id(ctx, query[:role_id]) || organization_role_by_name(ctx, organization_id, query[:role])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ROLE_NOT_FOUND")) unless role
        ctx.json(organization_role_wire(role))
      end
    end

    def organization_update_role_endpoint(config)
      Endpoint.new(path: "/organization/update-role", method: "POST", metadata: organization_openapi("updateOrganizationRole", "Update an organization role", response: organization_role_action_schema)) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        organization_id = body[:organization_id] || session[:session]["activeOrganizationId"]
        require_org_permission!(ctx, config, session, organization_id, {ac: ["update"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE"))
        role = organization_role_by_id(ctx, body[:role_id]) || organization_role_by_name(ctx, organization_id, body[:role] || body[:role_name])
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ROLE_NOT_FOUND")) unless role
        update = {}
        update[:role] = body[:data][:role] || body[:data][:role_name] if body[:data].is_a?(Hash) && (body[:data][:role] || body[:data][:role_name])
        permission = body[:permission] || body[:permissions] || body.dig(:data, :permission) || body.dig(:data, :permissions)
        if permission
          permission = stringify_permission(permission)
          validate_permission_resources!(config, permission)
          unless organization_permission?(ctx, config, require_member!(ctx, session[:user]["id"], organization_id)["role"], permission, organization_id)
            raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE"))
          end
          update[:permission] = JSON.generate(permission)
        end
        update.merge!(additional_input(body[:data], :role, :role_name, :permission, :permissions)) if body[:data].is_a?(Hash)
        updated = ctx.context.adapter.update(model: "organizationRole", where: [{field: "id", value: role["id"]}], update: update)
        ctx.json({success: true, roleData: organization_role_wire(updated)})
      end
    end

    def organization_delete_role_endpoint(config)
      Endpoint.new(path: "/organization/delete-role", method: "POST", metadata: organization_openapi("deleteOrganizationRole", "Delete an organization role", response: OpenAPI.success_response_schema)) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        organization_id = body[:organization_id] || session[:session]["activeOrganizationId"]
        require_org_permission!(ctx, config, session, organization_id, {ac: ["delete"]}, ORGANIZATION_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE"))
        role_name = body[:role] || body[:role_name]
        if role_name && organization_roles(config).key?(role_name.to_s)
          raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("CANNOT_DELETE_A_PRE_DEFINED_ROLE"))
        end
        role = organization_role_by_id(ctx, body[:role_id]) || organization_role_by_name(ctx, organization_id, role_name)
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ROLE_NOT_FOUND")) unless role
        assigned = ctx.context.adapter.find_many(model: "member", where: [{field: "organizationId", value: organization_id}]).any? do |member|
          member["role"].to_s.split(",").map(&:strip).include?(role["role"])
        end
        raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("ROLE_IS_ASSIGNED_TO_MEMBERS")) if assigned
        ctx.context.adapter.delete(model: "organizationRole", where: [{field: "id", value: role["id"]}])
        ctx.json({success: true})
      end
    end

    def organization_openapi(operation_id, description, response:, response_description: "Success", request: nil, required: [], parameters: nil)
      openapi = {
        operationId: operation_id,
        description: description,
        responses: {
          "200" => OpenAPI.json_response(response_description, response)
        }
      }
      openapi[:requestBody] = OpenAPI.json_request_body(OpenAPI.object_schema(request, required: required)) if request
      openapi[:parameters] = parameters if parameters

      {openapi: openapi}
    end

    def organization_ref_schema(name)
      {
        type: "object",
        "$ref": "#/components/schemas/#{name}"
      }
    end

    def organization_nullable_schema(name)
      {
        type: ["object", "null"],
        "$ref": "#/components/schemas/#{name}"
      }
    end

    def organization_array_schema(name)
      {
        type: "array",
        items: organization_ref_schema(name)
      }
    end

    def organization_accept_invitation_schema
      OpenAPI.object_schema(
        {
          invitation: organization_ref_schema("Invitation"),
          member: organization_ref_schema("Member")
        },
        required: ["invitation", "member"]
      )
    end

    def organization_active_member_role_schema
      OpenAPI.object_schema(
        {
          role: {type: "string"},
          member: organization_ref_schema("Member")
        },
        required: ["role", "member"]
      )
    end

    def organization_members_response_schema
      OpenAPI.object_schema(
        {
          members: organization_array_schema("Member"),
          total: {type: "number"}
        },
        required: ["members", "total"]
      )
    end

    def organization_permission_response_schema
      OpenAPI.object_schema(
        {
          error: {type: ["string", "null"]},
          success: {type: "boolean"}
        },
        required: ["success"]
      )
    end

    def organization_role_schema
      OpenAPI.object_schema(
        {
          id: {type: "string"},
          organizationId: {type: "string"},
          role: {type: "string"},
          permission: {type: "object"}
        },
        required: ["role", "permission"]
      )
    end

    def organization_role_action_schema
      OpenAPI.object_schema(
        {
          success: {type: "boolean"},
          roleData: organization_role_schema,
          statements: {type: "object"}
        },
        required: ["success", "roleData"]
      )
    end

    def parse_roles(roles)
      Array(roles).join(",")
    end

    def organization_roles(config)
      (config[:roles] || organization_default_roles(config)).transform_keys(&:to_s)
    end

    def organization_permission?(ctx, config, role_string, permissions, organization_id)
      roles = organization_roles(config)
      if org_truthy?(config.dig(:dynamic_access_control, :enabled))
        ctx.context.adapter.find_many(model: "organizationRole", where: [{field: "organizationId", value: organization_id}]).each do |entry|
          permission = parse_permission(entry["permission"])
          if roles.key?(entry["role"])
            permission = merge_permissions(roles[entry["role"]].statements, permission)
          end
          roles[entry["role"]] = (config[:ac] || create_access_control(ORGANIZATION_DEFAULT_STATEMENTS)).new_role(permission)
        end
      end
      role_string.to_s.split(",").any? do |role|
        roles[role]&.authorize(permissions || {})&.fetch(:success, false)
      end
    end

    def require_org_permission!(ctx, config, session, organization_id, permissions, message)
      member = require_member!(ctx, session[:user]["id"], organization_id)
      return member if organization_permission?(ctx, config, member["role"], permissions, organization_id)

      raise APIError.new("FORBIDDEN", message: message)
    end

    def merge_permissions(base, extra)
      stringify_permission(base).merge(stringify_permission(extra)) do |_resource, base_actions, extra_actions|
        (Array(base_actions) + Array(extra_actions)).map(&:to_s).uniq
      end
    end

    def require_member!(ctx, user_id, organization_id)
      member = require_member(ctx, user_id, organization_id)
      raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")) unless member

      member
    end

    def require_member(ctx, user_id, organization_id)
      return nil if user_id.to_s.empty? || organization_id.to_s.empty?

      ctx.context.adapter.find_one(model: "member", where: [{field: "userId", value: user_id}, {field: "organizationId", value: organization_id}])
    end

    def require_team_member!(ctx, user_id, team_id)
      member = ctx.context.adapter.find_one(model: "teamMember", where: [{field: "userId", value: user_id}, {field: "teamId", value: team_id}])
      raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("USER_IS_NOT_A_MEMBER_OF_THE_TEAM")) unless member

      member
    end

    def member_by_id(ctx, id)
      return nil if id.to_s.empty?

      ctx.context.adapter.find_one(model: "member", where: [{field: "id", value: id}])
    end

    def find_member_by_email(ctx, organization_id, email)
      user = ctx.context.adapter.find_one(model: "user", where: [{field: "email", value: email.to_s.downcase}])
      user && require_member(ctx, user["id"], organization_id)
    end

    def organization_by_id(ctx, id)
      return nil if id.to_s.empty?

      ctx.context.adapter.find_one(model: "organization", where: [{field: "id", value: id}])
    end

    def organization_by_slug(ctx, slug)
      return nil if slug.to_s.empty?

      ctx.context.adapter.find_one(model: "organization", where: [{field: "slug", value: slug}])
    end

    def invitation_by_id(ctx, id)
      return nil if id.to_s.empty?

      ctx.context.adapter.find_one(model: "invitation", where: [{field: "id", value: id}])
    end

    def team_by_id(ctx, id)
      return nil if id.to_s.empty?

      ctx.context.adapter.find_one(model: "team", where: [{field: "id", value: id}])
    end

    def organization_role_by_id(ctx, id)
      return nil if id.to_s.empty?

      ctx.context.adapter.find_one(model: "organizationRole", where: [{field: "id", value: id}])
    end

    def organization_role_by_name(ctx, organization_id, role)
      return nil if role.to_s.empty?

      ctx.context.adapter.find_one(model: "organizationRole", where: [{field: "organizationId", value: organization_id}, {field: "role", value: role}])
    end

    def list_members_for(ctx, organization_id, query = {}, config = nil, user = nil)
      where = [{field: "organizationId", value: organization_id}]
      if query[:filter_field]
        where << {field: query[:filter_field], value: query[:filter_value], operator: query[:filter_operator]}
      elsif query[:filter].is_a?(Hash)
        filter = normalize_hash(query[:filter])
        where << {field: filter[:field], value: filter[:value], operator: filter[:operator]}
      end
      limit = member_list_limit(ctx, organization_id, query, config, user)
      members = ctx.context.adapter.find_many(
        model: "member",
        where: where,
        limit: limit,
        offset: query[:offset],
        sort_by: query[:sort_by] ? {field: query[:sort_by], direction: query[:sort_direction] || query[:sort_order] || "asc"} : nil
      )
      users_by_id = member_users_by_id(ctx, members)
      {
        members: members.map { |entry| member_wire(ctx, entry, users_by_id: users_by_id) },
        total: ctx.context.adapter.count(model: "member", where: where)
      }
    end

    def member_list_limit(ctx, organization_id, query, config, user)
      configured = config && config[:membership_limit]
      configured = 100 if configured.nil?
      default = numeric_member_limit(configured)
      default = 100 unless default.positive?
      requested = query[:limit].to_i if query.key?(:limit) && !query[:limit].to_s.empty?
      return default unless requested&.positive?

      [requested, default].min
    end

    def numeric_member_limit(value)
      return value.to_i if value.is_a?(Numeric)
      return value.to_i if value.to_s.match?(/\A\d+\z/)

      100
    end

    def member_users_by_id(ctx, members)
      user_ids = members.map { |member| member["userId"] }.compact.uniq
      return {} if user_ids.empty?

      ctx.context.adapter.find_many(model: "user", where: [{field: "id", operator: "in", value: user_ids}]).each_with_object({}) do |user, result|
        result[user["id"]] = user
      end
    end

    def ensure_team_member_capacity!(ctx, config, team_ids)
      max_members = config.dig(:teams, :maximum_members_per_team)
      return unless max_members && team_ids.any?

      team_ids.each do |team_id|
        count = ctx.context.adapter.count(model: "teamMember", where: [{field: "teamId", value: team_id}])
        if count >= max_members.to_i
          raise APIError.new("FORBIDDEN", message: ORGANIZATION_ERROR_CODES.fetch("TEAM_MEMBER_LIMIT_REACHED"))
        end
      end
    end

    def member_wire(ctx, member, users_by_id: nil)
      data = Schema.parse_output(ctx.context.options, "member", member)
      user = users_by_id ? users_by_id[member["userId"]] : ctx.context.internal_adapter.find_user_by_id(member["userId"])
      data["user"] = user.slice("id", "name", "email", "image") if user
      data
    end

    def organization_wire(ctx, organization)
      data = Schema.parse_output(ctx.context.options, "organization", organization)
      data["metadata"] = parse_metadata(data["metadata"]) if data&.key?("metadata")
      data
    end

    def invitation_wire(ctx, invitation)
      Schema.parse_output(ctx.context.options, "invitation", invitation)
    end

    def team_wire(ctx, team)
      Schema.parse_output(ctx.context.options, "team", team)
    end

    def team_member_wire(ctx, member)
      Schema.parse_output(ctx.context.options, "teamMember", member)
    end

    def organization_role_wire(role)
      role.merge("permission" => parse_permission(role["permission"]))
    end

    def ensure_not_last_owner!(ctx, member)
      return unless member["role"].to_s.split(",").include?("owner")

      owners = ctx.context.adapter.find_many(model: "member", where: [{field: "organizationId", value: member["organizationId"]}]).select { |entry| entry["role"].to_s.split(",").include?("owner") }
      raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")) if owners.length <= 1
    end

    def create_default_team(ctx, config, organization, session)
      custom = config.dig(:teams, :default_team, :custom_create_default_team)
      team_data = {organizationId: organization["id"], name: organization["name"], createdAt: Time.now}
      merge_hook_data!(team_data, run_org_hook(config, :before_create_team, {team: team_data, user: session[:user], organization: organization_wire(ctx, organization)}, ctx))
      team = if custom.respond_to?(:call)
        custom.call(organization_wire(ctx, organization), ctx)
      else
        ctx.context.adapter.create(model: "team", data: team_data, force_allow_id: true)
      end
      ctx.context.adapter.create(model: "teamMember", data: {teamId: team["id"], userId: session[:user]["id"], createdAt: Time.now})
      run_org_hook(config, :after_create_team, {team: team_wire(ctx, team), user: session[:user], organization: organization_wire(ctx, organization)}, ctx)
      team
    end

    def organization_created_count(ctx, user_id)
      members = ctx.context.adapter.find_many(model: "member", where: [{field: "userId", value: user_id}])
      members.count { |member| member["role"].to_s.split(",").include?("owner") }
    end

    def run_org_hook(config, key, data, ctx)
      hooks = [config.dig(:organization_hooks, key), config.dig(:hooks, key)]
      hooks.concat(ctx.context.options.plugins.filter_map { |plugin| plugin.dig(:options, :organization_hooks, key) || plugin.dig("options", "organizationHooks", key.to_s) }) if ctx&.context&.options
      hooks.compact.uniq.filter_map { |hook| hook.call(data, ctx) if hook.respond_to?(:call) }.find { |response| response.is_a?(Hash) && normalize_hash(response).key?(:data) }
    end

    def merge_hook_data!(target, response)
      data = if response.is_a?(Hash)
        normalize_hash(response)[:data]
      end
      target.merge!(normalize_hash(data)) if data.is_a?(Hash)
      target
    end

    def parse_metadata(value)
      return value if value.nil? || value.is_a?(Hash)

      JSON.parse(value)
    rescue JSON::ParserError
      value
    end

    def serialize_metadata(value)
      value.is_a?(Hash) ? JSON.generate(value) : value
    end

    def parse_permission(value)
      return value if value.is_a?(Hash)
      return {} if value.nil? || value.to_s.empty?

      JSON.parse(value)
    rescue JSON::ParserError
      {}
    end

    def stringify_permission(value)
      normalize_hash(value || {}).each_with_object({}) do |(resource, actions), result|
        result[resource.to_s] = Array(actions).map(&:to_s)
      end
    end

    def validate_permission_resources!(config, permission)
      valid = (config[:ac] || create_access_control(ORGANIZATION_DEFAULT_STATEMENTS)).statements.keys
      invalid = permission.keys - valid
      raise APIError.new("BAD_REQUEST", message: ORGANIZATION_ERROR_CODES.fetch("INVALID_RESOURCE")) if invalid.any?
    end

    def organization_team_ids(value)
      Array(value).flat_map { |entry| entry.to_s.split(",") }.map(&:strip).reject(&:empty?)
    end

    def additional_input(hash, *exclude)
      data = normalize_hash(hash)
      additional = normalize_hash(data.delete(:additional_fields))
      extra_input(data, *exclude, :additional_fields).merge(additional)
    end

    def extra_input(hash, *exclude)
      normalize_hash(hash).except(*exclude.map(&:to_sym))
    end

    def org_truthy?(value)
      value == true || value.to_s == "true"
    end
  end
end

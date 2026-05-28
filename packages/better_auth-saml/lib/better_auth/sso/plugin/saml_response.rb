# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def sso_handle_saml_response(ctx, config = {})
      provider = sso_find_saml_provider!(ctx, sso_fetch(ctx.params, :provider_id), config)
      relay_state = sso_fetch(ctx.body, :relay_state) || sso_fetch(ctx.query, :relay_state)
      state = sso_parse_saml_relay_state(ctx, relay_state) || {}
      raw_response = sso_fetch(ctx.body, :saml_response) || sso_fetch(ctx.query, :saml_response)
      if ctx.method == "GET" && raw_response.to_s.empty?
        session = Routes.current_session(ctx, allow_nil: true)
        unless session
          return sso_redirect(ctx, sso_append_error("#{ctx.context.base_url}/error", "invalid_request"))
        end

        return sso_redirect(ctx, sso_safe_saml_callback_url(ctx, relay_state || sso_saml_callback_url(provider) || "/", provider.fetch("providerId")))
      end
      max_response_size = config.dig(:saml, :max_response_size) || SSO_DEFAULT_MAX_SAML_RESPONSE_SIZE
      if raw_response.to_s.bytesize > max_response_size
        raise APIError.new("BAD_REQUEST", message: "SAML response exceeds maximum allowed size (#{max_response_size} bytes)")
      end
      in_response_to_result = sso_validate_saml_in_response_to(ctx, config, provider, raw_response, state)
      return in_response_to_result if in_response_to_result.is_a?(Array)

      assertion = sso_parse_saml_response(raw_response, config, provider, ctx)
      assertion[:email_verified] = false unless config[:trust_email_verified]
      sso_validate_saml_timestamp!(sso_saml_timestamp_conditions(assertion), config)
      sso_validate_saml_response!(config, assertion, provider, ctx)
      sso_consume_saml_in_response_to(ctx, in_response_to_result)
      assertion_id = assertion[:id] || assertion["id"]
      unless assertion_id.to_s.empty?
        replay_key = "#{SSO_SAML_USED_ASSERTION_KEY_PREFIX}#{assertion_id}"
        if ctx.context.internal_adapter.find_verification_value(replay_key)
          callback_url = sso_safe_saml_callback_url(ctx, state["callbackURL"] || sso_saml_callback_url(provider) || "/", provider.fetch("providerId"))
          return sso_redirect(ctx, sso_append_error(callback_url, "replay_detected", "SAML assertion has already been used"))
        end
        ctx.context.internal_adapter.create_verification_value(identifier: replay_key, value: "used", expiresAt: sso_saml_assertion_replay_expires_at(assertion, config))
      end

      callback_url = sso_safe_saml_callback_url(ctx, state["callbackURL"] || sso_saml_callback_url(provider) || "/", provider.fetch("providerId"))
      email = (assertion[:email] || assertion["email"]).to_s.downcase
      if config[:disable_implicit_sign_up] && !state["requestSignUp"] && !ctx.context.internal_adapter.find_user_by_email(email)
        return sso_redirect(ctx, sso_append_error(callback_url, "signup disabled"))
      end

      result = sso_find_or_create_user_result(ctx, provider, assertion, config)
      return sso_redirect(ctx, sso_append_error(callback_url, result.fetch(:error))) if result[:error]

      user = result.fetch(:user)
      if config[:provision_user].respond_to?(:call) && (result.fetch(:created) || config[:provision_user_on_every_login])
        config[:provision_user].call(user: user, userInfo: assertion, provider: provider)
      end
      session = ctx.context.internal_adapter.create_session(user.fetch("id"))
      sso_store_saml_session(ctx, provider, assertion, session) if config.dig(:saml, :enable_single_logout)
      Cookies.set_session_cookie(ctx, {session: session, user: user})
      sso_redirect(ctx, callback_url)
    end

    def sso_find_or_create_user(ctx, provider, user_info, config = {})
      sso_find_or_create_user_result(ctx, provider, user_info, config).fetch(:user)
    end

    def sso_find_or_create_user_result(ctx, provider, user_info, config = {})
      user_info = normalize_hash(user_info)
      email = user_info[:email].to_s.downcase
      account_id = (user_info[:id] || user_info["id"]).to_s
      provider_id = provider.fetch("providerId")
      storage_provider_id = provider["samlConfig"] ? provider_id : "sso:#{provider_id}"
      existing_account = account_id.empty? ? nil : (
        ctx.context.internal_adapter.find_account_by_provider_id(account_id, provider_id) ||
          ctx.context.internal_adapter.find_account_by_provider_id(account_id, "sso:#{provider_id}")
      )
      if existing_account
        user = ctx.context.internal_adapter.find_user_by_id(existing_account.fetch("userId"))
        created = false
      elsif (found = ctx.context.internal_adapter.find_user_by_email(email, include_accounts: true))
        already_linked_provider = Array(found[:accounts]).any? do |account|
          [provider_id, "sso:#{provider_id}"].include?(account["providerId"])
        end
        if provider["samlConfig"]
          return {error: "account_not_linked"} unless already_linked_provider || sso_saml_trusted_provider?(ctx, provider, email)
        elsif !already_linked_provider && !sso_oidc_trusted_provider?(ctx, provider, email)
          return {error: "account_not_linked"}
        end

        user = found[:user]
        unless account_id.empty?
          ctx.context.internal_adapter.create_account(
            accountId: account_id,
            providerId: storage_provider_id,
            userId: user.fetch("id")
          )
        end
        oidc_config = sso_provider_config_hash(provider["oidcConfig"])
        if oidc_config[:override_user_info] || config[:default_override_user_info]
          update = {}
          update[:name] = user_info[:name] if user_info.key?(:name)
          update[:image] = user_info[:image] if user_info.key?(:image)
          update[:emailVerified] = !!user_info[:email_verified] if user_info.key?(:email_verified)
          user = ctx.context.internal_adapter.update_user(user.fetch("id"), update) if update.any?
        end
        created = false
      else
        created = ctx.context.internal_adapter.create_user(
          email: email,
          name: user_info[:name] || email,
          emailVerified: user_info.key?(:email_verified) ? user_info[:email_verified] : false,
          image: user_info[:image]
        )
        ctx.context.internal_adapter.create_account(
          accountId: account_id.empty? ? created.fetch("id") : account_id,
          providerId: storage_provider_id,
          userId: created.fetch("id")
        )
        user = created
        created = true
      end
      sso_assign_organization_membership(ctx, provider, user, config)
      {user: user, created: created}
    end

    def sso_saml_trusted_provider?(ctx, provider, email)
      provider_id = provider.fetch("providerId")
      linking = ctx.context.options.account[:account_linking] || {}
      return false if linking[:enabled] == false

      trusted = Array(linking[:trusted_providers]).map(&:to_s).include?(provider_id.to_s)
      trusted || (provider["domainVerified"] && sso_email_domain_matches?(email, provider["domain"]))
    end

    def sso_oidc_trusted_provider?(ctx, provider, email)
      provider_id = provider.fetch("providerId")
      linking = ctx.context.options.account[:account_linking] || {}
      return false if linking[:enabled] == false

      trusted_providers = Array(linking[:trusted_providers]).map(&:to_s)
      trusted_providers.include?(provider_id.to_s) ||
        trusted_providers.include?("sso:#{provider_id}") ||
        (provider["domainVerified"] && sso_email_domain_matches?(email, provider["domain"]))
    end

    def sso_assign_organization_membership(ctx, provider, user, config)
      organization_id = provider["organizationId"]
      return if organization_id.to_s.empty?
      return if config.dig(:organization_provisioning, :disabled)
      return unless ctx.context.options.plugins.any? { |plugin| plugin.id == "organization" }
      return if ctx.context.adapter.find_one(model: "member", where: [{field: "organizationId", value: organization_id}, {field: "userId", value: user.fetch("id")}])

      role = if config.dig(:organization_provisioning, :get_role).respond_to?(:call)
        config.dig(:organization_provisioning, :get_role).call(user: user, userInfo: {}, provider: provider)
      else
        config.dig(:organization_provisioning, :default_role) || config.dig(:organization_provisioning, :role) || "member"
      end
      ctx.context.adapter.create(model: "member", data: {organizationId: organization_id, userId: user.fetch("id"), role: role, createdAt: Time.now})
    end

    def sso_validate_saml_response!(config, assertion, provider, ctx)
      validator = config.dig(:saml, :validate_response)
      return unless validator.respond_to?(:call)
      return if validator.call(response: assertion, provider: provider, context: ctx)

      raise APIError.new("BAD_REQUEST", message: "Invalid SAML response")
    end
  end
end

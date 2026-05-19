# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_create_client_endpoint(config)
      Endpoint.new(path: "/oauth2/create-client", method: "POST", metadata: oauth_openapi_for(:create_client)) do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "create")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.create_client(
          ctx,
          model: "oauthClient",
          body: body,
          owner_session: session,
          default_scopes: config[:client_registration_default_scopes] || config[:scopes],
          allowed_scopes: config[:client_registration_allowed_scopes] || config[:scopes],
          store_client_secret: config[:store_client_secret],
          prefix: config[:prefix],
          dynamic_registration: false,
          admin: false,
          pairwise_secret: config[:pairwise_secret],
          strip_client_metadata: true,
          reference_id: oauth_client_reference(config, session)
        )
        ctx.json(client, status: 201, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
      end
    end

    def oauth_get_client_endpoint(config)
      Endpoint.new(path: "/oauth2/get-client", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "read")
        query = OAuthProtocol.stringify_keys(ctx.query)
        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)

        ctx.json(OAuthProtocol.client_response(client, include_secret: false))
      end
    end

    def oauth_get_client_public_endpoint(_config)
      Endpoint.new(path: "/oauth2/public-client", method: "GET") do |ctx|
        Routes.current_session(ctx, allow_nil: true)
        query = OAuthProtocol.stringify_keys(ctx.query)
        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        raise APIError.new("NOT_FOUND", message: "client not found") if OAuthProtocol.stringify_keys(client)["disabled"]

        ctx.json(oauth_public_client_response(client))
      end
    end

    def oauth_get_client_public_prelogin_endpoint(config)
      Endpoint.new(
        path: "/oauth2/public-client-prelogin",
        method: "POST",
        body_schema: ->(value) { value },
        metadata: oauth_openapi_for(:public_client_prelogin)
      ) do |ctx|
        input = OAuthProtocol.stringify_keys(ctx.body).merge(OAuthProtocol.stringify_keys(ctx.query))
        unless config[:allow_public_client_prelogin] || config[:allowPublicClientPrelogin]
          raise APIError.new("BAD_REQUEST")
        end
        unless OAuthProvider::Utils.verify_oauth_query_params(input["oauth_query"], ctx.context.secret)
          raise APIError.new("UNAUTHORIZED", body: {error: "invalid_signature"})
        end

        client = OAuthProtocol.find_client(ctx, "oauthClient", input["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        raise APIError.new("NOT_FOUND", message: "client not found") if OAuthProtocol.stringify_keys(client)["disabled"]

        ctx.json(oauth_public_client_response(client))
      end
    end

    def oauth_list_clients_endpoint(config)
      Endpoint.new(path: "/oauth2/get-clients", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "list")
        reference_id = config[:client_reference]&.call({user: session[:user], session: session[:session]})
        clients = if reference_id
          ctx.context.adapter.find_many(model: "oauthClient", where: [{field: "referenceId", value: reference_id}])
        else
          ctx.context.adapter.find_many(model: "oauthClient", where: [{field: "userId", value: session[:user]["id"]}])
        end
        ctx.json(clients.map { |client| OAuthProtocol.client_response(client, include_secret: false) })
      end
    end

    def oauth_delete_client_endpoint(config)
      Endpoint.new(path: "/oauth2/delete-client", method: "POST", metadata: oauth_openapi_for(:delete_client)) do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "delete")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)
        ctx.context.adapter.delete(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}])
        ctx.json({deleted: true})
      end
    end

    def oauth_update_client_endpoint(config)
      Endpoint.new(path: "/oauth2/update-client", method: "POST", metadata: oauth_openapi_for(:update_client)) do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "update")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)

        update_source = OAuthProtocol.stringify_keys(body["update"] || {})
        oauth_validate_client_update!(client, update_source, config, admin: false)
        update = oauth_client_update_data(update_source)
        updated = update.empty? ? client : ctx.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}], update: update.merge(updatedAt: Time.now))
        ctx.json(OAuthProtocol.client_response(updated, include_secret: false))
      end
    end

    def oauth_admin_create_client_endpoint(config)
      Endpoint.new(path: "/admin/oauth2/create-client", method: "POST", metadata: {server_only: true}) do |ctx|
        session = nil
        if config[:client_privileges].respond_to?(:call)
          session = Routes.current_session(ctx)
          oauth_assert_client_privilege!(ctx, config, session, "create")
        elsif config[:client_reference].respond_to?(:call)
          session = Routes.current_session(ctx, allow_nil: true)
        end
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.create_client(
          ctx,
          model: "oauthClient",
          body: body,
          owner_session: nil,
          default_scopes: config[:client_registration_default_scopes] || config[:scopes],
          allowed_scopes: config[:client_registration_allowed_scopes] || config[:scopes],
          store_client_secret: config[:store_client_secret],
          prefix: config[:prefix],
          dynamic_registration: false,
          admin: true,
          pairwise_secret: config[:pairwise_secret],
          strip_client_metadata: true,
          reference_id: oauth_client_reference(config, session)
        )
        ctx.json(client, status: 201, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
      end
    end

    def oauth_admin_update_client_endpoint(config)
      Endpoint.new(path: "/admin/oauth2/update-client", method: "PATCH", metadata: {server_only: true}) do |ctx|
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client

        update_source = OAuthProtocol.stringify_keys(body["update"] || {})
        oauth_validate_client_update!(client, update_source, config, admin: true)
        update = oauth_client_update_data(update_source, admin: true)
        updated = update.empty? ? client : ctx.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}], update: update.merge(updatedAt: Time.now))
        ctx.json(OAuthProtocol.client_response(updated, include_secret: false))
      end
    end

    def oauth_rotate_client_secret_endpoint(config)
      Endpoint.new(path: "/oauth2/client/rotate-secret", method: "POST", metadata: oauth_openapi_for(:rotate_client_secret)) do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "rotate")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)
        client_data = OAuthProtocol.stringify_keys(client)
        raise APIError.new("BAD_REQUEST", message: "public clients cannot rotate secrets") if client_data["public"] || client_data["tokenEndpointAuthMethod"] == "none"

        client_secret = Crypto.random_string(32)
        updated = ctx.context.adapter.update(
          model: "oauthClient",
          where: [{field: "clientId", value: body["client_id"]}],
          update: {clientSecret: OAuthProtocol.store_client_secret_value(ctx, client_secret, config[:store_client_secret]), updatedAt: Time.now}
        )
        response = OAuthProtocol.client_response(updated, include_secret: false)
        ctx.json(response.merge(client_secret: OAuthProtocol.apply_prefix(client_secret, config[:prefix], :client_secret), client_secret_expires_at: client_data["clientSecretExpiresAt"] || 0))
      end
    end

    def oauth_legacy_get_client_endpoint(config)
      Endpoint.new(path: "/oauth2/client/:id", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "read")
        client = OAuthProtocol.find_client(ctx, "oauthClient", ctx.params["id"] || ctx.params[:id])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)
        ctx.json(OAuthProtocol.client_response(client, include_secret: false))
      end
    end

    def oauth_legacy_get_client_public_endpoint(_config)
      Endpoint.new(path: "/oauth2/client", method: "GET") do |ctx|
        query = OAuthProtocol.stringify_keys(ctx.query)
        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        ctx.json(OAuthProtocol.client_response(client, include_secret: false))
      end
    end

    def oauth_legacy_list_clients_endpoint(config)
      Endpoint.new(path: "/oauth2/clients", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "list")
        clients = ctx.context.adapter.find_many(model: "oauthClient", where: [{field: "userId", value: session[:user]["id"]}])
        ctx.json(clients.map { |client| OAuthProtocol.client_response(client, include_secret: false) })
      end
    end

    def oauth_legacy_update_client_endpoint(config)
      Endpoint.new(path: "/oauth2/client", method: "PATCH", metadata: oauth_openapi_for(:update_client)) do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "update")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)
        update = oauth_client_update_data(OAuthProtocol.stringify_keys(body["update"] || body))
        updated = update.empty? ? client : ctx.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}], update: update.merge(updatedAt: Time.now))
        ctx.json(OAuthProtocol.client_response(updated, include_secret: false))
      end
    end

    def oauth_legacy_delete_client_endpoint(config)
      Endpoint.new(path: "/oauth2/client", method: "DELETE") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "delete")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)
        ctx.context.adapter.delete(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}])
        ctx.json({deleted: true})
      end
    end
  end
end

# frozen_string_literal: true

module BetterAuth
  module Routes
    def self.list_accounts
      Endpoint.new(
        path: "/list-accounts",
        method: "GET",
        metadata: {
          openapi: {
            operationId: "listUserAccounts",
            description: "List linked accounts for the current user",
            responses: {
              "200" => OpenAPI.json_response(
                "Linked accounts",
                {type: "array", items: {type: "object", "$ref": "#/components/schemas/Account"}}
              )
            }
          }
        }
      ) do |ctx|
        session = current_session(ctx)
        accounts = ctx.context.internal_adapter.find_accounts(session[:user]["id"]).map do |account|
          parsed = Schema.parse_output(ctx.context.options, "account", account)
          scope = parsed.delete("scope")
          parsed.merge("scopes" => scope.to_s.empty? ? [] : scope.to_s.split(","))
        end
        ctx.json(accounts)
      end
    end

    def self.unlink_account
      Endpoint.new(
        path: "/unlink-account",
        method: "POST",
        body_schema: request_body_schema(
          required_strings: %w[providerId],
          optional_strings: %w[accountId]
        ),
        metadata: {
          openapi: {
            operationId: "unlinkAccount",
            description: "Unlink an account from the current user",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  providerId: {type: "string"},
                  accountId: {type: ["string", "null"]}
                },
                required: ["providerId"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response("Account unlinked", OpenAPI.status_response_schema)
            }
          }
        }
      ) do |ctx|
        session = current_session(ctx, sensitive: true, fresh: true)
        body = normalize_hash(ctx.body)
        accounts = ctx.context.internal_adapter.find_accounts(session[:user]["id"])
        if accounts.length == 1 && !ctx.context.options.account.dig(:account_linking, :allow_unlinking_all)
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["FAILED_TO_UNLINK_LAST_ACCOUNT"])
        end

        provider_id = body["providerId"] || body["provider_id"]
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VALIDATION_ERROR"]) if provider_id.to_s.empty?

        account_id = body["accountId"] || body["account_id"]
        account = accounts.find do |entry|
          entry["providerId"] == provider_id && (account_id.to_s.empty? || entry["accountId"] == account_id)
        end
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["ACCOUNT_NOT_FOUND"]) unless account

        ctx.context.internal_adapter.delete_account(account["id"])
        ctx.json({status: true})
      end
    end

    def self.get_access_token
      Endpoint.new(
        path: "/get-access-token",
        method: "POST",
        body_schema: request_body_schema(
          required_strings: %w[providerId],
          optional_strings: %w[accountId userId]
        ),
        metadata: {
          openapi: {
            operationId: "getAccessToken",
            description: "Get an access token for a linked provider account",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  providerId: {type: "string"},
                  accountId: {type: ["string", "null"]},
                  userId: {type: ["string", "null"]}
                },
                required: ["providerId"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "Provider access token",
                OpenAPI.object_schema(
                  {
                    accessToken: {type: ["string", "null"]},
                    accessTokenExpiresAt: {type: ["string", "null"], format: "date-time"},
                    scopes: {type: "array", items: {type: "string"}},
                    idToken: {type: ["string", "null"]}
                  },
                  required: ["scopes"]
                )
              )
            }
          }
        }
      ) do |ctx|
        session = current_session(ctx, allow_nil: true)
        body = normalize_hash(ctx.body)
        raise APIError.new("UNAUTHORIZED") if ctx.request && !session

        user_id = session&.dig(:user, "id") || body["userId"] || body["user_id"]
        raise APIError.new("UNAUTHORIZED") if user_id.to_s.empty?

        provider_id = body["providerId"] || body["provider_id"]
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VALIDATION_ERROR"]) if provider_id.to_s.empty?

        account_id = body["accountId"] || body["account_id"]
        ctx.json(access_token_response(ctx, user_id: user_id, provider_id: provider_id, account_id: account_id))
      end
    end

    def self.refresh_token
      Endpoint.new(
        path: "/refresh-token",
        method: "POST",
        body_schema: request_body_schema(
          required_strings: %w[providerId],
          optional_strings: %w[accountId userId]
        ),
        metadata: {
          openapi: {
            operationId: "refreshToken",
            description: "Refresh an OAuth provider access token",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  providerId: {type: "string"},
                  accountId: {type: ["string", "null"]},
                  userId: {type: ["string", "null"]}
                },
                required: ["providerId"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "Refreshed provider tokens",
                OpenAPI.object_schema(
                  {
                    accessToken: {type: ["string", "null"]},
                    refreshToken: {type: ["string", "null"]},
                    accessTokenExpiresAt: {type: ["string", "null"], format: "date-time"},
                    refreshTokenExpiresAt: {type: ["string", "null"], format: "date-time"},
                    scope: {type: ["string", "null"]},
                    idToken: {type: ["string", "null"]},
                    providerId: {type: "string"},
                    accountId: {type: "string"}
                  },
                  required: ["providerId", "accountId"]
                )
              )
            }
          }
        }
      ) do |ctx|
        session = current_session(ctx, allow_nil: true)
        body = normalize_hash(ctx.body)
        raise APIError.new("UNAUTHORIZED") if ctx.request && !session

        user_id = session&.dig(:user, "id") || body["userId"] || body["user_id"]
        raise APIError.new("BAD_REQUEST", message: "Either userId or session is required") if user_id.to_s.empty?

        provider_id = body["providerId"] || body["provider_id"]
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VALIDATION_ERROR"]) if provider_id.to_s.empty?

        provider = social_provider(ctx.context, provider_id)
        raise APIError.new("BAD_REQUEST", message: "Provider #{provider_id} not found.") unless provider
        raise APIError.new("BAD_REQUEST", message: "Provider #{provider_id} does not support token refreshing.") unless provider_callable(provider, :refresh_access_token)

        account_id = body["accountId"] || body["account_id"]
        account = account_cookie(ctx, provider_id, account_id, user_id) || find_provider_account(ctx, user_id, provider_id, account_id)
        raise APIError.new("BAD_REQUEST", message: "Account not found") unless account
        refresh_token = oauth_token_value(ctx, account["refreshToken"])
        raise APIError.new("BAD_REQUEST", message: "Refresh token not found") if refresh_token.to_s.empty?

        begin
          tokens = call_provider(provider, :refresh_access_token, refresh_token)
          updated = update_account_tokens(ctx, account, tokens)
          values = token_hash(tokens)
          Cookies.set_account_cookie(ctx, updated || account.merge(token_hash_for_storage(ctx, tokens)))
        rescue => error
          log(ctx.context, :error, "FAILED_TO_REFRESH_ACCESS_TOKEN #{error.message}")
          raise APIError.new("BAD_REQUEST", code: "FAILED_TO_REFRESH_ACCESS_TOKEN", message: "Failed to refresh access token")
        end
        ctx.json({
          accessToken: values["accessToken"],
          refreshToken: values["refreshToken"] || refresh_token,
          accessTokenExpiresAt: values["accessTokenExpiresAt"],
          refreshTokenExpiresAt: values["refreshTokenExpiresAt"] || account["refreshTokenExpiresAt"],
          scope: values["scope"] || account["scope"],
          idToken: values["idToken"] || account["idToken"],
          providerId: account["providerId"],
          accountId: account["accountId"]
        })
      end
    end

    def self.account_info
      Endpoint.new(
        path: "/account-info",
        method: "GET",
        metadata: {
          openapi: {
            operationId: "accountInfo",
            description: "Get user info from a linked provider account",
            parameters: [
              {
                name: "accountId",
                in: "query",
                required: false,
                schema: {type: "string"}
              }
            ],
            responses: {
              "200" => OpenAPI.json_response(
                "Success",
                OpenAPI.object_schema(
                  {
                    user: OpenAPI.object_schema(
                      {
                        id: {type: "string"},
                        name: {type: "string"},
                        email: {type: "string"},
                        image: {type: "string"},
                        emailVerified: {type: "boolean"}
                      },
                      required: ["id", "emailVerified"]
                    ),
                    data: {
                      type: "object",
                      properties: {},
                      additionalProperties: true
                    }
                  },
                  required: ["user", "data"]
                ).merge(additionalProperties: false)
              )
            }
          }
        }
      ) do |ctx|
        session = current_session(ctx)
        account_id = fetch_value(ctx.query, "accountId")
        account = if account_id
          ctx.context.internal_adapter.find_accounts(session[:user]["id"]).find do |entry|
            entry["id"] == account_id || entry["accountId"] == account_id
          end
        else
          account_cookie(ctx, nil, nil, session[:user]["id"])
        end
        raise APIError.new("BAD_REQUEST", message: "Account not found") unless account && account["userId"] == session[:user]["id"]

        provider = social_provider(ctx.context, account["providerId"])
        raise APIError.new("INTERNAL_SERVER_ERROR", message: "Provider account provider is #{account["providerId"]} but it is not configured") unless provider

        tokens = access_token_response(
          ctx,
          user_id: session[:user]["id"],
          provider_id: account["providerId"],
          account_id: account["accountId"],
          provider: provider
        )
        raise APIError.new("BAD_REQUEST", message: "Access token not found") if tokens[:accessToken].to_s.empty?

        info = call_provider(provider, :get_user_info, tokens.merge(access_token: tokens[:accessToken]))
        ctx.json(info)
      end
    end

    def self.access_token_response(ctx, user_id:, provider_id:, account_id: nil, provider: nil)
      provider ||= social_provider(ctx.context, provider_id)
      raise APIError.new("BAD_REQUEST", message: "Provider #{provider_id} is not supported.") unless provider

      account = account_cookie(ctx, provider_id, account_id, user_id) || find_provider_account(ctx, user_id, provider_id, account_id)
      raise APIError.new("BAD_REQUEST", message: "Account not found") unless account

      if account["refreshToken"] && access_token_expired?(account) && provider_callable(provider, :refresh_access_token)
        begin
          tokens = call_provider(provider, :refresh_access_token, oauth_token_value(ctx, account["refreshToken"]))
          updated = update_account_tokens(ctx, account, tokens)
          account = account.merge(token_hash(tokens))
          Cookies.set_account_cookie(ctx, updated || account.merge(token_hash_for_storage(ctx, tokens)))
        rescue => error
          log(ctx.context, :error, "FAILED_TO_GET_ACCESS_TOKEN #{error.message}")
          raise APIError.new("BAD_REQUEST", code: "FAILED_TO_GET_ACCESS_TOKEN", message: "Failed to get a valid access token")
        end
      end

      {
        accessToken: oauth_token_value(ctx, account["accessToken"]),
        accessTokenExpiresAt: account["accessTokenExpiresAt"],
        scopes: account["scopes"] || (account["scope"].to_s.empty? ? [] : account["scope"].to_s.split(",")),
        idToken: account["idToken"]
      }
    end

    def self.social_provider(context, provider_id)
      return nil if provider_id.to_s.empty?

      provider = context.social_providers[provider_id.to_sym] || context.social_providers[provider_id.to_s]
      return provider.merge(id: provider_id.to_s) if provider.is_a?(Hash) && !provider.key?(:id) && !provider.key?("id")

      provider
    end

    def self.find_provider_account(ctx, user_id, provider_id, account_id = nil)
      ctx.context.internal_adapter.find_accounts(user_id).find do |account|
        account["providerId"] == provider_id && (account_id.to_s.empty? || account["id"] == account_id || account["accountId"] == account_id)
      end
    end

    def self.account_cookie(ctx, provider_id, account_id = nil, user_id = nil)
      return nil unless ctx.context.options.account[:store_account_cookie]

      account = Cookies.get_account_cookie(ctx)
      return nil unless account
      return nil if provider_id && account["providerId"] != provider_id
      return nil unless account_id.to_s.empty? || account["id"] == account_id || account["accountId"] == account_id
      return nil unless user_id.to_s.empty? || account["userId"].to_s.empty? || account["userId"] == user_id

      account
    end

    def self.access_token_expired?(account)
      value = parse_time(account["accessTokenExpiresAt"])
      value && value < Time.now + 5
    end

    def self.parse_time(value)
      return value if value.is_a?(Time)
      return nil if value.nil? || value.to_s.empty?

      Time.parse(value.to_s)
    rescue ArgumentError
      nil
    end

    def self.update_account_tokens(ctx, account, tokens)
      return nil if account["id"].to_s.empty?

      data = account_token_update_hash(ctx, tokens)
      return nil if data.empty?

      ctx.context.internal_adapter.update_account(account["id"], data)
    end

    def self.token_hash(tokens)
      data = normalize_hash(tokens || {})
      data["scope"] = Array(data.delete("scopes")).join(",") if data.key?("scopes")
      data
    end

    def self.token_hash_for_storage(ctx, tokens)
      data = token_hash(tokens)
      data["accessToken"] = oauth_token_for_storage(ctx, data["accessToken"]) if data.key?("accessToken")
      data["refreshToken"] = oauth_token_for_storage(ctx, data["refreshToken"]) if data.key?("refreshToken")
      data
    end

    def self.account_token_update_hash(ctx, tokens)
      account_storage_fields(token_hash_for_storage(ctx, tokens))
    end

    def self.account_storage_fields(data)
      allowed = %w[accessToken refreshToken idToken accessTokenExpiresAt refreshTokenExpiresAt scope]
      token_hash(data).select { |key, value| allowed.include?(key) && !value.nil? }
    end

    def self.oauth_token_for_storage(ctx, token)
      return token if token.to_s.empty?
      return token unless ctx.context.options.account[:encrypt_oauth_tokens]

      Crypto.symmetric_encrypt(key: ctx.context.secret_config, data: token)
    end

    def self.oauth_token_value(ctx, token)
      return token if token.to_s.empty?
      return token unless ctx.context.options.account[:encrypt_oauth_tokens]

      Crypto.symmetric_decrypt(key: ctx.context.secret_config, data: token) || token
    end

    def self.provider_callable(provider, key)
      provider.respond_to?(key) || (provider.is_a?(Hash) && (provider[key] || provider[key.to_s]))
    end

    def self.call_provider(provider, key, *arguments)
      return provider.public_send(key, *arguments) if provider.respond_to?(key)

      callable = provider[key] || provider[key.to_s]
      callable.respond_to?(:call) ? callable.call(*arguments) : callable
    end
  end
end

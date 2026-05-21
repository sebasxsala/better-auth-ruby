# frozen_string_literal: true

require "uri"
require "json"
require "net/http"
require "securerandom"

module BetterAuth
  module Routes
    def self.sign_in_social
      Endpoint.new(
        path: "/sign-in/social",
        method: "POST",
        metadata: {
          openapi: {
            description: "Sign in with a social provider",
            operationId: "socialSignIn",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  provider: {type: "string"},
                  callbackURL: {type: ["string", "null"], description: "Callback URL to redirect to after the user has signed in"},
                  errorCallbackURL: {type: ["string", "null"], description: "Callback URL to redirect to if an error happens"},
                  newUserCallbackURL: {type: ["string", "null"]},
                  disableRedirect: {type: ["boolean", "null"], description: "Disable automatic redirection to the provider. Useful for handling the redirection yourself"},
                  requestSignUp: {type: ["boolean", "null"], description: "Explicitly request sign-up. Useful when disableImplicitSignUp is true for this provider"},
                  loginHint: {type: ["string", "null"], description: "The login hint to use for the authorization code request"},
                  additionalData: {type: ["string", "null"]},
                  scopes: {type: ["array", "null"], description: "Array of scopes to request from the provider. This will override the default scopes passed."},
                  idToken: {
                    type: ["object", "null"],
                    properties: {
                      token: {type: "string", description: "ID token from the provider"},
                      accessToken: {type: ["string", "null"], description: "Access token from the provider"},
                      refreshToken: {type: ["string", "null"], description: "Refresh token from the provider"},
                      expiresAt: {type: ["number", "null"], description: "Expiry date of the token"},
                      nonce: {type: ["string", "null"], description: "Nonce used to generate the token"}
                    },
                    required: ["token"]
                  }
                },
                required: ["provider"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "Success - Returns either session details or redirect URL",
                OpenAPI.session_response_schema(description: "Session response when idToken is provided")
              )
            }
          }
        }
      ) do |ctx|
        body = normalize_hash(ctx.body)
        provider_id = body["provider"].to_s
        provider = social_provider(ctx.context, provider_id)
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES["PROVIDER_NOT_FOUND"]) unless provider
        validate_social_callback_url!(ctx.context, body["callbackURL"] || body["callbackUrl"] || body["callback_url"], "INVALID_CALLBACK_URL")
        validate_social_callback_url!(ctx.context, body["errorCallbackURL"] || body["errorCallbackUrl"] || body["error_callback_url"], "INVALID_ERROR_CALLBACK_URL")
        validate_social_callback_url!(ctx.context, body["newUserCallbackURL"] || body["newUserCallbackUrl"] || body["new_user_callback_url"], "INVALID_NEW_USER_CALLBACK_URL")

        id_token = fetch_value(body, "idToken")
        if id_token
          data = social_user_from_id_token!(ctx, provider, id_token)
          session_data = persist_social_user(
            ctx,
            provider_id,
            data[:user],
            token_hash_for_storage(ctx, data[:account]),
            callback_url: body["callbackURL"],
            disable_sign_up: provider_disable_sign_up?(provider) || (provider_disable_implicit_sign_up?(provider) && !body["requestSignUp"])
          )
          raise APIError.new("UNAUTHORIZED", message: session_data[:error], code: "OAUTH_LINK_ERROR") if session_data[:error]

          Cookies.set_session_cookie(ctx, session_data)
          next ctx.json({
            redirect: false,
            token: session_data[:session]["token"],
            url: nil,
            user: Schema.parse_output(ctx.context.options, "user", session_data[:user])
          })
        end

        code_verifier = SecureRandom.hex(16)
        state = Crypto.sign_jwt(
          {
            "callbackURL" => body["callbackURL"] || body["callbackUrl"] || body["callback_url"] || "/",
            "errorCallbackURL" => body["errorCallbackURL"] || body["errorCallbackUrl"] || body["error_callback_url"],
            "newUserCallbackURL" => body["newUserCallbackURL"] || body["newUserCallbackUrl"] || body["new_user_callback_url"],
            "requestSignUp" => body["requestSignUp"] || body["request_sign_up"],
            "codeVerifier" => code_verifier
          }.merge(safe_additional_state(body)),
          ctx.context.secret,
          expires_in: 600
        )
        store_oauth_state_cookie(ctx, state)
        url = call_provider(provider, :create_authorization_url, {
          state: state,
          codeVerifier: code_verifier,
          code_verifier: code_verifier,
          redirectURI: "#{ctx.context.base_url}/callback/#{provider_id}",
          redirect_uri: "#{ctx.context.base_url}/callback/#{provider_id}",
          scopes: body["scopes"],
          loginHint: body["loginHint"] || body["login_hint"]
        })
        ctx.set_header("location", url.to_s) unless body["disableRedirect"] || body["disable_redirect"]
        ctx.json({url: url.to_s, redirect: !(body["disableRedirect"] || body["disable_redirect"])})
      end
    end

    def self.callback_oauth
      Endpoint.new(
        path: "/callback/:id",
        method: ["GET", "POST"],
        metadata: {
          allowed_media_types: ["application/x-www-form-urlencoded", "application/json"],
          openapi: {
            operationId: "callbackOAuth",
            description: "Handle an OAuth provider callback",
            parameters: [
              {
                name: "id",
                in: "path",
                required: true,
                schema: {type: "string"}
              }
            ],
            responses: {
              "302" => {description: "Redirects to the configured callback URL"}
            }
          }
        }
      ) do |ctx|
        provider_id = (fetch_value(ctx.params, "id") || fetch_value(ctx.params, "providerId")).to_s
        if ctx.method == "POST"
          merged = normalize_hash(ctx.query).merge(normalize_hash(ctx.body))
          query = URI.encode_www_form(merged.reject { |_key, value| value.nil? || value.to_s.empty? })
          target = "#{ctx.context.base_url}/callback/#{provider_id}"
          target = "#{target}?#{query}" unless query.empty?
          raise ctx.redirect(target)
        end

        source = ctx.query
        data = normalize_hash(source)
        provider = social_provider(ctx.context, provider_id)
        state = data["state"].to_s
        state_data = state.empty? ? nil : Crypto.verify_jwt(state, ctx.context.secret)
        error_url = state_data ? (state_data["errorCallbackURL"] || "#{ctx.context.base_url}/error") : "#{ctx.context.base_url}/error"

        raise ctx.redirect(oauth_error_url(error_url, data["error"], data["errorDescription"] || data["error_description"])) if data["error"]
        raise ctx.redirect(oauth_error_url(error_url, "oauth_provider_not_found")) unless provider
        raise ctx.redirect(oauth_error_url(error_url, "state_not_found")) unless state_data
        raise ctx.redirect(oauth_error_url(error_url, "state_mismatch")) unless valid_oauth_state_cookie?(ctx, state)
        raise ctx.redirect(oauth_error_url(error_url, "no_code")) if data["code"].to_s.empty?

        tokens = call_provider(provider, :validate_authorization_code, {
          code: data["code"],
          codeVerifier: state_data["codeVerifier"],
          code_verifier: state_data["codeVerifier"],
          redirectURI: "#{ctx.context.base_url}/callback/#{provider_id}",
          redirect_uri: "#{ctx.context.base_url}/callback/#{provider_id}"
        })
        raise ctx.redirect(oauth_error_url(error_url, "invalid_code")) unless tokens

        token_data = token_hash(tokens)
        token_data["user"] = parse_json_hash(data["user"]) if data["user"]
        user_info = begin
          call_provider(provider, :get_user_info, token_data)
        rescue Net::OpenTimeout, Net::ReadTimeout, SocketError, SystemCallError
          nil
        end
        user = user_info[:user] || user_info["user"] if user_info
        raise ctx.redirect(oauth_error_url(error_url, "unable_to_get_user_info")) unless user
        raise ctx.redirect(oauth_error_url(error_url, "email_not_found")) if fetch_value(user, "email").to_s.empty?

        link = state_data["link"] || state_data[:link]
        if link
          linked = link_social_account_from_callback(ctx, provider_id, user, tokens, link)
          raise ctx.redirect(oauth_error_url(error_url, linked[:error])) if linked[:error]

          raise ctx.redirect(state_data["callbackURL"] || "/")
        end

        account_info = token_hash_for_storage(ctx, tokens).merge("accountId" => fetch_value(user, "id").to_s)
        session_data = persist_social_user(
          ctx,
          provider_id,
          user,
          account_info,
          callback_url: state_data["callbackURL"],
          disable_sign_up: provider_disable_sign_up?(provider) || (provider_disable_implicit_sign_up?(provider) && !state_data["requestSignUp"])
        )
        raise ctx.redirect(oauth_error_url(error_url, session_data[:error].tr(" ", "_"))) if session_data[:error]
        Cookies.set_session_cookie(ctx, session_data)
        callback_url = session_data[:new_user] ? (state_data["newUserCallbackURL"] || state_data["callbackURL"] || "/") : (state_data["callbackURL"] || "/")
        raise ctx.redirect(callback_url)
      end
    end

    def self.link_social
      Endpoint.new(
        path: "/link-social",
        method: "POST",
        metadata: {
          openapi: {
            operationId: "linkSocialAccount",
            description: "Link a social account to the current user",
            requestBody: OpenAPI.json_request_body(
              OpenAPI.object_schema(
                {
                  provider: {type: "string"},
                  callbackURL: {type: ["string", "null"]},
                  errorCallbackURL: {type: ["string", "null"]},
                  disableRedirect: {type: ["boolean", "null"]},
                  scopes: {type: ["array", "null"], items: {type: "string"}},
                  idToken: {type: ["object", "null"]}
                },
                required: ["provider"]
              )
            ),
            responses: {
              "200" => OpenAPI.json_response(
                "Social account link started or completed",
                OpenAPI.object_schema(
                  {
                    url: {type: "string"},
                    redirect: {type: "boolean"},
                    status: {type: ["boolean", "null"]}
                  },
                  required: ["url", "redirect"]
                )
              )
            }
          }
        }
      ) do |ctx|
        session = current_session(ctx)
        body = normalize_hash(ctx.body)
        provider_id = body["provider"].to_s
        provider = social_provider(ctx.context, provider_id)
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES["PROVIDER_NOT_FOUND"]) unless provider
        validate_social_callback_url!(ctx.context, body["callbackURL"] || body["callbackUrl"] || body["callback_url"], "INVALID_CALLBACK_URL")
        validate_social_callback_url!(ctx.context, body["errorCallbackURL"] || body["errorCallbackUrl"] || body["error_callback_url"], "INVALID_ERROR_CALLBACK_URL")

        id_token = fetch_value(body, "idToken")
        if id_token
          data = social_user_from_id_token!(ctx, provider, id_token)
          email = fetch_value(data[:user], "email").to_s.downcase
          unless linkable_provider?(ctx, provider_id, data[:user])
            raise APIError.new("UNAUTHORIZED", message: "Account not linked - untrusted provider")
          end
          unless email == session[:user]["email"].to_s.downcase || ctx.context.options.account.dig(:account_linking, :allow_different_emails)
            raise APIError.new("UNAUTHORIZED", message: "Account not linked - different emails not allowed")
          end

          account_id = fetch_value(data[:user], "id").to_s
          existing = ctx.context.internal_adapter.find_accounts(session[:user]["id"]).find do |account|
            account["providerId"] == provider_id && account["accountId"] == account_id
          end
          unless existing
            ctx.context.internal_adapter.create_account(token_hash_for_storage(ctx, data[:account]).merge("userId" => session[:user]["id"]))
          end
          update_verified_email_on_link(ctx, session[:user]["id"], session[:user]["email"], data[:user])
          next ctx.json({url: "", status: true, redirect: false})
        end

        code_verifier = SecureRandom.hex(16)
        state_data = {
          "callbackURL" => body["callbackURL"] || body["callbackUrl"] || body["callback_url"] || ctx.context.base_url,
          "errorCallbackURL" => body["errorCallbackURL"] || body["errorCallbackUrl"] || body["error_callback_url"],
          "requestSignUp" => body["requestSignUp"] || body["request_sign_up"],
          "codeVerifier" => code_verifier,
          "link" => {
            "userId" => session[:user]["id"],
            "email" => session[:user]["email"]
          }
        }.merge(safe_additional_state(body))
        state = Crypto.sign_jwt(state_data, ctx.context.secret, expires_in: 600)
        store_oauth_state_cookie(ctx, state)
        url = call_provider(provider, :create_authorization_url, {
          state: state,
          codeVerifier: code_verifier,
          code_verifier: code_verifier,
          redirectURI: "#{ctx.context.base_url}/callback/#{provider_id}",
          redirect_uri: "#{ctx.context.base_url}/callback/#{provider_id}",
          scopes: body["scopes"],
          loginHint: body["loginHint"] || body["login_hint"]
        })
        ctx.set_header("location", url.to_s) unless body["disableRedirect"] || body["disable_redirect"]
        ctx.json({url: url.to_s, redirect: !(body["disableRedirect"] || body["disable_redirect"])})
      end
    end

    def self.social_user_from_id_token!(ctx, provider, id_token)
      token = fetch_value(id_token, "token").to_s
      unless provider_callable(provider, :verify_id_token)
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES["ID_TOKEN_NOT_SUPPORTED"])
      end

      valid = call_provider(provider, :verify_id_token, token, fetch_value(id_token, "nonce"))
      raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["INVALID_TOKEN"]) unless valid

      token_user = parse_json_hash(fetch_value(id_token, "user"))
      user_info = call_provider(provider, :get_user_info, {
        "idToken" => token,
        "id_token" => token,
        "accessToken" => fetch_value(id_token, "accessToken"),
        "access_token" => fetch_value(id_token, "accessToken"),
        "refreshToken" => fetch_value(id_token, "refreshToken"),
        "refresh_token" => fetch_value(id_token, "refreshToken"),
        "user" => token_user
      })
      user = user_info[:user] || user_info["user"] if user_info
      raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["FAILED_TO_GET_USER_INFO"]) unless user
      raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["USER_EMAIL_NOT_FOUND"]) if fetch_value(user, "email").to_s.empty?

      {
        user: user,
        account: {
          "providerId" => fetch_value(provider, "id").to_s,
          "accountId" => fetch_value(user, "id").to_s,
          "accessToken" => fetch_value(id_token, "accessToken"),
          "refreshToken" => fetch_value(id_token, "refreshToken"),
          "idToken" => token,
          "user" => token_user
        }
      }
    end

    def self.persist_social_user(ctx, provider_id, user_info, account_info, callback_url: nil, disable_sign_up: false)
      email = fetch_value(user_info, "email").to_s.downcase
      account_id = (account_info["accountId"] || account_info[:accountId] || account_info[:account_id] || fetch_value(user_info, "id")).to_s
      existing = ctx.context.internal_adapter.find_oauth_user(email, account_id, provider_id)

      if existing && existing[:linked_account]
        user = existing[:user]
        if ctx.context.options.account[:update_account_on_sign_in] != false
          update_data = account_storage_fields(account_info)
          ctx.context.internal_adapter.update_account(existing[:linked_account]["id"], update_data) unless update_data.empty?
        end
        verified_user = update_verified_email_on_link(ctx, user["id"], user["email"], user_info)
        user = verified_user if verified_user
        new_user = false
      elsif existing
        unless linkable_provider?(ctx, provider_id, user_info, implicit: true)
          return {error: "account not linked"}
        end
        user = existing[:user]
        ctx.context.internal_adapter.create_account(account_info.merge("providerId" => provider_id, "accountId" => account_id, "userId" => user["id"]))
        verified_user = update_verified_email_on_link(ctx, user["id"], user["email"], user_info)
        user = verified_user if verified_user
        new_user = false
      else
        return {error: "signup disabled"} if disable_sign_up

        created = ctx.context.internal_adapter.create_oauth_user(
          {
            email: email,
            name: fetch_value(user_info, "name").to_s,
            image: fetch_value(user_info, "image"),
            emailVerified: !!fetch_value(user_info, "emailVerified")
          },
          account_info.merge("providerId" => provider_id, "accountId" => account_id),
          context: ctx
        )
        user = created[:user]
        new_user = true
      end
      user = override_social_user_info(ctx, user, user_info) if existing && provider_override_user_info_on_sign_in?(provider_id, ctx.context)

      session = ctx.context.internal_adapter.create_session(user["id"], false, session_overrides(ctx), true, ctx)
      {session: session, user: user, new_user: new_user}
    end

    def self.store_oauth_state_cookie(ctx, state)
      return unless ctx.request

      cookie = ctx.context.create_auth_cookie("state", max_age: 600)
      ctx.set_signed_cookie(cookie.name, state, ctx.context.secret, cookie.attributes)
    end

    def self.valid_oauth_state_cookie?(ctx, state)
      return true unless ctx.request

      cookie = ctx.context.create_auth_cookie("state", max_age: 600)
      stored = ctx.get_signed_cookie(cookie.name, ctx.context.secret)
      Cookies.expire_cookie(ctx, cookie)
      stored == state
    end

    def self.oauth_error_url(base_url, error, description = nil)
      uri = URI.parse(base_url.to_s)
      query = URI.decode_www_form(uri.query.to_s)
      query << ["error", error.to_s]
      query << ["error_description", description.to_s] if description
      uri.query = URI.encode_www_form(query)
      uri.to_s
    end

    def self.provider_disable_implicit_sign_up?(provider)
      !!(fetch_value(provider, "disableImplicitSignUp") || fetch_value(provider, "disableSignUp") || fetch_value(fetch_value(provider, "options") || {}, "disableSignUp"))
    end

    def self.provider_disable_sign_up?(provider)
      !!(fetch_value(provider, "disableSignUp") || fetch_value(fetch_value(provider, "options") || {}, "disableSignUp"))
    end

    def self.linkable_provider?(ctx, provider_id, user_info, implicit: false)
      linking = ctx.context.options.account[:account_linking] || {}
      return false if linking[:enabled] == false
      return false if implicit && linking[:disable_implicit_linking] == true

      trusted = Array(linking[:trusted_providers]).map(&:to_s).include?(provider_id.to_s)
      trusted || !!fetch_value(user_info, "emailVerified")
    end

    def self.link_social_account_from_callback(ctx, provider_id, user_info, tokens, link)
      return {error: "unable_to_link_account"} unless linkable_provider?(ctx, provider_id, user_info)

      email = fetch_value(user_info, "email").to_s.downcase
      link_email = fetch_value(link, "email").to_s.downcase
      unless email == link_email || ctx.context.options.account.dig(:account_linking, :allow_different_emails)
        return {error: "email_doesn't_match"}
      end

      account_id = fetch_value(user_info, "id").to_s
      user_id = fetch_value(link, "userId").to_s
      account_info = token_hash_for_storage(ctx, tokens).merge(
        "providerId" => provider_id,
        "accountId" => account_id,
        "userId" => user_id
      )
      existing = ctx.context.internal_adapter.find_account_by_provider_id(account_id, provider_id)
      if existing
        return {error: "account_already_linked_to_different_user"} if existing["userId"].to_s != user_id

        ctx.context.internal_adapter.update_account(existing["id"], account_info)
      else
        ctx.context.internal_adapter.create_account(account_info)
      end

      if ctx.context.options.account.dig(:account_linking, :update_user_info_on_link)
        ctx.context.internal_adapter.update_user(user_id, {
          name: fetch_value(user_info, "name"),
          image: fetch_value(user_info, "image")
        }.compact)
      end
      update_verified_email_on_link(ctx, user_id, link_email, user_info)

      {status: true}
    end

    def self.provider_override_user_info_on_sign_in?(provider_id, context)
      provider = social_provider(context, provider_id)
      !!(fetch_value(provider, "overrideUserInfoOnSignIn") || fetch_value(fetch_value(provider, "options") || {}, "overrideUserInfoOnSignIn"))
    end

    def self.override_social_user_info(ctx, user, user_info)
      email = fetch_value(user_info, "email").to_s.downcase
      email_verified = if email == user["email"].to_s.downcase
        !!(user["emailVerified"] || fetch_value(user_info, "emailVerified"))
      else
        !!fetch_value(user_info, "emailVerified")
      end
      update = {
        "email" => email,
        "name" => fetch_value(user_info, "name").to_s,
        "image" => fetch_value(user_info, "image"),
        "emailVerified" => email_verified
      }.reject { |_key, value| value.nil? }
      ctx.context.internal_adapter.update_user(user["id"], update) || user
    end

    def self.safe_additional_state(body)
      additional = body["additionalData"] || body["additional_data"]
      return {} unless additional.is_a?(Hash)

      reserved = %w[callbackURL callbackUrl callback_url errorCallbackURL errorCallbackUrl error_callback_url errorURL error_url newUserCallbackURL newUserCallbackUrl new_user_callback_url newUserURL new_user_url requestSignUp request_sign_up codeVerifier code_verifier link expiresAt expires_at]
      normalize_hash(additional).reject { |key, _value| reserved.include?(key.to_s) }
    end

    def self.validate_social_callback_url!(context, callback_url, error_code)
      validate_callback_url!(context, callback_url)
    rescue APIError => error
      return if oauth_proxy_callback_url?(context, callback_url)
      raise error unless error.message == BASE_ERROR_CODES["INVALID_CALLBACK_URL"]

      raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES[error_code])
    end

    def self.oauth_proxy_callback_url?(context, callback_url)
      uri = URI.parse(callback_url.to_s)
      proxy_path = "#{context.options.base_path}/oauth-proxy-callback"
      return false unless uri.path == proxy_path

      nested = URI.decode_www_form(uri.query.to_s).assoc("callbackURL")&.last
      validate_callback_url!(context, nested)
      true
    rescue APIError, URI::InvalidURIError
      false
    end

    def self.update_verified_email_on_link(ctx, user_id, current_email, social_user)
      return unless fetch_value(social_user, "emailVerified")
      return unless fetch_value(social_user, "email").to_s.downcase == current_email.to_s.downcase

      ctx.context.internal_adapter.update_user(user_id, {"emailVerified" => true})
    end

    def self.parse_json_hash(value)
      return value if value.is_a?(Hash)
      return {} if value.nil? || value.to_s.empty?

      parsed = JSON.parse(value.to_s)
      parsed.is_a?(Hash) ? parsed : {}
    rescue JSON::ParserError
      {}
    end
  end
end

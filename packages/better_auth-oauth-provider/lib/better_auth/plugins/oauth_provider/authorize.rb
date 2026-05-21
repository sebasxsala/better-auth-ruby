# frozen_string_literal: true

module BetterAuth
  module Plugins
    module OAuthProvider
      module_function

      def validate_issuer_url(value)
        uri = URI.parse(value.to_s)
        uri.query = nil
        uri.fragment = nil
        if uri.scheme == "http" && !["localhost", "127.0.0.1", "::1"].include?(uri.hostname || uri.host)
          uri.scheme = "https"
        end
        uri.to_s.sub(%r{/+\z}, "")
      rescue URI::InvalidURIError
        value.to_s.split(/[?#]/).first.sub(%r{/+\z}, "")
      end
    end

    module_function

    def oauth_authorize_endpoint(config)
      Endpoint.new(path: "/oauth2/authorize", method: "GET") do |ctx|
        oauth_authorize_flow(ctx, config, OAuthProtocol.stringify_keys(ctx.query))
      end
    end

    def oauth_authorize_flow(ctx, config, query, continue_post_login: false)
      query = oauth_resolve_request_uri!(ctx, config, query)
      response_type = query["response_type"].to_s

      client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
      raise APIError.new("BAD_REQUEST", message: "invalid_client") unless client
      OAuthProtocol.validate_redirect_uri!(client, query["redirect_uri"])
      if response_type != "code"
        raise ctx.redirect(oauth_authorize_error_redirect(ctx, query, "unsupported_response_type", "response_type must be code"))
      end

      scopes = OAuthProtocol.parse_scopes(query["scope"])
      scopes = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(client)["scopes"] || config[:scopes]) if scopes.empty?
      prompts = OAuthProtocol.parse_scopes(query["prompt"])
      if prompts.include?("none") && (prompts - ["none"]).any?
        raise ctx.redirect(oauth_authorize_error_redirect(ctx, query, "invalid_request", "prompt none cannot be combined with other prompts"))
      end
      client_data = OAuthProtocol.stringify_keys(client)
      if client_data["disabled"]
        raise ctx.redirect(oauth_authorize_error_redirect(ctx, query, "invalid_client", "client is disabled"))
      end
      allowed_scopes = OAuthProtocol.parse_scopes(client_data["scopes"])
      allowed_scopes = OAuthProtocol.parse_scopes(config[:scopes]) if allowed_scopes.empty?
      unless scopes.all? { |scope| allowed_scopes.include?(scope) }
        raise ctx.redirect(oauth_authorize_error_redirect(ctx, query, "invalid_scope", "invalid scope"))
      end
      pkce_error = OAuthProtocol.validate_authorize_pkce(client_data, scopes, query["code_challenge"], query["code_challenge_method"])
      raise ctx.redirect(oauth_authorize_error_redirect(ctx, query, "invalid_request", pkce_error)) if pkce_error

      session = Routes.current_session(ctx, allow_nil: true)
      unless session
        if prompts.include?("none")
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "login_required", state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))))
        end

        if prompts.include?("create")
          raise ctx.redirect(oauth_prompt_redirect(ctx, config, query, "create"))
        end

        raise ctx.redirect(oauth_prompt_redirect(ctx, config, query, "login"))
      end

      if oauth_requires_login?(session, prompts, query) && !continue_post_login
        raise ctx.redirect(oauth_prompt_redirect(ctx, config, query, "login"))
      end

      if prompts.include?("select_account") && !continue_post_login
        if prompts.include?("none")
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "account_selection_required", state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))))
        end

        raise ctx.redirect(oauth_prompt_redirect(ctx, config, query, "select_account"))
      end

      if config.dig(:post_login, :should_redirect).respond_to?(:call) && !continue_post_login
        should_redirect = config.dig(:post_login, :should_redirect).call({user: session[:user], session: session[:session], client: client_data, scopes: scopes})
        if should_redirect
          if prompts.include?("none")
            raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "interaction_required", state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))))
          end

          raise ctx.redirect(oauth_prompt_redirect(ctx, config, query, "post_login", page: should_redirect.is_a?(String) ? should_redirect : nil))
        end
      end

      consent_reference_id = oauth_consent_reference(config, session, scopes)
      requires_consent = !client_data["skipConsent"] && (prompts.include?("consent") || !oauth_consent_granted?(ctx, client_data["clientId"], session[:user]["id"], scopes, consent_reference_id))

      if requires_consent
        if prompts.include?("none")
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "consent_required", state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))))
        end

        consent_code = Crypto.random_string(32)
        config[:store][:consents][consent_code] = {
          query: query,
          session: session,
          client: client,
          scopes: scopes,
          reference_id: consent_reference_id,
          expires_at: Time.now + 600
        }
        raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(config[:consent_page], consent_code: consent_code, client_id: client_data["clientId"], scope: OAuthProtocol.scope_string(scopes)))
      end

      oauth_redirect_with_code(ctx, config, query, session, client, scopes, reference_id: consent_reference_id)
    end

    def oauth_requires_login?(session, prompts, query)
      return true if prompts.include?("login")
      return false unless query.key?("max_age")

      max_age = Integer(query["max_age"])
      return false if max_age.negative?

      auth_time = OAuthProvider::Utils.resolve_session_auth_time(session)
      return false unless auth_time

      (Time.now - auth_time) > max_age
    rescue ArgumentError, TypeError
      false
    end

    def oauth_prompt_redirect(ctx, config, query, type, page: nil)
      target = page || oauth_prompt_page(config, type)

      "#{target}?#{oauth_signed_query(ctx, query)}"
    end

    def oauth_prompt_page(config, type)
      case type
      when "create"
        config.dig(:signup, :page) || config[:login_page]
      when "select_account"
        config.dig(:select_account, :page) || config[:login_page]
      when "post_login"
        config.dig(:post_login, :page) || config[:login_page]
      when "consent"
        config[:consent_page]
      else
        config[:login_page]
      end
    end

    def oauth_signed_query(ctx, query)
      data = OAuthProtocol.stringify_keys(query).compact
      data["exp"] = (Time.now.to_i + 600).to_s
      unsigned = URI.encode_www_form(data)
      signature = Crypto.hmac_signature(unsigned, ctx.context.secret, encoding: :base64url)
      "#{unsigned}&#{URI.encode_www_form("sig" => signature)}"
    end

    def oauth_verified_query!(ctx, oauth_query)
      raise APIError.new("BAD_REQUEST", message: "missing oauth query") if oauth_query.to_s.empty?

      pairs = URI.decode_www_form(oauth_query.to_s)
      signature = pairs.reverse_each.find { |key, _value| key == "sig" }&.last
      unsigned_pairs = pairs.filter_map { |key, value| [key, value] unless key == "sig" }
      unsigned = URI.encode_www_form(unsigned_pairs)
      exp = unsigned_pairs.reverse_each.find { |key, _value| key == "exp" }&.last.to_i
      unless signature && exp >= Time.now.to_i && Crypto.verify_hmac_signature(unsigned, signature, ctx.context.secret, encoding: :base64url)
        raise APIError.new("BAD_REQUEST", message: "invalid oauth query")
      end

      unsigned_pairs.each_with_object({}) do |(key, value), result|
        next if key == "exp"

        result[key] = if result.key?(key)
          Array(result[key]) << value
        else
          value
        end
      end
    end

    def oauth_delete_prompt!(query, prompt)
      prompts = OAuthProtocol.parse_scopes(query["prompt"])
      prompts.delete(prompt)
      if prompts.empty?
        query.delete("prompt")
      else
        query["prompt"] = OAuthProtocol.scope_string(prompts)
      end
    end

    def oauth_redirect_location
      yield
    rescue APIError => error
      location = error.headers["location"]
      return location if location

      raise
    end

    def oauth_authorize_error_redirect(ctx, query, error, description)
      OAuthProtocol.redirect_uri_with_params(
        query["redirect_uri"],
        error: error,
        error_description: description,
        state: query["state"],
        iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))
      )
    end

    def oauth_resolve_request_uri!(ctx, config, query)
      query = OAuthProtocol.stringify_keys(query)
      return query if query["request_uri"].to_s.empty?

      resolver = config[:request_uri_resolver]
      unless resolver.respond_to?(:call)
        return oauth_invalid_request_uri!(ctx, query, "request_uri not supported")
      end

      resolved = resolver.call({request_uri: query["request_uri"], client_id: query["client_id"], context: ctx})
      return oauth_invalid_request_uri!(ctx, query, "request_uri is invalid or expired") unless resolved

      resolved_query = OAuthProtocol.stringify_keys(resolved)
      resolved_query["client_id"] = query["client_id"] if query["client_id"]
      resolved_query
    end

    def oauth_invalid_request_uri!(ctx, query, description)
      redirect_uri = query["redirect_uri"]
      raise APIError.new("BAD_REQUEST", message: "invalid_request_uri") if redirect_uri.to_s.empty?

      raise ctx.redirect(oauth_authorize_error_redirect(ctx, query, "invalid_request_uri", description))
    end
  end
end

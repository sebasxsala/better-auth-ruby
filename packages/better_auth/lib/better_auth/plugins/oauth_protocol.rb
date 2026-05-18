# frozen_string_literal: true

require "base64"
require "jwt"
require "openssl"
require "time"
require "uri"

module BetterAuth
  module Plugins
    module OAuthProtocol
      AUTH_CODE_GRANT = "authorization_code"
      REFRESH_GRANT = "refresh_token"
      CLIENT_CREDENTIALS_GRANT = "client_credentials"
      DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

      module_function

      def parse_scopes(value)
        case value
        when Array
          value.map(&:to_s).reject(&:empty?)
        else
          value.to_s.split(/\s+/).reject(&:empty?)
        end
      end

      def scope_string(value)
        parse_scopes(value).join(" ")
      end

      def request_body!(value)
        return stringify_keys(value || {}) if value.nil? || value.is_a?(Hash)

        raise APIError.new("BAD_REQUEST", message: "request body must be an object")
      end

      def issuer(ctx)
        ctx.context.options.base_url.to_s.empty? ? origin_for(ctx.context.base_url) : ctx.context.options.base_url
      end

      def endpoint_base(ctx)
        ctx.context.base_url
      end

      def origin_for(url)
        uri = URI.parse(url.to_s)
        port = uri.port
        default_port = (uri.scheme == "http" && port == 80) || (uri.scheme == "https" && port == 443)
        default_port ? "#{uri.scheme}://#{uri.host}" : "#{uri.scheme}://#{uri.host}:#{port}"
      end

      def redirect_uri_with_params(uri, params)
        parsed = URI.parse(uri.to_s)
        existing = URI.decode_www_form(parsed.query.to_s)
        params.each { |key, value| existing << [key.to_s, value.to_s] unless value.nil? }
        parsed.query = URI.encode_www_form(existing)
        parsed.to_s
      end

      def validate_redirect_uri!(client, redirect_uri)
        redirects = client_redirect_uris(client)
        return if redirects.include?(redirect_uri.to_s)
        return if loopback_redirect_match?(redirects, redirect_uri)

        raise APIError.new("BAD_REQUEST", message: "invalid redirect_uri")
      end

      def loopback_redirect_match?(redirects, redirect_uri)
        requested = URI.parse(redirect_uri.to_s)
        return false unless ["http", "https"].include?(requested.scheme)
        requested_host = requested.hostname || requested.host
        return false unless loopback_host?(requested_host)

        redirects.any? do |allowed|
          allowed_uri = URI.parse(allowed.to_s)
          allowed_host = allowed_uri.hostname || allowed_uri.host
          allowed_uri.scheme == requested.scheme &&
            loopback_host?(allowed_host) &&
            allowed_host == requested_host &&
            allowed_uri.path == requested.path &&
            allowed_uri.query == requested.query
        rescue URI::InvalidURIError
          false
        end
      rescue URI::InvalidURIError
        false
      end

      def loopback_host?(host)
        ["127.0.0.1", "::1"].include?(host.to_s)
      end

      def client_redirect_uris(client)
        value = client["redirectUris"] || client["redirectUrls"] || client[:redirect_uris] || client[:redirectUrls]
        return value if value.is_a?(Array)

        value.to_s.split(",").map(&:strip).reject(&:empty?)
      end

      def client_logout_redirect_uris(client)
        value = client["postLogoutRedirectUris"] || client[:post_logout_redirect_uris]
        return value if value.is_a?(Array)

        value.to_s.split(",").map(&:strip).reject(&:empty?)
      end

      def create_client(ctx, model:, body:, owner_session: nil, default_auth_method: "client_secret_basic", store_client_secret: "plain", unauthenticated: false, default_scopes: nil, allowed_scopes: nil, prefix: {}, dynamic_registration: false, admin: false, pairwise_secret: nil, strip_client_metadata: false, reference_id: nil)
        body = request_body!(body || {})
        requested_auth_method = body["token_endpoint_auth_method"] || default_auth_method
        validate_client_metadata_enums!(requested_auth_method, body)
        validate_admin_only_fields!(body, admin: admin)
        auth_method = unauthenticated ? "none" : requested_auth_method
        public_client = auth_method == "none"
        client_id = Crypto.random_string(32)
        client_secret = public_client ? nil : Crypto.random_string(32)
        redirects = Array(body["redirect_uris"]).map(&:to_s)
        raise APIError.new("BAD_REQUEST", message: "redirect_uris is required") if redirects.empty?
        redirects.each { |uri| validate_safe_url!(uri, field: "redirect_uris") }
        Array(body["post_logout_redirect_uris"]).map(&:to_s).each { |uri| validate_safe_url!(uri, field: "post_logout_redirect_uris") }

        grant_types = Array(body["grant_types"] || [AUTH_CODE_GRANT]).map(&:to_s)
        response_types = Array(body["response_types"] || ["code"]).map(&:to_s)
        validate_client_registration!(auth_method, grant_types, response_types, body, unauthenticated: unauthenticated, dynamic_registration: dynamic_registration)
        validate_redirect_scheme_for_client!(auth_method, body, redirects)
        validate_pairwise_client!(body, redirects, pairwise_secret)

        scopes = parse_scopes(body["scope"] || body["scopes"])
        scopes = parse_scopes(default_scopes) if scopes.empty? && default_scopes
        allowed = parse_scopes(allowed_scopes)
        unless allowed.empty? || scopes.all? { |scope| allowed.include?(scope) }
          raise APIError.new("BAD_REQUEST", message: "invalid_scope")
        end

        metadata = client_metadata(body, strip_unknown: strip_client_metadata)
        metadata["software_id"] = body["software_id"] if body["software_id"]
        metadata["software_version"] = body["software_version"] if body["software_version"]
        metadata["software_statement"] = body["software_statement"] if body["software_statement"]
        metadata["tos_uri"] = body["tos_uri"] if body["tos_uri"]
        metadata["policy_uri"] = body["policy_uri"] if body["policy_uri"]
        require_pkce = body.key?("require_pkce") ? body["require_pkce"] : body["requirePKCE"]
        require_pkce = true if dynamic_registration && require_pkce.nil?

        client_type = if unauthenticated && public_client && body["type"] == "web"
          nil
        else
          body["type"] || (public_client ? nil : "web")
        end
        data = {
          "clientId" => client_id,
          "clientSecret" => client_secret ? store_client_secret_value(ctx, client_secret, store_client_secret) : nil,
          "public" => public_client,
          "type" => client_type,
          "name" => body["client_name"] || body["name"] || "OAuth Client",
          "icon" => body["logo_uri"],
          "uri" => body["client_uri"],
          "contacts" => Array(body["contacts"]).map(&:to_s),
          "tos" => body["tos_uri"],
          "policy" => body["policy_uri"],
          "softwareId" => body["software_id"] || metadata["software_id"],
          "softwareVersion" => body["software_version"] || metadata["software_version"],
          "softwareStatement" => body["software_statement"] || metadata["software_statement"],
          "redirectUris" => redirects,
          "redirectUrls" => redirects.join(","),
          "postLogoutRedirectUris" => Array(body["post_logout_redirect_uris"]).map(&:to_s),
          "clientSecretExpiresAt" => admin ? (body["client_secret_expires_at"] || 0) : nil,
          "tokenEndpointAuthMethod" => auth_method,
          "grantTypes" => grant_types,
          "responseTypes" => response_types,
          "scopes" => scopes,
          "skipConsent" => unauthenticated ? false : !!(body["skip_consent"] || body["skipConsent"]),
          "enableEndSession" => !!(body["enable_end_session"] || body["enableEndSession"]),
          "requirePKCE" => require_pkce,
          "subjectType" => body["subject_type"] || body["subjectType"],
          "metadata" => metadata,
          "disabled" => false
        }
        data["referenceId"] = reference_id if reference_id
        data["userId"] = owner_session[:user]["id"] if owner_session && !reference_id
        created = ctx.context.adapter.create(model: model, data: data)
        response = client_response(created).merge(
          client_secret: client_secret ? apply_prefix(client_secret, prefix, :client_secret) : nil,
          client_id_issued_at: Time.now.to_i
        ).compact
        response[:require_pkce] = require_pkce unless require_pkce.nil?
        response[:client_secret_expires_at] = 0 if client_secret
        response
      end

      def client_response(client, include_secret: true)
        data = stringify_keys(client || {})
        metadata = stringify_keys(data["metadata"] || {})
        response = {
          client_id: data["clientId"],
          client_name: data["name"],
          client_uri: data["uri"],
          logo_uri: data["icon"],
          redirect_uris: client_redirect_uris(data),
          post_logout_redirect_uris: client_logout_redirect_uris(data),
          token_endpoint_auth_method: data["tokenEndpointAuthMethod"] || "client_secret_basic",
          grant_types: data["grantTypes"] || [],
          response_types: data["responseTypes"] || [],
          scope: scope_string(data["scopes"]),
          public: !!data["public"],
          type: data["type"],
          user_id: data["userId"],
          reference_id: data["referenceId"],
          require_pkce: client_require_pkce(data),
          subject_type: data["subjectType"],
          metadata: metadata,
          contacts: data["contacts"] || [],
          tos_uri: data["tos"],
          policy_uri: data["policy"],
          software_id: data["softwareId"],
          software_version: data["softwareVersion"],
          software_statement: data["softwareStatement"],
          client_secret_expires_at: data["clientSecretExpiresAt"]
        }
        response[:skip_consent] = true if data["skipConsent"]
        metadata.each { |key, value| response[key.to_sym] = value }
        response[:client_secret] = data["clientSecret"] if include_secret && data["clientSecret"]
        response.compact
      end

      def validate_client_registration!(auth_method, grant_types, response_types, body, unauthenticated:, dynamic_registration:)
        public_client = auth_method == "none"
        if dynamic_registration && (body["require_pkce"] == false || body["requirePKCE"] == false)
          raise APIError.new("BAD_REQUEST", message: "pkce is required for registered clients")
        end
        if dynamic_registration && (body["enable_end_session"] || body["enableEndSession"])
          raise APIError.new("BAD_REQUEST", message: "enable_end_session is not allowed during dynamic client registration")
        end
        if public_client && grant_types.include?(CLIENT_CREDENTIALS_GRANT)
          raise APIError.new("BAD_REQUEST", message: "public clients cannot use client_credentials")
        end
        if grant_types.include?(AUTH_CODE_GRANT) && !response_types.include?("code")
          raise APIError.new("BAD_REQUEST", message: "authorization_code clients must support code response_type")
        end
        if auth_method != "none" && ["native", "user-agent-based"].include?(body["type"])
          raise APIError.new("BAD_REQUEST", message: "public client types must use token_endpoint_auth_method none")
        end
        if !unauthenticated && auth_method == "none" && body["type"] == "web"
          raise APIError.new("BAD_REQUEST", message: "web clients must be confidential")
        end
      end

      def validate_redirect_scheme_for_client!(auth_method, body, redirects)
        return if auth_method == "none" && body["type"] != "web"

        redirects.each do |value|
          uri = URI.parse(value.to_s)
          next if uri.scheme == "https"
          next if uri.scheme == "http" && loopback_host?(uri.hostname || uri.host)

          raise APIError.new("BAD_REQUEST", message: "redirect_uris is invalid")
        end
      rescue URI::InvalidURIError
        raise APIError.new("BAD_REQUEST", message: "redirect_uris is invalid")
      end

      def validate_pairwise_client!(body, redirects, pairwise_secret)
        subject_type = body["subject_type"] || body["subjectType"]
        return unless subject_type == "pairwise"

        raise APIError.new("BAD_REQUEST", message: "pairwise subject_type requires pairwise_secret") if pairwise_secret.to_s.empty?

        hosts = redirects.map { |uri| URI.parse(uri).host }.uniq
        raise APIError.new("BAD_REQUEST", message: "pairwise redirect_uris must share the same host") if hosts.length > 1
      rescue URI::InvalidURIError
        raise APIError.new("BAD_REQUEST", message: "invalid redirect_uris")
      end

      def validate_safe_url!(value, field:)
        raise APIError.new("BAD_REQUEST", message: "#{field} is invalid") if value.to_s.empty?

        uri = URI.parse(value.to_s)
        scheme = uri.scheme.to_s.downcase
        raise APIError.new("BAD_REQUEST", message: "#{field} is invalid") if scheme.empty?
        raise APIError.new("BAD_REQUEST", message: "#{field} is invalid") if %w[javascript data vbscript].include?(scheme)

        if scheme == "http"
          raise APIError.new("BAD_REQUEST", message: "#{field} is invalid") unless ["localhost", "127.0.0.1", "::1"].include?(uri.hostname || uri.host)
        end
        true
      rescue URI::InvalidURIError
        raise APIError.new("BAD_REQUEST", message: "#{field} is invalid")
      end

      def client_metadata(body, strip_unknown: false)
        raw_metadata = body["metadata"]
        unless raw_metadata.nil? || raw_metadata.is_a?(Hash)
          raise APIError.new("BAD_REQUEST", message: "metadata must be an object")
        end
        metadata = stringify_keys(raw_metadata || {})
        metadata = metadata.slice("software_id", "software_version", "software_statement", "tos_uri", "policy_uri") if strip_unknown
        metadata["software_id"] = body["software_id"] if body["software_id"]
        metadata["software_version"] = body["software_version"] if body["software_version"]
        metadata["software_statement"] = body["software_statement"] if body["software_statement"]
        metadata["tos_uri"] = body["tos_uri"] if body["tos_uri"]
        metadata["policy_uri"] = body["policy_uri"] if body["policy_uri"]
        metadata
      end

      def client_require_pkce(data)
        data = stringify_keys(data || {})
        return data["requirePKCE"] if data.key?("requirePKCE")
        return data["requirePkce"] if data.key?("requirePkce")

        nil
      end

      def validate_client_metadata_enums!(auth_method, body)
        unless ["client_secret_basic", "client_secret_post", "none"].include?(auth_method)
          raise APIError.new("BAD_REQUEST", message: "invalid token_endpoint_auth_method")
        end

        invalid_grant = Array(body["grant_types"]).map(&:to_s) - [AUTH_CODE_GRANT, CLIENT_CREDENTIALS_GRANT, REFRESH_GRANT]
        raise APIError.new("BAD_REQUEST", message: "invalid grant_types") unless invalid_grant.empty?

        invalid_response = Array(body["response_types"]).map(&:to_s) - ["code"]
        raise APIError.new("BAD_REQUEST", message: "invalid response_types") unless invalid_response.empty?

        client_type = body["type"]
        if client_type && !["web", "native", "user-agent-based"].include?(client_type)
          raise APIError.new("BAD_REQUEST", message: "invalid type")
        end
      end

      def validate_admin_only_fields!(body, admin:)
        return if admin

        %w[client_secret_expires_at clientSecretExpiresAt].each do |key|
          raise APIError.new("BAD_REQUEST", message: "field #{key} is server-only") if body.key?(key)
        end
      end

      def find_client(ctx, model, client_id)
        ctx.context.adapter.find_one(model: model, where: [{field: "clientId", value: client_id.to_s}])
      end

      def authenticate_client!(ctx, model, store_client_secret: "plain", prefix: {}, require_confidential: false)
        body = request_body!(ctx.body || {})
        client_id = body["client_id"]
        client_secret = strip_prefix(body["client_secret"], prefix, :client_secret) || body["client_secret"]

        authorization = ctx.headers["authorization"]
        auth_method_used = client_secret.to_s.empty? ? nil : "client_secret_post"
        if authorization.to_s.start_with?("Basic ")
          decoded = Base64.strict_decode64(authorization.delete_prefix("Basic "))
          unless decoded.include?(":")
            raise APIError.new("BAD_REQUEST", message: "invalid authorization header format", body: {error: "invalid_client", error_description: "invalid authorization header format"})
          end
          client_id, client_secret = decoded.split(":", 2)
          if client_id.to_s.empty? || client_secret.to_s.empty?
            raise APIError.new("BAD_REQUEST", message: "invalid authorization header format", body: {error: "invalid_client", error_description: "invalid authorization header format"})
          end
          auth_method_used = "client_secret_basic"
        end

        client = find_client(ctx, model, client_id)
        raise APIError.new("UNAUTHORIZED", message: "invalid_client") unless client

        client_data = stringify_keys(client)
        raise APIError.new("UNAUTHORIZED", message: "invalid_client") if client_data["disabled"]

        method = client_data["tokenEndpointAuthMethod"] || "client_secret_basic"
        if method == "none"
          raise APIError.new("UNAUTHORIZED", message: "invalid_client") if require_confidential
          raise APIError.new("UNAUTHORIZED", message: "invalid_client") unless client_secret.to_s.empty?
          return client
        end
        expected_method = (method == "client_secret_post") ? "client_secret_post" : "client_secret_basic"
        raise APIError.new("UNAUTHORIZED", message: "invalid_client") unless auth_method_used == expected_method
        if client_secret_expired?(client_data["clientSecretExpiresAt"])
          raise APIError.new("UNAUTHORIZED", message: "invalid_client")
        end
        if method != "none" && !verify_client_secret(ctx, stringify_keys(client)["clientSecret"], client_secret, store_client_secret)
          raise APIError.new("UNAUTHORIZED", message: "invalid_client")
        end

        client.merge("__providedClientSecret" => client_secret)
      rescue ArgumentError
        raise APIError.new("BAD_REQUEST", message: "invalid authorization header format", body: {error: "invalid_client", error_description: "invalid authorization header format"})
      end

      def client_secret_expired?(value)
        return false if value.nil? || value.to_i == 0

        seconds = timestamp_seconds(value)
        seconds && seconds <= Time.now.to_i
      end

      def store_code(store, code:, client_id:, redirect_uri:, session:, scopes:, code_challenge: nil, code_challenge_method: nil, nonce: nil, reference_id: nil, auth_time: nil, expires_in: 600, store_tokens: "hashed")
        stored_code = get_stored_token(store_tokens, code, "authorization_code")
        store[:codes][stored_code] = {
          client_id: client_id,
          redirect_uri: redirect_uri,
          session: session,
          scopes: parse_scopes(scopes),
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method,
          nonce: nonce,
          reference_id: reference_id,
          auth_time: auth_time || session_auth_time(session),
          expires_at: Time.now + expires_in.to_i
        }
      end

      def consume_code!(store, code, client_id:, redirect_uri:, code_verifier: nil, store_tokens: "hashed")
        stored_code = get_stored_token(store_tokens, code.to_s, "authorization_code")
        data = store[:codes].delete(stored_code) || store[:codes].delete(code.to_s)
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless data
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") if data[:expires_at] <= Time.now
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless data[:client_id] == client_id.to_s
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless data[:redirect_uri] == redirect_uri.to_s
        if data[:code_challenge]
          verify_pkce!(data, code_verifier)
        elsif !code_verifier.to_s.empty?
          raise APIError.new("BAD_REQUEST", message: "invalid_grant")
        end

        data
      end

      def verify_pkce!(code_data, verifier)
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") if verifier.to_s.empty?

        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless code_data[:code_challenge_method].to_s == "S256"

        challenge = Base64.urlsafe_encode64(OpenSSL::Digest.digest("SHA256", verifier.to_s), padding: false)
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless challenge == code_data[:code_challenge]
      end

      def validate_authorize_pkce(client, scopes, code_challenge, code_challenge_method)
        method = code_challenge_method.to_s
        return "code_challenge_method must be S256" if !code_challenge.to_s.empty? && method != "S256"

        return nil unless pkce_required?(client, scopes)
        return "PKCE is required" if code_challenge.to_s.empty?
        return "code_challenge_method must be S256" if method != "S256"

        nil
      end

      def pkce_required?(client, scopes)
        data = stringify_keys(client)
        return true if data["public"] || data["tokenEndpointAuthMethod"] == "none" || ["native", "user-agent-based"].include?(data["type"])
        return true if parse_scopes(scopes).include?("offline_access")
        require_pkce = client_require_pkce(data)
        return require_pkce unless require_pkce.nil?

        true
      end

      def issue_tokens(ctx, store, model:, client:, session:, scopes:, include_refresh: false, issuer: nil, jwt_audience: nil, access_token_expires_in: 3600, refresh_token_expires_in: 2_592_000, id_token_expires_in: 3600, id_token_signer: nil, prefix: {}, audience: nil, grant_type: nil, custom_token_response_fields: nil, custom_access_token_claims: nil, custom_id_token_claims: nil, jwt_access_token: false, use_jwt_plugin: false, pairwise_secret: nil, nonce: nil, auth_time: nil, reference_id: nil, filter_id_token_claims_by_scope: false, store_tokens: "hashed")
        data = stringify_keys(session || {})
        user = stringify_keys(data["user"] || data[:user] || {})
        session_data = stringify_keys(data["session"] || data[:session] || {})
        client_data = stringify_keys(client)
        subject = subject_identifier(user["id"], client_data, pairwise_secret)
        token_auth_time = auth_time || session_auth_time({"session" => session_data})
        token_reference_id = reference_id || client_data["referenceId"]
        access_token_value = Crypto.random_string(32)
        refresh_token_value = include_refresh ? Crypto.random_string(32) : nil
        refresh_token = refresh_token_value ? apply_prefix(refresh_token_value, prefix, :refresh_token) : nil
        scope = scope_string(scopes)
        expires_at = Time.now + access_token_expires_in.to_i
        access_token = if jwt_access_token && audience
          build_jwt_access_token(ctx, client_data, user, session_data, scope, audience, issuer || issuer(ctx), expires_at, custom_access_token_claims, reference_id: token_reference_id, use_jwt_plugin: use_jwt_plugin)
        else
          apply_prefix(access_token_value, prefix, :access_token)
        end
        refresh_record = nil
        if refresh_token_value
          refresh_record = {
            "token" => store_token_value(store_tokens, refresh_token_value, "refresh_token"),
            "clientId" => client_data["clientId"],
            "sessionId" => session_data["id"],
            "userId" => user["id"],
            "referenceId" => token_reference_id,
            "authTime" => token_auth_time,
            "expiresAt" => Time.now + refresh_token_expires_in.to_i,
            "createdAt" => Time.now,
            "revoked" => nil,
            "scopes" => parse_scopes(scope),
            "subject" => subject,
            "audience" => audience,
            "issuer" => issuer || issuer(ctx),
            "issuedAt" => Time.now
          }
          created_refresh = schema_model?(ctx, "oauthRefreshToken") ? ctx.context.adapter.create(model: "oauthRefreshToken", data: refresh_record) : nil
          refresh_record = refresh_record.merge("id" => stringify_keys(created_refresh || {})["id"], "token" => refresh_token_value, "user" => user, "session" => session_data, "client" => client_data, "scope" => scope)
          store[:refresh_tokens][refresh_token_value] = refresh_record
          store[:refresh_tokens][refresh_token] = refresh_record
        end
        unless jwt_access_token && audience
          record = {
            "token" => store_token_value(store_tokens, access_token_value, "access_token"),
            "expiresAt" => expires_at,
            "clientId" => client_data["clientId"],
            "userId" => user["id"],
            "subject" => subject,
            "sessionId" => session_data["id"],
            "scopes" => parse_scopes(scope),
            "revoked" => nil,
            "referenceId" => token_reference_id,
            "authTime" => token_auth_time,
            "refreshId" => refresh_record && refresh_record["id"],
            "audience" => audience,
            "issuer" => issuer || issuer(ctx),
            "issuedAt" => Time.now
          }
          created_access = ctx.context.adapter.create(model: model, data: record)
          created = stringify_keys(created_access || {})
          record = record.merge("id" => created["id"]) if created["id"]
          stored_record = record.merge("token" => access_token_value, "user" => user, "session" => session_data, "client" => client_data)
          store[:tokens][access_token_value] = stored_record
          store[:tokens][access_token] = stored_record
        end

        response = {
          access_token: access_token,
          token_type: "Bearer",
          expires_in: access_token_expires_in.to_i,
          expires_at: expires_at.to_i,
          scope: scope
        }
        response[:audience] = audience if audience
        response[:refresh_token] = refresh_token if refresh_token
        id_token_client_data = client_data.merge("clientSecret" => client_data["__providedClientSecret"] || client_data["clientSecret"])
        response[:id_token] = id_token(user.merge("id" => subject), client_data["clientId"], issuer || issuer(ctx), jwt_audience || client_data["clientId"], ctx: ctx, signer: id_token_signer, session_id: session_data["id"], include_sid: !!client_data["enableEndSession"], nonce: nonce, auth_time: token_auth_time, custom_claims: custom_id_token_claims, scopes: parse_scopes(scope), client: id_token_client_data, filter_claims_by_scope: filter_id_token_claims_by_scope, expires_in: id_token_expires_in, use_jwt_plugin: use_jwt_plugin) if parse_scopes(scope).include?("openid")
        if custom_token_response_fields.respond_to?(:call)
          extra = custom_token_response_fields.call({grant_type: grant_type, user: user.empty? ? nil : user, scopes: parse_scopes(scope), metadata: stringify_keys(client_data["metadata"] || {})})
          response.merge!(stringify_keys(extra).reject { |key, _value| standard_token_response_field?(key) }.transform_keys(&:to_sym)) if extra.is_a?(Hash)
        end
        response
      end

      def refresh_tokens(ctx, store, model:, client:, refresh_token:, scopes: nil, issuer: nil, access_token_expires_in: 3600, refresh_token_expires_in: 2_592_000, id_token_expires_in: 3600, id_token_signer: nil, prefix: {}, audience: nil, custom_token_response_fields: nil, custom_access_token_claims: nil, custom_id_token_claims: nil, jwt_access_token: false, use_jwt_plugin: false, pairwise_secret: nil, filter_id_token_claims_by_scope: false, store_tokens: "hashed")
        refresh_token_value = strip_prefix(refresh_token, prefix, :refresh_token)
        data = refresh_token_value ? store[:refresh_tokens][refresh_token_value] : nil
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless data
        if data["revoked"]
          revoke_refresh_family!(ctx, store, data)
          raise APIError.new("BAD_REQUEST", message: "invalid_grant")
        end
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") if data["expiresAt"] && data["expiresAt"] <= Time.now

        client_data = stringify_keys(client)
        unless data["clientId"].to_s == client_data["clientId"].to_s
          raise APIError.new("BAD_REQUEST", message: "invalid_grant")
        end

        requested = scopes ? parse_scopes(scopes) : data["scopes"]
        unless requested.all? { |scope| data["scopes"].include?(scope) }
          raise APIError.new("BAD_REQUEST", message: "invalid_scope")
        end
        data["revoked"] = Time.now
        ctx.context.adapter.update(model: "oauthRefreshToken", where: [{field: "id", value: data["id"]}], update: {revoked: data["revoked"]}) if data["id"] && schema_model?(ctx, "oauthRefreshToken")

        issue_tokens(
          ctx,
          store,
          model: model,
          client: client,
          session: {"user" => data["user"], "session" => data["session"]},
          scopes: requested,
          include_refresh: true,
          issuer: issuer,
          access_token_expires_in: access_token_expires_in,
          refresh_token_expires_in: refresh_token_expires_in,
          id_token_signer: id_token_signer,
          prefix: prefix,
          audience: audience,
          grant_type: REFRESH_GRANT,
          custom_token_response_fields: custom_token_response_fields,
          custom_access_token_claims: custom_access_token_claims,
          custom_id_token_claims: custom_id_token_claims,
          jwt_access_token: jwt_access_token,
          use_jwt_plugin: use_jwt_plugin,
          pairwise_secret: pairwise_secret,
          id_token_expires_in: id_token_expires_in,
          auth_time: data["authTime"],
          reference_id: data["referenceId"],
          filter_id_token_claims_by_scope: filter_id_token_claims_by_scope,
          store_tokens: store_tokens
        )
      end

      def token_record(store, token, prefix: {})
        token_value = strip_prefix(token, prefix, :access_token)
        data = token_value ? store[:tokens][token_value] : nil
        return nil unless data
        return nil if data["revoked"]
        return nil if data["expiresAt"] && data["expiresAt"] <= Time.now

        data
      end

      def build_jwt_access_token(ctx, client, user, session, scope, audience, issuer_value, expires_at, custom_claims, reference_id: nil, use_jwt_plugin: false)
        scopes = parse_scopes(scope)
        extra = if custom_claims.respond_to?(:call)
          custom_claims.call({user: user.empty? ? nil : user, scopes: scopes, resource: audience, reference_id: reference_id, metadata: stringify_keys(client["metadata"] || {})})
        end
        payload = (extra.is_a?(Hash) ? stringify_keys(extra) : {}).merge(
          "sub" => user["id"] || client["clientId"],
          "aud" => audience,
          "azp" => client["clientId"],
          "scope" => scope,
          "sid" => session["id"],
          "name" => user["name"],
          "email" => user["email"],
          "email_verified" => user["emailVerified"],
          "iss" => issuer_value,
          "iat" => Time.now.to_i,
          "exp" => expires_at.to_i
        ).compact
        if use_jwt_plugin
          signed = sign_oauth_jwt(ctx, payload, issuer: issuer_value, audience: audience)
          return signed if signed
        end

        ::JWT.encode(payload, ctx.context.secret, "HS256")
      end

      def userinfo(store, authorization, additional_claim: nil, prefix: {}, jwt_secret: nil, ctx: nil, issuer: nil)
        if authorization.to_s.strip.empty?
          raise APIError.new(
            "UNAUTHORIZED",
            message: "authorization header not found",
            body: {error: "invalid_request", error_description: "authorization header not found"}
          )
        end
        token = authorization.to_s.delete_prefix("Bearer ").strip
        record = token_record(store, token, prefix: prefix)
        return jwt_userinfo(token, jwt_secret, additional_claim: additional_claim, ctx: ctx, issuer: issuer) unless record
        user = stringify_keys(record["user"])
        scopes = parse_scopes(record["scopes"])
        raise userinfo_openid_scope_error unless scopes.include?("openid")

        response = {sub: record["subject"] || user["id"]}
        response[:name] = user["name"] if scopes.include?("profile")
        response[:given_name] = user["name"].to_s.split(/\s+/, 2).first if scopes.include?("profile") && user["name"]
        response[:family_name] = user["name"].to_s.split(/\s+/, 2).last if scopes.include?("profile") && user["name"].to_s.include?(" ")
        response[:picture] = user["image"] if scopes.include?("profile") && user["image"]
        if scopes.include?("email")
          response[:email] = user["email"]
          response[:email_verified] = !!user["emailVerified"]
        end
        if additional_claim.respond_to?(:call)
          extra = begin
            additional_claim.call({user: user, scopes: scopes, jwt: record, client: stringify_keys(record["client"] || {})})
          rescue ArgumentError
            additional_claim.call(user, scopes, stringify_keys(record["client"] || {}))
          end
          response.merge!(extra) if extra.is_a?(Hash)
        end
        response
      end

      def jwt_userinfo(token, jwt_secret, additional_claim: nil, ctx: nil, issuer: nil)
        payload = if ctx
          verify_oauth_jwt(ctx, token, issuer: issuer || issuer(ctx), hs256_secret: jwt_secret)
        else
          ::JWT.decode(token, jwt_secret.to_s, true, algorithm: "HS256").first
        end
        scopes = parse_scopes(payload["scope"])
        raise userinfo_openid_scope_error unless scopes.include?("openid")

        response = {sub: payload["sub"]}
        if scopes.include?("profile")
          response[:name] = payload["name"] if payload["name"]
          response[:given_name] = payload["name"].to_s.split(/\s+/, 2).first if payload["name"]
          response[:family_name] = payload["name"].to_s.split(/\s+/, 2).last if payload["name"].to_s.include?(" ")
        end
        if scopes.include?("email")
          response[:email] = payload["email"]
          response[:email_verified] = !!payload["email_verified"]
        end
        if additional_claim.respond_to?(:call)
          extra = additional_claim.call({user: payload, scopes: scopes, jwt: payload, client: {}})
          response.merge!(extra) if extra.is_a?(Hash)
        end
        response
      rescue ::JWT::DecodeError
        raise APIError.new("UNAUTHORIZED", message: "invalid_token")
      end

      def userinfo_openid_scope_error
        APIError.new(
          "BAD_REQUEST",
          message: "openid scope is required",
          body: {error: "invalid_request", error_description: "openid scope is required"}
        )
      end

      def find_token_by_hint(store, token, hint, prefix: {})
        access = -> { (value = strip_prefix(token, prefix, :access_token)) && store[:tokens][value] }
        refresh = -> { (value = strip_prefix(token, prefix, :refresh_token)) && store[:refresh_tokens][value] }

        case hint.to_s
        when "access_token"
          access.call
        when "refresh_token"
          refresh.call
        else
          access.call || refresh.call
        end
      end

      def revoke_refresh_family!(ctx, store, refresh_record)
        client_id = refresh_record["clientId"]
        user_id = refresh_record["userId"]
        store[:refresh_tokens].delete_if { |_token, record| record["clientId"] == client_id && record["userId"] == user_id }
        store[:tokens].delete_if { |_token, record| record["clientId"] == client_id && record["userId"] == user_id }
        if schema_model?(ctx, "oauthRefreshToken")
          refresh_ids = ctx.context.adapter.find_many(
            model: "oauthRefreshToken",
            where: [
              {field: "clientId", value: client_id},
              {field: "userId", value: user_id}
            ]
          ).map { |entry| stringify_keys(entry)["id"] }

          ctx.context.adapter.delete_many(
            model: "oauthRefreshToken",
            where: [
              {field: "clientId", value: client_id},
              {field: "userId", value: user_id}
            ]
          )

          if schema_model?(ctx, "oauthAccessToken")
            refresh_ids.each do |refresh_id|
              ctx.context.adapter.delete_many(model: "oauthAccessToken", where: [{field: "refreshId", value: refresh_id}])
            end
          end
        end
      end

      def schema_model?(ctx, model)
        Schema.auth_tables(ctx.context.options).key?(model.to_s)
      end

      def apply_prefix(value, prefix, kind)
        "#{token_prefix(prefix, kind)}#{value}"
      end

      def strip_prefix(value, prefix, kind)
        token = value.to_s
        expected = token_prefix(prefix, kind)
        return token if expected.empty?
        return token.delete_prefix(expected) if token.start_with?(expected)

        nil
      end

      def token_prefix(prefix, kind)
        data = stringify_keys(prefix || {})
        case kind
        when :access_token
          data["opaque_access_token"] || data["opaqueAccessToken"] || "ba_at_"
        when :refresh_token
          data["refresh_token"] || data["refreshToken"] || "ba_rt_"
        when :client_secret
          data["client_secret"] || data["clientSecret"] || ""
        else
          ""
        end
      end

      def id_token(user, client_id, issuer_value, audience, ctx: nil, signer: nil, session_id: nil, include_sid: false, nonce: nil, auth_time: nil, custom_claims: nil, scopes: [], client: {}, filter_claims_by_scope: false, expires_in: 3600, use_jwt_plugin: false)
        requested_scopes = parse_scopes(scopes)
        payload = {
          sub: user["id"],
          iss: issuer_value,
          aud: audience || client_id
        }
        include_profile_claims = !filter_claims_by_scope || requested_scopes.include?("profile")
        include_email_claims = !filter_claims_by_scope || requested_scopes.include?("email")
        payload[:name] = user["name"] if include_profile_claims
        if include_email_claims
          payload[:email] = user["email"]
          payload[:email_verified] = !!user["emailVerified"]
        end
        payload[:sid] = session_id if include_sid && session_id
        payload[:nonce] = nonce if nonce
        payload[:auth_time] = timestamp_seconds(auth_time) if auth_time
        if custom_claims.respond_to?(:call)
          extra = custom_claims.call({user: user, scopes: requested_scopes, client: client})
          if extra.is_a?(Hash)
            pinned = %w[sub iss aud exp iat nonce sid]
            payload.merge!(stringify_keys(extra).except(*pinned).transform_keys(&:to_sym))
          end
        end
        return signer.call(ctx, payload) if signer.respond_to?(:call)

        if use_jwt_plugin && ctx
          signed = sign_oauth_jwt(ctx, payload, issuer: issuer_value, audience: audience)
          return signed if signed
        end

        Crypto.sign_jwt(
          payload,
          id_token_hs256_key(ctx, client_id, stringify_keys(client)["clientSecret"] || stringify_keys(client)["client_secret"]),
          expires_in: expires_in
        )
      end

      def id_token_hs256_key(ctx, client_id, client_secret = nil)
        oauth_provider = ctx&.context&.options&.plugins&.find { |plugin| plugin.id == "oauth-provider" }
        if oauth_provider&.options&.fetch(:store_client_secret, nil).to_s == "hashed"
          label = client_id.to_s.empty? ? "better-auth" : client_id.to_s
          return OpenSSL::HMAC.hexdigest("SHA256", ctx.context.secret.to_s, "oidc.id_token.#{label}")
        end
        return client_secret.to_s unless client_secret.to_s.empty?

        label = client_id.to_s.empty? ? "better-auth" : client_id.to_s
        OpenSSL::HMAC.hexdigest("SHA256", ctx.context.secret.to_s, "oidc.id_token.#{label}")
      end

      def jwt_plugin_options(ctx)
        plugin = ctx.context.options.plugins.find { |entry| entry.id == "jwt" }
        plugin&.options
      end

      def oauth_jwt_config(ctx, issuer:, audience:)
        options = jwt_plugin_options(ctx)
        return nil unless options

        BetterAuth::Plugins.deep_merge(options, jwt: {issuer: issuer, audience: audience})
      end

      def sign_oauth_jwt(ctx, payload, issuer:, audience:)
        config = oauth_jwt_config(ctx, issuer: issuer, audience: audience)
        return nil unless config

        BetterAuth::Plugins.sign_jwt_payload(ctx, stringify_keys(payload), config)
      end

      def verify_oauth_jwt(ctx, token, issuer:, hs256_secret:)
        payload = ::JWT.decode(token.to_s, nil, false).first
        audience = payload["aud"]
        config = oauth_jwt_config(ctx, issuer: issuer, audience: audience.is_a?(Array) ? audience.first : audience)
        verified = BetterAuth::Plugins.verify_jwt_token(ctx, token, config) if config
        return verified if verified

        ::JWT.decode(token, hs256_secret.to_s, true, algorithm: "HS256").first
      end

      def standard_token_response_field?(key)
        %w[access_token token_type expires_in scope refresh_token id_token audience].include?(key.to_s)
      end

      def subject_identifier(user_id, client, pairwise_secret)
        data = stringify_keys(client)
        return user_id unless data["subjectType"] == "pairwise" && pairwise_secret && user_id

        OpenSSL::HMAC.hexdigest("SHA256", pairwise_secret.to_s, "#{sector_identifier(data)}.#{user_id}")
      end

      def sector_identifier(client)
        data = stringify_keys(client)
        uri = client_redirect_uris(data).first
        raise APIError.new("BAD_REQUEST", message: "pairwise subject_type requires redirect_uris") if uri.to_s.empty?

        URI.parse(uri.to_s).host || data["clientId"]
      rescue URI::InvalidURIError
        data["clientId"]
      end

      def session_auth_time(session)
        data = stringify_keys(session || {})
        session_data = stringify_keys(data["session"] || data[:session] || data)
        session_data["createdAt"] || session_data["created_at"]
      end

      def timestamp_seconds(value)
        if value.is_a?(Numeric)
          return nil unless value.finite?
          return nil if value.abs > 8_640_000_000_000_000

          return (value / 1000.0).floor if value.abs >= 100_000_000_000

          return value.to_i
        end
        if value.is_a?(String) && value.match?(/\A[-+]?(?:\d+(?:\.\d+)?|\.\d+)(?:e[-+]?\d+)?\z/i)
          numeric = value.to_f
          return nil unless numeric.finite?
          return nil if numeric.abs > 8_640_000_000_000_000

          return (numeric / 1000.0).floor if numeric.abs >= 100_000_000_000

          return numeric.to_i
        end
        return timestamp_seconds(value.to_i) if value.respond_to?(:to_i) && !value.is_a?(String)

        Time.parse(value.to_s).to_i
      rescue ArgumentError, TypeError, FloatDomainError
        nil
      end

      def store_client_secret_value(ctx, secret, mode)
        mode = normalize_secret_storage_mode(mode)
        return Crypto.sha256(secret, encoding: :base64url) if mode == "hashed"
        return Crypto.symmetric_encrypt(key: ctx.context.secret_config, data: secret) if mode == "encrypted"

        if mode.is_a?(Hash)
          return mode[:hash].call(secret) if mode[:hash].respond_to?(:call)
          return mode[:encrypt].call(secret) if mode[:encrypt].respond_to?(:call)
        end

        secret
      end

      def store_token_value(storage_method, token, type)
        case storage_method
        when "hashed", :hashed
          Crypto.sha256(token.to_s, encoding: :base64url)
        else
          mode = normalize_secret_storage_mode(storage_method)
          return mode[:hash].call(token.to_s, type) if mode.is_a?(Hash) && mode[:hash].respond_to?(:call)

          raise Error, "storeToken: unsupported storageMethod type '#{storage_method}'"
        end
      end

      def get_stored_token(storage_method, token, type)
        store_token_value(storage_method, token, type)
      end

      def verify_client_secret(ctx, stored_secret, provided_secret, mode)
        mode = normalize_secret_storage_mode(mode)
        return Crypto.constant_time_compare(Crypto.sha256(provided_secret, encoding: :base64url), stored_secret.to_s) if mode == "hashed"
        if mode == "encrypted"
          decrypted = Crypto.symmetric_decrypt(key: ctx.context.secret_config, data: stored_secret)
          return Crypto.constant_time_compare(decrypted.to_s, provided_secret.to_s)
        end

        if mode.is_a?(Hash)
          return Crypto.constant_time_compare(mode[:hash].call(provided_secret).to_s, stored_secret.to_s) if mode[:hash].respond_to?(:call)
          return Crypto.constant_time_compare(mode[:decrypt].call(stored_secret).to_s, provided_secret.to_s) if mode[:decrypt].respond_to?(:call)
        end

        Crypto.constant_time_compare(stored_secret.to_s, provided_secret.to_s)
      rescue Error, ArgumentError
        false
      end

      def normalize_secret_storage_mode(mode)
        return stringify_keys(mode).transform_keys(&:to_sym) if mode.is_a?(Hash)

        mode.to_s
      end

      def stores
        {
          codes: {},
          tokens: {},
          refresh_tokens: {},
          consents: {}
        }
      end

      def stringify_keys(value)
        return value.each_with_object({}) { |(key, object_value), result| result[key.to_s] = stringify_keys(object_value) } if value.is_a?(Hash)
        return value.map { |entry| stringify_keys(entry) } if value.is_a?(Array)

        value
      end
    end
  end
end

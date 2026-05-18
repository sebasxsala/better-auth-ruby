# frozen_string_literal: true

require "base64"
require "json"
require "jwt"
require "net/http"
require "openssl"
require "time"
require "uri"
require_relative "../http_client"

module BetterAuth
  module SocialProviders
    module Base
      module_function

      def authorization_url(endpoint, params)
        uri = URI(endpoint)
        query = URI.decode_www_form(uri.query.to_s)
        params.compact.each do |key, value|
          next if value == ""

          query << [key.to_s, Array(value).join(" ")]
        end
        uri.query = URI.encode_www_form(query)
        uri.to_s
      end

      def oauth_provider(id:, name:, client_id:, authorization_endpoint:, token_endpoint:, profile_map:, client_secret: nil, user_info_endpoint: nil, scopes: [], scope_separator: " ", pkce: false, auth_params: {}, token_params: {}, user_info_method: :get, user_info_headers: {}, user_info_body: nil, **options)
        opts = normalize_options(options.merge(client_id: client_id, client_secret: client_secret))
        {
          id: id,
          name: name,
          client_id: client_id,
          client_secret: client_secret,
          options: opts,
          create_authorization_url: lambda do |data|
            verifier = value(data, :code_verifier, :codeVerifier)
            selected_scopes = selected_scopes(scopes, opts, data)
            params = {
              client_id: primary_client_id(client_id),
              redirect_uri: opts[:redirect_uri] || value(data, :redirect_uri, :redirectURI),
              response_type: "code",
              scope: selected_scopes.empty? ? nil : selected_scopes.join(scope_separator),
              state: value(data, :state),
              code_challenge: (pkce && verifier) ? pkce_challenge(verifier) : nil,
              code_challenge_method: (pkce && verifier) ? "S256" : nil,
              login_hint: value(data, :loginHint, :login_hint),
              prompt: opts[:prompt]
            }.merge(resolve_hash(auth_params, data, opts))
            authorization_url(option(opts, :authorization_endpoint, :authorizationEndpoint) || authorization_endpoint, params)
          end,
          validate_authorization_code: lambda do |data|
            post_form_json(option(opts, :token_endpoint, :tokenEndpoint) || token_endpoint, {
              client_id: primary_client_id(client_id),
              client_secret: client_secret,
              code: value(data, :code),
              code_verifier: value(data, :code_verifier, :codeVerifier),
              grant_type: "authorization_code",
              redirect_uri: opts[:redirect_uri] || value(data, :redirect_uri, :redirectURI)
            }.merge(resolve_hash(token_params, data, opts)))
          end,
          refresh_access_token: opts[:refresh_access_token] || lambda do |refresh_token|
            refresh_access_token(
              option(opts, :token_endpoint, :tokenEndpoint) || token_endpoint,
              refresh_token,
              client_id: primary_client_id(client_id),
              client_secret: client_secret
            )
          end,
          verify_id_token: opts[:verify_id_token],
          get_user_info: lambda do |tokens|
            custom = opts[:get_user_info]
            profile = if custom
              custom.call(tokens)
            elsif user_info_endpoint
              fetch_user_info(user_info_endpoint, tokens, method: user_info_method, headers: user_info_headers, body: user_info_body)
            else
              decode_jwt_payload(id_token(tokens))
            end
            return nil unless profile
            return profile if provider_user_info?(profile)

            mapped = profile_map.call(profile)
            user_map = opts[:map_profile_to_user]&.call(profile) || {}
            {user: mapped.merge(user_map), data: profile}
          end
        }
      end

      def pkce_challenge(verifier)
        digest = OpenSSL::Digest.digest("SHA256", verifier.to_s)
        Base64.urlsafe_encode64(digest, padding: false)
      end

      def post_form(url, form)
        post_form_json(url, form)
      end

      def post_form_json(url, form, headers = {})
        uri = URI(url)
        request = Net::HTTP::Post.new(uri)
        request.set_form_data(form.compact.transform_keys(&:to_s))
        request["Accept"] = "application/json"
        headers.each { |key, value| request[key.to_s] = value.to_s }
        parse_response(request_json(uri, request))
      end

      def get_json(url, headers = {})
        uri = URI(url)
        request = Net::HTTP::Get.new(uri)
        headers.each { |key, value| request[key.to_s] = value.to_s }
        parse_response(request_json(uri, request))
      end

      def get_bytes(url, headers = {})
        uri = URI(url)
        request = Net::HTTP::Get.new(uri)
        headers.each { |key, value| request[key.to_s] = value.to_s }
        response = request_json(uri, request)
        response.is_a?(Net::HTTPSuccess) ? response.body.to_s : nil
      rescue URI::InvalidURIError, SocketError, SystemCallError
        nil
      end

      def post_json(url, body = {}, headers = {})
        uri = URI(url)
        request = Net::HTTP::Post.new(uri)
        headers.each { |key, value| request[key.to_s] = value.to_s }
        request.set_form_data(body.compact.transform_keys(&:to_s))
        parse_response(request_json(uri, request))
      end

      def fetch_user_info(endpoint, tokens, method: :get, headers: {}, body: nil)
        resolved_headers = resolve_hash(headers, tokens, {})
        resolved_body = resolve_hash(body || {}, tokens, {})
        resolved_headers = {"Authorization" => "Bearer #{access_token(tokens)}"}.merge(resolved_headers)
        (method == :post) ? post_json(endpoint, resolved_body, resolved_headers) : get_json(endpoint, resolved_headers)
      end

      def refresh_access_token(token_endpoint, refresh_token, client_id:, client_secret: nil, extra_params: {})
        normalize_tokens(post_form_json(token_endpoint, {
          client_id: client_id,
          client_secret: client_secret,
          grant_type: "refresh_token",
          refresh_token: refresh_token
        }.merge(extra_params || {})))
      end

      def normalize_tokens(tokens, now: Time.now)
        data = stringify_keys(tokens || {})
        result = {}
        result["accessToken"] = data["accessToken"] || data["access_token"] if data["accessToken"] || data["access_token"]
        result["refreshToken"] = data["refreshToken"] || data["refresh_token"] if data["refreshToken"] || data["refresh_token"]
        result["idToken"] = data["idToken"] || data["id_token"] if data["idToken"] || data["id_token"]
        result["tokenType"] = data["tokenType"] || data["token_type"] if data["tokenType"] || data["token_type"]
        scope = data["scope"] || data["scopes"]
        result["scope"] = Array(scope).join(",").tr(" ", ",").split(",").reject(&:empty?).join(",") if scope
        result["accessTokenExpiresAt"] = time_from(data["accessTokenExpiresAt"] || data["access_token_expires_at"]) if data["accessTokenExpiresAt"] || data["access_token_expires_at"]
        result["refreshTokenExpiresAt"] = time_from(data["refreshTokenExpiresAt"] || data["refresh_token_expires_at"]) if data["refreshTokenExpiresAt"] || data["refresh_token_expires_at"]
        result["accessTokenExpiresAt"] ||= now + data["expires_in"].to_i if data["expires_in"]
        result["refreshTokenExpiresAt"] ||= now + data["refresh_token_expires_in"].to_i if data["refresh_token_expires_in"]
        data.each { |key, value| result[key] = value unless result.key?(key) || %w[access_token refresh_token id_token token_type expires_in refresh_token_expires_in scopes].include?(key) }
        result
      end

      def access_token(tokens)
        tokens[:access_token] || tokens["access_token"] || tokens[:accessToken] || tokens["accessToken"]
      end

      def id_token(tokens)
        tokens[:id_token] || tokens["id_token"] || tokens[:idToken] || tokens["idToken"]
      end

      def value(hash, *keys)
        return nil unless hash

        keys.each do |key|
          return hash[key] if hash.respond_to?(:key?) && hash.key?(key)

          string_key = key.to_s
          return hash[string_key] if hash.respond_to?(:key?) && hash.key?(string_key)
        end
        nil
      end

      def option(options, *keys)
        value(options, *keys)
      end

      def normalize_options(options)
        normalized = options.dup
        {
          clientId: :client_id,
          clientSecret: :client_secret,
          clientKey: :client_key,
          disableDefaultScope: :disable_default_scope,
          mapProfileToUser: :map_profile_to_user,
          getUserInfo: :get_user_info,
          verifyIdToken: :verify_id_token,
          refreshAccessToken: :refresh_access_token,
          disableIdTokenSignIn: :disable_id_token_sign_in,
          disableImplicitSignUp: :disable_implicit_sign_up,
          disableSignUp: :disable_sign_up,
          authorizationEndpoint: :authorization_endpoint,
          tokenEndpoint: :token_endpoint,
          userInfoEndpoint: :user_info_endpoint,
          emailsEndpoint: :emails_endpoint,
          redirectURI: :redirect_uri,
          jwksEndpoint: :jwks_endpoint,
          appBundleIdentifier: :app_bundle_identifier,
          profilePhotoSize: :profile_photo_size,
          disableProfilePhoto: :disable_profile_photo,
          tenantId: :tenant_id
        }.each do |camel, snake|
          normalized[snake] = normalized[camel] if normalized.key?(camel) && !normalized.key?(snake)
        end
        normalized
      end

      def selected_scopes(defaults, options, data)
        scopes = options[:disable_default_scope] ? [] : Array(defaults).dup
        scopes.concat(Array(options[:scope])) if options[:scope]
        scopes.concat(Array(options[:scopes])) if options[:scopes]
        request_scopes = value(data, :scopes)
        scopes.concat(Array(request_scopes)) if request_scopes
        scopes
      end

      def primary_client_id(client_id)
        value = Array(client_id).first
        raise Error, "CLIENT_ID_AND_SECRET_REQUIRED" if value.to_s.empty?

        value
      end

      def apply_profile_mapping(user, profile, options)
        user.merge(options[:map_profile_to_user]&.call(profile) || {})
      end

      def resolve_hash(value, data, options)
        resolved = value.respond_to?(:call) ? value.call(data, options) : value
        (resolved || {}).compact
      end

      def provider_user_info?(value)
        value.is_a?(Hash) && (value.key?(:user) || value.key?("user"))
      end

      def decode_jwt_payload(token)
        _header, payload, _signature = token.to_s.split(".", 3)
        return {} unless payload

        JSON.parse(Base64.urlsafe_decode64(padded_base64(payload)))
      rescue JSON::ParserError, ArgumentError
        {}
      end

      def verify_jwt_with_jwks(token, jwks:, jwks_endpoint:, algorithms:, issuers:, audience:, nonce: nil, max_age: 3600)
        jwks_payload = jwks.respond_to?(:call) ? jwks.call : jwks
        jwks_payload ||= fetch_jwks(jwks_endpoint)
        return nil unless jwks_payload

        options = {
          algorithms: algorithms,
          jwks: JWT::JWK::Set.new(stringify_keys(jwks_payload)),
          aud: audience,
          verify_aud: true
        }
        options[:iss] = issuers if issuers
        options[:verify_iss] = true if issuers
        payload, = JWT.decode(token.to_s, nil, true, options)
        return nil if nonce && payload["nonce"] != nonce
        return nil if max_age && payload["iat"] && payload["iat"].to_i < Time.now.to_i - max_age.to_i

        payload
      rescue JWT::DecodeError, JSON::ParserError, ArgumentError, OpenSSL::PKey::PKeyError, Net::OpenTimeout, Net::ReadTimeout, SocketError, SystemCallError
        nil
      end

      def fetch_jwks(endpoint)
        return nil if endpoint.to_s.empty?

        get_json(endpoint)
      end

      def stringify_keys(hash)
        hash.each_with_object({}) { |(key, value), memo| memo[key.to_s] = value }
      end

      def time_from(value)
        return value if value.is_a?(Time)
        return nil if value.nil? || value.to_s.empty?

        Time.parse(value.to_s)
      rescue ArgumentError
        nil
      end

      def parse_response(response)
        return nil unless response.is_a?(Net::HTTPSuccess)

        body = response.body.to_s
        return {} if body.empty?

        JSON.parse(body)
      rescue JSON::ParserError
        URI.decode_www_form(body).to_h
      end

      def request_json(uri, request)
        HTTPClient.request(uri, request)
      end

      def padded_base64(value)
        value + ("=" * ((4 - value.length % 4) % 4))
      end
    end
  end
end

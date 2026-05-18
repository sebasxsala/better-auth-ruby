# frozen_string_literal: true

require "base64"
require "net/http"
require "uri"
require "jwt"

module BetterAuth
  module OAuth2
    module_function

    def validate_token(token, jwks:, audience: nil, issuer: nil)
      header = JWT.decode(token, nil, false).last
      kid = header["kid"]
      raise APIError.new("UNAUTHORIZED", message: "Missing jwt kid") if kid.to_s.empty?

      key_data = Array(jwks["keys"] || jwks[:keys]).find { |key| (key["kid"] || key[:kid]).to_s == kid.to_s }
      raise APIError.new("UNAUTHORIZED", message: "kid doesn't match any key") unless key_data

      public_key = JWT::JWK.import(stringify_keys(key_data)).public_key
      algorithm = header["alg"] || key_data["alg"] || key_data[:alg]
      options = {algorithm: algorithm}
      options[:aud] = audience if audience
      options[:verify_aud] = true if audience
      options[:iss] = issuer if issuer
      options[:verify_iss] = true if issuer
      JWT.decode(token, public_key, true, **options).first
    rescue JWT::DecodeError => error
      raise APIError.new("UNAUTHORIZED", message: error.message)
    end

    def refresh_access_token(refresh_token:, token_endpoint:, options:, authentication: nil, extra_params: nil, resource: nil, fetcher: nil)
      request = create_refresh_access_token_request(
        refresh_token: refresh_token,
        options: options,
        authentication: authentication,
        extra_params: extra_params,
        resource: resource
      )
      data = fetcher ? fetcher.call(token_endpoint, request) : post_form(token_endpoint, request)
      now = Time.now
      tokens = {
        access_token: data["access_token"] || data[:access_token],
        refresh_token: data["refresh_token"] || data[:refresh_token],
        token_type: data["token_type"] || data[:token_type],
        scopes: (data["scope"] || data[:scope])&.split(" "),
        id_token: data["id_token"] || data[:id_token]
      }.compact

      expires_in = data["expires_in"] || data[:expires_in]
      tokens[:access_token_expires_at] = now + expires_in.to_i if expires_in

      refresh_expires_in = data["refresh_token_expires_in"] || data[:refresh_token_expires_in]
      tokens[:refresh_token_expires_at] = now + refresh_expires_in.to_i if refresh_expires_in
      tokens
    end

    def create_refresh_access_token_request(refresh_token:, options:, authentication: nil, extra_params: nil, resource: nil)
      body = {
        "grant_type" => "refresh_token",
        "refresh_token" => refresh_token
      }
      headers = {
        "content-type" => "application/x-www-form-urlencoded",
        "accept" => "application/json"
      }
      client_id = Array(options[:client_id] || options["client_id"] || options[:clientId] || options["clientId"]).first
      client_secret = options[:client_secret] || options["client_secret"] || options[:clientSecret] || options["clientSecret"]

      if authentication.to_s == "basic"
        headers["authorization"] = "Basic #{Base64.strict_encode64("#{client_id}:#{client_secret}")}"
      else
        body["client_id"] = client_id if client_id
        body["client_secret"] = client_secret if client_secret
      end

      Array(resource).each { |entry| (body["resource"] ||= []) << entry } if resource
      extra_params&.each { |key, value| body[key.to_s] = value }
      {body: body, headers: headers}
    end

    def post_form(token_endpoint, request)
      uri = URI.parse(token_endpoint)
      response = HTTPClient.post_form(uri, URI.encode_www_form(request[:body]), request[:headers])
      JSON.parse(response.body)
    end

    def stringify_keys(hash)
      hash.each_with_object({}) do |(key, value), result|
        result[key.to_s] = value.is_a?(Hash) ? stringify_keys(value) : value
      end
    end
  end
end

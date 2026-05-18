# frozen_string_literal: true

require "base64"

module BetterAuth
  module Plugins
    module_function

    def scim_store_token(ctx, config, token)
      storage = config[:store_scim_token]
      if storage == "hashed"
        Crypto.sha256(token, encoding: :base64url)
      elsif storage == "encrypted"
        Crypto.symmetric_encrypt(key: ctx.context.secret, data: token)
      elsif storage.is_a?(Hash) && storage[:hash].respond_to?(:call)
        storage[:hash].call(token)
      elsif storage.is_a?(Hash) && storage[:encrypt].respond_to?(:call)
        storage[:encrypt].call(token)
      else
        token
      end
    end

    def scim_token_matches?(ctx, config, token, stored)
      storage = config[:store_scim_token]
      return scim_token_string_matches?(Crypto.symmetric_decrypt(key: ctx.context.secret, data: stored), token) if storage == "encrypted"
      return scim_token_string_matches?(storage[:decrypt].call(stored), token) if storage.is_a?(Hash) && storage[:decrypt].respond_to?(:call)

      scim_token_string_matches?(scim_store_token(ctx, config, token), stored)
    end

    def scim_token_string_matches?(expected, provided)
      expected = expected.to_s
      provided = provided.to_s
      !provided.empty? && expected.bytesize == provided.bytesize && Crypto.constant_time_compare(expected, provided)
    end

    def scim_decode_token(encoded)
      decoded = Base64.urlsafe_decode64(encoded.to_s)
      token, provider_id, *organization_parts = decoded.split(":")
      raise scim_error("UNAUTHORIZED", "Invalid SCIM token") if token.to_s.empty? || provider_id.to_s.empty?

      [token, provider_id, organization_parts.join(":").then { |value| value.empty? ? nil : value }]
    rescue ArgumentError
      raise scim_error("UNAUTHORIZED", "Invalid SCIM token")
    end

    def scim_default_provider(config, provider_id, organization_id)
      Array(config[:default_scim]).find do |provider|
        candidate = normalize_hash(provider)
        next true if candidate[:provider_id].to_s == provider_id.to_s && organization_id.to_s.empty? && candidate[:organization_id].to_s.empty?

        candidate[:provider_id].to_s == provider_id.to_s &&
          !organization_id.to_s.empty? &&
          candidate[:organization_id].to_s == organization_id.to_s
      end&.then do |provider|
        data = normalize_hash(provider)
        {"providerId" => data[:provider_id], "scimToken" => data[:scim_token], "organizationId" => data[:organization_id]}
      end
    end
  end
end

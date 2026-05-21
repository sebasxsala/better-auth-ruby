# frozen_string_literal: true

require "openssl"
require "net/http"
require "uri"

module BetterAuth
  module Plugins
    module JWT
      SUPPORTED_ALGORITHMS = %w[EdDSA RS256 PS256 ES256 ES512].freeze

      module_function

      def public_key(jwk)
        data = stringify_jwk(jwk)
        return OpenSSL::PKey.read(data["pem"] || data["publicKey"]) if data["pem"] || data["publicKey"]

        if data["kty"] == "RSA" && data["n"] && data["e"]
          rsa_from_components(data["n"], data["e"])
        elsif data["kty"] == "OKP" && data["crv"] == "Ed25519" && data["x"]
          OpenSSL::PKey.new_raw_public_key("ED25519", Crypto.base64url_decode(data["x"]))
        else
          raise OpenSSL::PKey::PKeyError, "Unsupported JWK"
        end
      end

      def rsa_from_components(n, e)
        sequence = OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::Integer(OpenSSL::BN.new(Crypto.base64url_decode(n).unpack1("H*"), 16)),
          OpenSSL::ASN1::Integer(OpenSSL::BN.new(Crypto.base64url_decode(e).unpack1("H*"), 16))
        ])
        OpenSSL::PKey::RSA.new(sequence.to_der)
      end

      def stringify_jwk(value)
        value.each_with_object({}) { |(key, object_value), result| result[key.to_s] = object_value } if value.is_a?(Hash)
      end
    end

    module_function

    def jwt(options = {})
      config = normalize_hash(options)
      validate_jwt_options!(config)
      jwks_path = config.dig(:jwks, :jwks_path) || "/jwks"

      Plugin.new(
        id: "jwt",
        endpoints: {
          get_jwks: get_jwks_endpoint(config, jwks_path),
          get_token: get_token_endpoint(config),
          sign_jwt: sign_jwt_endpoint(config),
          verify_jwt: verify_jwt_endpoint(config)
        },
        hooks: {
          after: [
            {
              matcher: ->(ctx) { ctx.path == "/get-session" },
              handler: ->(ctx) { set_jwt_header(ctx, config) }
            }
          ]
        },
        schema: {
          jwks: {
            fields: {
              id: {type: "string", required: true},
              publicKey: {type: "string", required: true},
              privateKey: {type: "string", required: true},
              createdAt: {type: "date", required: true},
              expiresAt: {type: "date", required: false},
              alg: {type: "string", required: false},
              kty: {type: "string", required: false},
              crv: {type: "string", required: false},
              x: {type: "string", required: false},
              y: {type: "string", required: false},
              pem: {type: "string", required: false},
              n: {type: "string", required: false},
              e: {type: "string", required: false}
            }
          }
        },
        options: config
      )
    end

    def validate_jwt_options!(config)
      alg = config.dig(:jwks, :key_pair_config, :alg)
      if alg && !JWT::SUPPORTED_ALGORITHMS.include?(alg.to_s)
        raise Error, "JWT/JWKS algorithm #{alg} is not supported by the Ruby server. Supported algorithms: #{JWT::SUPPORTED_ALGORITHMS.join(", ")}"
      end

      if config.dig(:jwt, :sign) && !config.dig(:jwks, :remote_url)
        raise Error, "options.jwks.remoteUrl must be set when using options.jwt.sign"
      end

      if config.dig(:jwks, :remote_url) && !config.dig(:jwks, :key_pair_config, :alg)
        raise Error, "options.jwks.keyPairConfig.alg must be specified when using the oidc plugin with options.jwks.remoteUrl"
      end

      path = config.dig(:jwks, :jwks_path)
      if path && (!path.is_a?(String) || path.empty? || !path.start_with?("/") || path.include?(".."))
        raise Error, "options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '.."
      end
    end

    def get_jwks_endpoint(config, path)
      Endpoint.new(
        path: path,
        method: "GET",
        metadata: {
          openapi: {
            operationId: "getJSONWebKeySet",
            description: "Get the JSON Web Key Set",
            responses: {
              "200" => OpenAPI.json_response(
                "JSON Web Key Set retrieved successfully",
                OpenAPI.object_schema(
                  {keys: {type: "array", description: "Array of public JSON Web Keys", items: {type: "object"}}},
                  required: ["keys"]
                )
              )
            }
          }
        }
      ) do |ctx|
        raise APIError.new("NOT_FOUND") if config.dig(:jwks, :remote_url)

        create_jwk(ctx, config) if all_jwks(ctx, config).empty?
        ctx.json({keys: public_jwks(ctx, config).map { |key| public_jwk(key, config) }})
      end
    end

    def get_token_endpoint(config)
      Endpoint.new(
        path: "/token",
        method: "GET",
        metadata: {
          openapi: {
            operationId: "getJSONWebToken",
            description: "Get a JWT token",
            responses: {
              "200" => OpenAPI.json_response(
                "Success",
                OpenAPI.object_schema({token: {type: "string"}}, required: ["token"])
              )
            }
          }
        }
      ) do |ctx|
        session = Session.find_current(ctx)
        raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["FAILED_TO_GET_SESSION"]) unless session

        ctx.json({token: jwt_token(ctx, session, config)})
      end
    end

    def sign_jwt_endpoint(config)
      Endpoint.new(path: nil, method: "POST") do |ctx|
        payload = fetch_value(ctx.body, "payload") || {}
        override = normalize_hash(fetch_value(ctx.body, "overrideOptions") || {})
        ctx.json({token: sign_jwt_payload(ctx, stringify_payload(payload), deep_merge(config, override))})
      end
    end

    def verify_jwt_endpoint(config)
      Endpoint.new(path: nil, method: "POST") do |ctx|
        token = fetch_value(ctx.body, "token")
        issuer = fetch_value(ctx.body, "issuer")
        verify_options = issuer ? deep_merge(config, jwt: {issuer: issuer}) : config
        ctx.json({payload: verify_jwt_token(ctx, token, verify_options)})
      end
    end

    def set_jwt_header(ctx, config)
      return if config[:disable_setting_jwt_header]

      session = ctx.context.current_session || ctx.context.new_session
      return unless session && session[:session]

      token = jwt_token(ctx, session, config)
      exposed = ctx.response_headers["access-control-expose-headers"].to_s.split(",").map(&:strip).reject(&:empty?)
      exposed << "set-auth-jwt"
      ctx.set_header("set-auth-jwt", token)
      ctx.set_header("access-control-expose-headers", exposed.uniq.join(", "))
      nil
    end

    def jwt_token(ctx, session, config)
      jwt_config = config[:jwt] || {}
      payload = if jwt_config[:define_payload].respond_to?(:call)
        jwt_config[:define_payload].call(session)
      else
        session[:user]
      end
      subject = if jwt_config[:get_subject].respond_to?(:call)
        jwt_config[:get_subject].call(session)
      else
        session[:user]["id"]
      end
      sign_jwt_payload(ctx, stringify_payload(payload).merge("sub" => subject), config)
    end

    def sign_jwt_payload(ctx, payload, config)
      jwt_config = config[:jwt] || {}
      now = Time.now.to_i
      payload = stringify_payload(payload).dup
      payload["iat"] ||= now
      payload["exp"] ||= jwt_expiration(jwt_config[:expiration_time] || "15m", payload["iat"])
      payload["iss"] ||= jwt_config[:issuer] || ctx.context.base_url
      payload["aud"] ||= jwt_config[:audience] || ctx.context.base_url

      return jwt_config[:sign].call(payload) if jwt_config[:sign].respond_to?(:call)

      key = signing_jwk(ctx, config)
      private_key = OpenSSL::PKey.read(jwk_private_key_value(ctx, key, config))
      alg = key["alg"] || "RS256"
      return encode_eddsa_jwt(payload, private_key, key["id"]) if alg == "EdDSA"

      ::JWT.encode(payload, private_key, alg, kid: key["id"])
    end

    def verify_jwt_token(ctx, token, config)
      header = ::JWT.decode(token.to_s, nil, false).last
      key = verification_jwks(ctx, config).find { |entry| entry["id"] == header["kid"] || entry["kid"] == header["kid"] }
      return nil unless key
      return verify_eddsa_jwt(ctx, token.to_s, key, config) if (key["alg"] || header["alg"]) == "EdDSA"

      options = {
        algorithm: key["alg"] || "RS256",
        iss: config.dig(:jwt, :issuer) || ctx.context.base_url,
        verify_iss: true,
        aud: config.dig(:jwt, :audience) || ctx.context.base_url,
        verify_aud: true
      }
      decoded, = ::JWT.decode(token.to_s, JWT.public_key(key), true, options)
      jwt_payload_valid?(decoded) ? decoded : nil
    rescue ::JWT::DecodeError, OpenSSL::PKey::PKeyError
      nil
    end

    def latest_jwk(ctx, config)
      all_jwks(ctx, config).max_by { |entry| normalize_time(entry["createdAt"]) || Time.at(0) }
    end

    def signing_jwk(ctx, config)
      key = latest_jwk(ctx, config)
      return key if key && !jwk_expired?(key)

      create_jwk(ctx, config)
    end

    def public_jwks(ctx, config)
      now = Time.now
      grace_period = config.dig(:jwks, :grace_period) || 60 * 60 * 24 * 30
      all_jwks(ctx, config).select do |key|
        expires_at = normalize_time(key["expiresAt"])
        !expires_at || expires_at + grace_period.to_i > now
      end
    end

    def all_jwks(ctx, config)
      adapter = config[:adapter]
      if adapter && adapter[:get_jwks].respond_to?(:call)
        return Array(adapter[:get_jwks].call(ctx)).map { |entry| stringify_payload(entry) }
      end

      ctx.context.adapter.find_many(model: "jwks")
    end

    def verification_jwks(ctx, config)
      local = all_jwks(ctx, config)
      return local unless config.dig(:jwks, :remote_url)

      local + remote_jwks(ctx, config)
    end

    def remote_jwks(ctx, config)
      url = config.dig(:jwks, :remote_url)
      fetcher = config.dig(:jwks, :fetch) || config.dig(:jwks, :fetcher)
      payload = if fetcher.respond_to?(:call)
        fetcher.call(url)
      else
        cached = @jwt_remote_jwks_cache ||= {}
        entry = cached[url.to_s]
        if entry && entry[:expires_at] > Time.now
          entry[:payload]
        else
          fetched = HTTPClient.get_json(url)
          cached[url.to_s] = {payload: fetched, expires_at: Time.now + 300} if fetched
          fetched
        end
      end
      keys = fetch_value(payload, "keys")
      Array(keys).map { |entry| normalize_remote_jwk(entry) }
    rescue JSON::ParserError, URI::InvalidURIError, SocketError, SystemCallError
      []
    end

    def normalize_remote_jwk(entry)
      data = stringify_payload(entry || {})
      data["id"] ||= data["kid"]
      data["publicKey"] ||= data["pem"]
      data
    end

    def create_jwk(ctx, config)
      adapter = config[:adapter]
      alg = (config.dig(:jwks, :key_pair_config, :alg) || "EdDSA").to_s
      pair = generate_key_pair(alg)
      public_key = public_key_for(pair)
      public_pem = public_key_pem(public_key)
      data = {
        "id" => Crypto.uuid,
        "publicKey" => public_pem,
        "privateKey" => jwk_private_key_for_storage(ctx, private_key_pem(pair), config),
        "createdAt" => Time.now,
        "alg" => alg,
        "pem" => public_pem
      }
      data.merge!(public_key_jwk_fields(public_key, alg))
      data["expiresAt"] = Time.now + config.dig(:jwks, :rotation_interval).to_i if config.dig(:jwks, :rotation_interval)

      if adapter && adapter[:create_jwk].respond_to?(:call)
        return stringify_payload(adapter[:create_jwk].call(data, ctx))
      end

      ctx.context.adapter.create(model: "jwks", data: data, force_allow_id: true)
    end

    def public_jwk(key, _config)
      data = {
        kid: key["id"],
        kty: key["kty"] || key_type_for_alg(key["alg"] || "RS256"),
        alg: key["alg"] || "EdDSA",
        use: "sig",
        pem: key["pem"] || key["publicKey"]
      }
      data[:n] = key["n"] if key["n"]
      data[:e] = key["e"] if key["e"]
      data[:crv] = key["crv"] if key["crv"]
      data[:x] = key["x"] if key["x"]
      data[:y] = key["y"] if key["y"]
      data
    end

    def jwk_private_key_for_storage(ctx, private_key, config)
      return private_key if config.dig(:jwks, :disable_private_key_encryption)

      Crypto.symmetric_encrypt(key: ctx.context.secret_config, data: private_key)
    end

    def jwk_private_key_value(ctx, key, _config)
      value = key["privateKey"]
      Crypto.symmetric_decrypt(key: ctx.context.secret_config, data: value) || value
    end

    def jwt_payload_valid?(payload)
      return false if payload["sub"].to_s.empty?

      audience = payload["aud"]
      return false if audience.nil?
      return false if audience.respond_to?(:empty?) && audience.empty?

      true
    end

    def generate_key_pair(alg)
      case alg
      when "EdDSA"
        OpenSSL::PKey.generate_key("ED25519")
      when "RS256", "PS256"
        OpenSSL::PKey::RSA.generate(2048)
      when "ES256"
        OpenSSL::PKey::EC.generate("prime256v1")
      when "ES512"
        OpenSSL::PKey::EC.generate("secp521r1")
      else
        raise Error, "JWT/JWKS algorithm #{alg} is not supported by the Ruby server"
      end
    end

    def public_key_for(pair)
      OpenSSL::PKey.read(pair.public_to_pem)
    end

    def private_key_pem(pair)
      pair.respond_to?(:private_to_pem) ? pair.private_to_pem : pair.to_pem
    end

    def public_key_pem(pair)
      pair.respond_to?(:public_to_pem) ? pair.public_to_pem : pair.to_pem
    end

    def public_key_jwk_fields(public_key, alg)
      if public_key.is_a?(OpenSSL::PKey::RSA)
        {
          "kty" => "RSA",
          "n" => base64url_bn(public_key.n),
          "e" => base64url_bn(public_key.e)
        }
      elsif alg == "EdDSA"
        {
          "kty" => "OKP",
          "crv" => "Ed25519",
          "x" => Crypto.base64url_encode(public_key.raw_public_key)
        }
      else
        point = public_key.public_key.to_octet_string(:uncompressed).bytes
        length = (point.length - 1) / 2
        {
          "kty" => "EC",
          "crv" => ec_curve_for_alg(alg),
          "x" => Crypto.base64url_encode(point[1, length].pack("C*")),
          "y" => Crypto.base64url_encode(point[(1 + length), length].pack("C*"))
        }
      end
    end

    def key_type_for_alg(alg)
      return "OKP" if alg == "EdDSA"

      alg.to_s.start_with?("ES") ? "EC" : "RSA"
    end

    def ec_curve_for_alg(alg)
      (alg == "ES512") ? "P-521" : "P-256"
    end

    def encode_eddsa_jwt(payload, private_key, kid)
      header = {"alg" => "EdDSA", "kid" => kid}
      signing_input = [
        Crypto.base64url_encode(JSON.generate(header)),
        Crypto.base64url_encode(JSON.generate(payload))
      ].join(".")
      signature = private_key.sign(nil, signing_input)
      "#{signing_input}.#{Crypto.base64url_encode(signature)}"
    end

    def verify_eddsa_jwt(ctx, token, key, config)
      header_segment, payload_segment, signature_segment = token.split(".", 3)
      return nil unless header_segment && payload_segment && signature_segment

      public_key = JWT.public_key(key)
      signing_input = "#{header_segment}.#{payload_segment}"
      signature = Crypto.base64url_decode(signature_segment)
      return nil unless public_key.verify(nil, signature, signing_input)

      payload = JSON.parse(Crypto.base64url_decode(payload_segment))
      now = Time.now.to_i
      return nil if payload["exp"] && payload["exp"].to_i <= now
      issuer = config.dig(:jwt, :issuer) || ctx.context.base_url
      audience = config.dig(:jwt, :audience) || ctx.context.base_url
      return nil if issuer && payload["iss"] != issuer
      return nil if audience && Array(payload["aud"]).map(&:to_s).none?(audience.to_s)
      return nil unless jwt_payload_valid?(payload)

      payload
    rescue JSON::ParserError, OpenSSL::PKey::PKeyError, ArgumentError
      nil
    end

    def jwk_expired?(key)
      expires_at = normalize_time(key["expiresAt"])
      expires_at && expires_at < Time.now
    end

    def jwt_expiration(value, iat)
      return value.to_i if value.is_a?(Integer)
      return value.to_i if value.is_a?(Time)

      iat.to_i + parse_duration(value.to_s)
    end

    def parse_duration(value)
      match = value.strip.match(/\A(-?\d+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|week|weeks|y|yr|yrs|year|years)(?:\s+from now|\s+ago)?\z/i)
      raise TypeError, "Invalid time string" unless match

      amount = match[1].to_i
      amount = -amount if value.include?("ago")
      unit = match[2].downcase
      multiplier = case unit
      when "s", "sec", "secs", "second", "seconds" then 1
      when "m", "min", "mins", "minute", "minutes" then 60
      when "h", "hr", "hrs", "hour", "hours" then 3600
      when "d", "day", "days" then 86_400
      when "w", "week", "weeks" then 604_800
      else 31_557_600
      end
      amount * multiplier
    end

    def base64url_bn(number)
      hex = number.to_s(16)
      hex = "0#{hex}" if hex.length.odd?
      Crypto.base64url_encode([hex].pack("H*"))
    end

    def deep_merge(base, override)
      normalize_hash(base || {}).merge(normalize_hash(override || {})) do |_key, old_value, new_value|
        if old_value.is_a?(Hash) && new_value.is_a?(Hash)
          deep_merge(old_value, new_value)
        else
          new_value
        end
      end
    end

    def stringify_payload(value)
      return value.each_with_object({}) { |(key, object_value), result| result[key.to_s] = stringify_payload(object_value) } if value.is_a?(Hash)
      return value.map { |entry| stringify_payload(entry) } if value.is_a?(Array)

      value
    end

    def normalize_time(value)
      return value if value.is_a?(Time)
      return nil if value.nil?

      Time.parse(value.to_s)
    end
  end
end

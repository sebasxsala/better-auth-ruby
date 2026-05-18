# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module BetterAuth
  module Plugins
    CAPTCHA_EXTERNAL_ERROR_CODES = {
      "VERIFICATION_FAILED" => "Captcha verification failed",
      "MISSING_RESPONSE" => "Missing CAPTCHA response",
      "UNKNOWN_ERROR" => "Something went wrong"
    }.freeze

    CAPTCHA_INTERNAL_ERROR_CODES = {
      "MISSING_SECRET_KEY" => "Missing secret key",
      "SERVICE_UNAVAILABLE" => "CAPTCHA service unavailable"
    }.freeze

    CAPTCHA_DEFAULT_ENDPOINTS = [
      "/sign-up/email",
      "/sign-in/email",
      "/request-password-reset"
    ].freeze

    CAPTCHA_SITE_VERIFY_URLS = {
      "cloudflare-turnstile" => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      "google-recaptcha" => "https://www.google.com/recaptcha/api/siteverify",
      "hcaptcha" => "https://api.hcaptcha.com/siteverify",
      "captchafox" => "https://api.captchafox.com/siteverify"
    }.freeze

    module_function

    def captcha(options = {})
      config = normalize_hash(options)
      Plugin.new(
        id: "captcha",
        on_request: lambda do |request, context|
          captcha_on_request(request, context, config)
        end,
        error_codes: CAPTCHA_EXTERNAL_ERROR_CODES,
        options: config
      )
    end

    def captcha_on_request(request, context, config)
      endpoints = Array(config[:endpoints]).empty? ? CAPTCHA_DEFAULT_ENDPOINTS : Array(config[:endpoints])
      return nil unless endpoints.any? { |endpoint| request.path_info.include?(endpoint.to_s) || request.url.include?(endpoint.to_s) }

      raise CAPTCHA_INTERNAL_ERROR_CODES["MISSING_SECRET_KEY"] if config[:secret_key].to_s.empty?

      response_token = request.get_header("HTTP_X_CAPTCHA_RESPONSE")
      if response_token.to_s.empty?
        return {response: captcha_response(400, "MISSING_RESPONSE", CAPTCHA_EXTERNAL_ERROR_CODES["MISSING_RESPONSE"])}
      end

      result = captcha_verify(config, response_token, captcha_remote_ip(request, context))
      return nil if captcha_success?(config, result)

      {response: captcha_response(403, "VERIFICATION_FAILED", CAPTCHA_EXTERNAL_ERROR_CODES["VERIFICATION_FAILED"])}
    rescue => error
      captcha_log(context, error.message)
      {response: captcha_response(500, "UNKNOWN_ERROR", CAPTCHA_EXTERNAL_ERROR_CODES["UNKNOWN_ERROR"])}
    end

    def captcha_verify(config, response_token, remote_ip)
      provider = config[:provider].to_s
      url = config[:site_verify_url_override] || CAPTCHA_SITE_VERIFY_URLS.fetch(provider)
      params = {
        site_verify_url: url,
        secret_key: config[:secret_key],
        captcha_response: response_token,
        remote_ip: remote_ip,
        site_key: config[:site_key],
        min_score: config[:min_score],
        provider: provider
      }
      return captcha_normalize_verifier_response(config[:verifier].call(captcha_verifier_params(params))) if config[:verifier].respond_to?(:call)

      captcha_http_verify(params)
    end

    def captcha_verifier_params(params)
      provider = params.fetch(:provider)
      payload = captcha_payload(provider, params)
      content_type = (provider == "cloudflare-turnstile") ? "application/json" : "application/x-www-form-urlencoded"
      {
        url: params.fetch(:site_verify_url),
        content_type: content_type,
        payload: payload,
        provider: provider
      }
    end

    def captcha_http_verify(params)
      verifier = captcha_verifier_params(params)
      uri = URI.parse(verifier[:url])
      request = Net::HTTP::Post.new(uri)
      request["Content-Type"] = verifier[:content_type]
      request.body = if verifier[:content_type] == "application/json"
        JSON.generate(verifier[:payload])
      else
        URI.encode_www_form(verifier[:payload])
      end
      response = HTTPClient.request(uri, request)
      raise CAPTCHA_INTERNAL_ERROR_CODES["SERVICE_UNAVAILABLE"] unless response.is_a?(Net::HTTPSuccess)

      JSON.parse(response.body.to_s)
    rescue JSON::ParserError
      raise CAPTCHA_INTERNAL_ERROR_CODES["SERVICE_UNAVAILABLE"]
    end

    def captcha_payload(provider, params)
      payload = {
        "secret" => params[:secret_key],
        "response" => params[:captcha_response]
      }
      payload["sitekey"] = params[:site_key] if params[:site_key] && ["hcaptcha", "captchafox"].include?(provider)
      if params[:remote_ip]
        payload[(provider == "captchafox") ? "remoteIp" : "remoteip"] = params[:remote_ip]
      end
      payload
    end

    def captcha_success?(config, result)
      return false unless result && result["success"]

      if config[:provider].to_s == "google-recaptcha" && result.key?("score")
        return result["score"].to_f >= (config[:min_score] || 0.5).to_f
      end

      true
    end

    def captcha_normalize_verifier_response(value)
      return value.transform_keys(&:to_s) if value.is_a?(Hash)

      {}
    end

    def captcha_response(status, code, message)
      [status, {"content-type" => "application/json"}, [JSON.generate({code: code, message: message})]]
    end

    def captcha_remote_ip(request, context)
      RequestIP.client_ip(request, context.options)
    end

    def captcha_log(context, message)
      logger = context.logger
      if logger.respond_to?(:call)
        logger.call(:error, message)
      elsif logger.respond_to?(:error)
        logger.error(message)
      end
    end
  end
end

# frozen_string_literal: true

require "uri"

module BetterAuth
  module URLHelpers
    module_function

    def valid_proxy_header?(header, type)
      value = header.to_s
      return false if value.strip.empty?

      case type.to_sym
      when :proto
        ["http", "https"].include?(value)
      when :host
        return false if value.match?(/\.\.|\0|\s|\A[.]|[<>'"]|javascript:|file:|data:/i)
        return false if value.match?(%r{[/\\]})

        patterns = [
          /\A[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(:[0-9]{1,5})?\z/,
          /\A(\d{1,3}\.){3}\d{1,3}(:[0-9]{1,5})?\z/,
          /\A\[[0-9a-fA-F:]+\](:[0-9]{1,5})?\z/,
          /\Alocalhost(:[0-9]{1,5})?\z/i
        ]
        patterns.any? { |pattern| value.match?(pattern) } && valid_port?(value)
      else
        false
      end
    end

    def matches_host_pattern?(host, pattern)
      return false if host.to_s.empty? || pattern.to_s.empty?

      normalized_host = normalize_host_pattern_value(host)
      normalized_pattern = normalize_host_pattern_value(pattern)
      regex = Regexp.escape(normalized_pattern)
        .gsub("\\*", ".*")
        .gsub("\\?", ".")
      !!normalized_host.match?(/\A#{regex}\z/i)
    end

    def host_from_source(source, trusted_proxy_headers: false)
      headers = headers_from_source(source)
      if trusted_proxy_headers
        forwarded_host = header_value(headers, "x-forwarded-host")
        return forwarded_host if forwarded_host && valid_proxy_header?(forwarded_host, :host)
      end

      host = header_value(headers, "host")
      return host if host && valid_proxy_header?(host, :host)

      uri_host(source_url(source))
    end

    def protocol_from_source(source, config_protocol: nil, trusted_proxy_headers: false)
      return config_protocol if ["http", "https"].include?(config_protocol)

      headers = headers_from_source(source)
      if trusted_proxy_headers
        forwarded_proto = header_value(headers, "x-forwarded-proto")
        return forwarded_proto if forwarded_proto && valid_proxy_header?(forwarded_proto, :proto)
      end

      protocol = uri_scheme(source_url(source))
      return protocol if ["http", "https"].include?(protocol)

      host = host_from_source(source, trusted_proxy_headers: trusted_proxy_headers)
      return "http" if host && loopback_for_dev_scheme?(host)

      "https"
    end

    def resolve_base_url(config, base_path, source = nil, load_env: true, trusted_proxy_headers: false)
      if dynamic_config?(config)
        return resolve_dynamic_base_url(config, source, base_path, trusted_proxy_headers: trusted_proxy_headers) if source
        return with_path(config[:fallback] || config["fallback"], base_path) if config[:fallback] || config["fallback"]

        return env_base_url(base_path) if load_env
        return nil
      end

      return with_path(config, base_path) if config.is_a?(String)
      return env_base_url(base_path) if load_env
      return with_path(origin(source_url(source)), base_path) if source

      nil
    end

    def resolve_dynamic_base_url(config, source, base_path, trusted_proxy_headers: false)
      host = host_from_source(source, trusted_proxy_headers: trusted_proxy_headers)
      fallback = config[:fallback] || config["fallback"]
      raise Error, "Could not determine host from request headers. Please provide a fallback URL in your baseURL config." unless host || fallback

      allowed_hosts = config[:allowed_hosts] || config["allowed_hosts"] || config[:allowedHosts] || config["allowedHosts"] || []
      if host && allowed_hosts.any? { |pattern| matches_host_pattern?(host, pattern) }
        protocol = protocol_from_source(source, config_protocol: config[:protocol] || config["protocol"], trusted_proxy_headers: trusted_proxy_headers)
        return with_path("#{protocol}://#{host}", base_path)
      end

      return with_path(fallback, base_path) if fallback

      raise Error, "Host \"#{host}\" is not in the allowed hosts list."
    end

    def with_path(url, path = "/api/auth")
      parsed = URI.parse(url.to_s)
      raise Error, "Invalid base URL: #{url}. URL must include 'http://' or 'https://'" unless ["http", "https"].include?(parsed.scheme)

      current_path = parsed.path.to_s.gsub(%r{/+\z}, "")
      return url.to_s if !current_path.empty? && current_path != "/"

      trimmed = url.to_s.gsub(%r{/+\z}, "")
      return trimmed if path.to_s.empty? || path == "/"

      suffix = path.start_with?("/") ? path : "/#{path}"
      "#{trimmed}#{suffix}"
    rescue URI::InvalidURIError
      raise Error, "Invalid base URL: #{url}. Please provide a valid base URL."
    end

    def origin(url)
      parsed = URI.parse(url.to_s)
      return nil unless ["http", "https"].include?(parsed.scheme)

      port = parsed.port
      default_port = (parsed.scheme == "http" && port == 80) || (parsed.scheme == "https" && port == 443)
      default_port ? "#{parsed.scheme}://#{parsed.host}" : "#{parsed.scheme}://#{parsed.host}:#{port}"
    rescue URI::InvalidURIError
      nil
    end

    def uri_host(url)
      parsed = URI.parse(url.to_s)
      return nil unless parsed.host

      default_port = (parsed.scheme == "http" && parsed.port == 80) || (parsed.scheme == "https" && parsed.port == 443)
      default_port ? parsed.host : "#{parsed.host}:#{parsed.port}"
    rescue URI::InvalidURIError
      nil
    end

    def uri_scheme(url)
      URI.parse(url.to_s).scheme
    rescue URI::InvalidURIError
      nil
    end

    def normalize_host_pattern_value(value)
      value.to_s.sub(%r{\Ahttps?://}i, "").split("/").first.to_s.downcase
    end

    def headers_from_source(source)
      return {} unless source
      return source.headers if source.respond_to?(:headers)
      return rack_request_headers(source) if source.respond_to?(:get_header)
      return source if source.is_a?(Hash)

      {}
    end

    def header_value(headers, key)
      if headers.respond_to?(:get)
        headers.get(key)
      else
        headers[key] || headers[key.to_s] || headers[key.to_s.downcase] || headers[key.to_s.upcase] || headers[key.tr("-", "_").upcase]
      end
    end

    def source_url(source)
      return source.url if source.respond_to?(:url)

      source.get_header("REQUEST_URI") if source.respond_to?(:get_header)
    end

    def dynamic_config?(config)
      config.is_a?(Hash) && (config.key?(:allowed_hosts) || config.key?("allowed_hosts") || config.key?(:allowedHosts) || config.key?("allowedHosts"))
    end

    def env_base_url(base_path)
      url = Env.get("BETTER_AUTH_URL") || Env.get("NEXT_PUBLIC_BETTER_AUTH_URL") || Env.get("PUBLIC_BETTER_AUTH_URL") || Env.get("NUXT_PUBLIC_BETTER_AUTH_URL") || ENV["NUXT_PUBLIC_AUTH_URL"]
      url ||= ENV["BASE_URL"] if ENV["BASE_URL"] && ENV["BASE_URL"] != "/"
      url ? with_path(url, base_path) : nil
    end

    def loopback_for_dev_scheme?(host)
      hostname = host.to_s.sub(/:\d+\z/, "").sub(/\A\[/, "").sub(/\]\z/, "").downcase
      hostname == "localhost" || hostname.end_with?(".localhost") || hostname == "::1" || hostname.start_with?("127.")
    end

    def valid_port?(host)
      port = host[/:(\d{1,5})\z/, 1]
      return true unless port

      port.to_i.between?(1, 65_535)
    end

    def rack_request_headers(source)
      {
        "x-forwarded-host" => source.get_header("HTTP_X_FORWARDED_HOST"),
        "x-forwarded-proto" => source.get_header("HTTP_X_FORWARDED_PROTO"),
        "host" => source.get_header("HTTP_HOST")
      }.compact
    end
  end
end

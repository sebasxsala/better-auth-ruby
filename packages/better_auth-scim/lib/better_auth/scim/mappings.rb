# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def scim_user_update(body)
      email = scim_primary_email(body)&.downcase
      {
        email: email,
        name: scim_display_name(body, email),
        updatedAt: Time.now
      }.compact
    end

    def scim_display_name(body, fallback = nil)
      name = normalize_hash(body[:name] || {})
      return name[:formatted].to_s.strip unless name[:formatted].to_s.strip.empty?

      scim_full_name(fallback, given_name: name[:given_name], family_name: name[:family_name])
    end

    def scim_account_id(body)
      body[:external_id] || body[:user_name].to_s.downcase
    end

    def scim_primary_email(body)
      primary = Array(body[:emails]).find { |email| normalize_hash(email)[:primary] }
      first = Array(body[:emails]).first
      normalize_hash(primary || first)[:value] || body[:user_name]
    end

    def scim_full_name(fallback, given_name:, family_name:)
      name = [given_name, family_name].compact.join(" ").strip
      name.empty? ? fallback.to_s : name
    end

    def scim_given_name(name)
      parts = name.to_s.split
      (parts.length > 1) ? parts[0...-1].join(" ") : name.to_s
    end

    def scim_family_name(name)
      parts = name.to_s.split
      (parts.length > 1) ? parts[1..].join(" ") : ""
    end
  end
end

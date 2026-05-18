# frozen_string_literal: true

module BetterAuth
  module Roda
    class Configuration
      AUTH_OPTION_NAMES = %i[
        app_name
        base_url
        base_path
        secret
        secrets
        database
        plugins
        trusted_origins
        rate_limit
        session
        account
        user
        verification
        advanced
        email_and_password
        password_hasher
        email_verification
        social_providers
        experimental
        secondary_storage
        database_hooks
        hooks
        on_api_error
        disabled_paths
        logger
      ].freeze

      attr_accessor(*AUTH_OPTION_NAMES)

      def initialize
        @base_path = BetterAuth::Configuration::DEFAULT_BASE_PATH
        @plugins = []
        @trusted_origins = []
      end

      def to_auth_options
        AUTH_OPTION_NAMES.each_with_object({}) do |name, options|
          value = public_send(name)
          next if value.nil?
          next if value.respond_to?(:empty?) && value.empty?

          options[name] = value
        end
      end

      def copy
        self.class.new.tap do |copy|
          AUTH_OPTION_NAMES.each do |name|
            value = public_send(name)
            copy.public_send("#{name}=", deep_dup(value))
          end
        end
      end

      private

      def deep_dup(value)
        case value
        when Hash
          value.transform_values { |entry| deep_dup(entry) }
        when Array
          value.map { |entry| deep_dup(entry) }
        else
          value
        end
      end
    end
  end
end

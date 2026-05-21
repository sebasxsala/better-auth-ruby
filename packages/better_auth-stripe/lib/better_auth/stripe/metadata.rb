# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Metadata
      UNSAFE_KEYS = %w[__proto__ constructor prototype].freeze

      module_function

      def merge(internal, *user_metadata)
        user_metadata.compact
          .reduce({}) do |acc, entry|
            next acc unless entry.respond_to?(:each)

            acc.merge(entry.each_with_object({}) do |(key, value), result|
              metadata_key = metadata_key(key)
              result[metadata_key] = value unless UNSAFE_KEYS.include?(metadata_key)
            end)
          end
          .merge(internal.transform_keys { |key| metadata_key(key) })
      end

      def customer_set(internal_fields, *user_metadata)
        merge(internal_fields, *user_metadata)
      end

      def customer_get(metadata)
        {
          userId: metadata_fetch(metadata, "userId"),
          organizationId: metadata_fetch(metadata, "organizationId"),
          customerType: metadata_fetch(metadata, "customerType")
        }
      end

      def subscription_set(internal_fields, *user_metadata)
        merge(internal_fields, *user_metadata)
      end

      def subscription_get(metadata)
        {
          userId: metadata_fetch(metadata, "userId"),
          subscriptionId: metadata_fetch(metadata, "subscriptionId"),
          referenceId: metadata_fetch(metadata, "referenceId")
        }
      end

      def metadata_key(key)
        case BetterAuth::Plugins.normalize_key(key)
        when :user_id then "userId"
        when :organization_id then "organizationId"
        when :customer_type then "customerType"
        when :subscription_id then "subscriptionId"
        when :reference_id then "referenceId"
        else
          key.to_s
        end
      end

      def metadata_fetch(metadata, key)
        return nil unless metadata.respond_to?(:[])

        candidates = [key, key.to_sym, BetterAuth::Plugins.normalize_key(key), BetterAuth::Plugins.normalize_key(key).to_s]
        if metadata.respond_to?(:key?)
          candidates.each do |candidate|
            return metadata[candidate] if metadata.key?(candidate)
          end
        end

        candidates.each do |candidate|
          value = metadata[candidate]
          return value unless value.nil?
        end
        nil
      end

      def deep_merge(base, override)
        BetterAuth::Plugins.normalize_hash(base).merge(BetterAuth::Plugins.normalize_hash(override)) do |_key, old, new|
          if old.is_a?(Hash) && new.is_a?(Hash)
            deep_merge(old, new)
          else
            new
          end
        end
      end

      def stringify_keys(value)
        return value unless value.is_a?(Hash)

        value.each_with_object({}) do |(key, object), result|
          result[key.to_s] = object
          result[key.to_sym] = object
        end
      end
    end
  end
end

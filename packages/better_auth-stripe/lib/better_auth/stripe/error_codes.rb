# frozen_string_literal: true

module BetterAuth
  module Stripe
    remove_const(:ERROR_CODES) if const_defined?(:ERROR_CODES, false)

    ERROR_CODES = {
      "UNAUTHORIZED" => "Unauthorized access",
      "EMAIL_VERIFICATION_REQUIRED" => "Email verification required",
      "SUBSCRIPTION_NOT_FOUND" => "Subscription not found",
      "SUBSCRIPTION_PLAN_NOT_FOUND" => "Subscription plan not found",
      "FAILED_TO_FETCH_PLANS" => "Failed to fetch plans",
      "ALREADY_SUBSCRIBED_PLAN" => "You're already subscribed to this plan",
      "REFERENCE_ID_NOT_ALLOWED" => "Reference id is not allowed",
      "CUSTOMER_NOT_FOUND" => "Stripe customer not found for this user",
      "UNABLE_TO_CREATE_CUSTOMER" => "Unable to create customer",
      "UNABLE_TO_CREATE_BILLING_PORTAL" => "Unable to create billing portal session",
      "ORGANIZATION_NOT_FOUND" => "Organization not found",
      "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED" => "Organization subscription is not enabled",
      "AUTHORIZE_REFERENCE_REQUIRED" => "Organization subscriptions require authorizeReference callback to be configured",
      "ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION" => "Cannot delete organization with active subscription",
      "ORGANIZATION_REFERENCE_ID_REQUIRED" => "Reference ID is required. Provide referenceId or set activeOrganizationId in session",
      "SUBSCRIPTION_NOT_ACTIVE" => "Subscription is not active",
      "SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION" => "Subscription is not scheduled for cancellation",
      "SUBSCRIPTION_NOT_PENDING_CHANGE" => "Subscription has no pending cancellation or scheduled plan change",
      "STRIPE_SIGNATURE_NOT_FOUND" => "Stripe signature not found",
      "STRIPE_WEBHOOK_SECRET_NOT_FOUND" => "Stripe webhook secret not found",
      "FAILED_TO_CONSTRUCT_STRIPE_EVENT" => "Failed to construct Stripe event",
      "STRIPE_WEBHOOK_ERROR" => "Stripe webhook error",
      "INVALID_CUSTOMER_TYPE" => "Customer type must be either user or organization",
      "INVALID_REQUEST_BODY" => "Invalid request body"
    }.freeze
  end
end

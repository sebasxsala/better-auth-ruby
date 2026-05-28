# frozen_string_literal: true

module BetterAuth
  module Plugins
    SSO_DEFAULT_OIDC_HTTP_TIMEOUT = 10
    SSO_DEFAULT_OIDC_HTTP_MAX_BODY_SIZE = 1024 * 1024
    SSO_OIDC_PKCE_VERIFIER_KEY_PREFIX = "oidc-pkce-verifier:"
  end
end

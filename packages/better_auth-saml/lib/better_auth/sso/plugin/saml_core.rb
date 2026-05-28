# frozen_string_literal: true

module BetterAuth
  module Plugins
    SSO_SAML_SIGNATURE_ALGORITHMS = {
      "rsa-sha1" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      "rsa-sha256" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      "rsa-sha384" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
      "rsa-sha512" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
      "ecdsa-sha256" => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
      "ecdsa-sha384" => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
      "ecdsa-sha512" => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
      "sha1" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      "sha256" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      "sha384" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
      "sha512" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    }.freeze

    SSO_SAML_DIGEST_ALGORITHMS = {
      "sha1" => "http://www.w3.org/2000/09/xmldsig#sha1",
      "sha256" => "http://www.w3.org/2001/04/xmlenc#sha256",
      "sha384" => "http://www.w3.org/2001/04/xmldsig-more#sha384",
      "sha512" => "http://www.w3.org/2001/04/xmlenc#sha512"
    }.freeze

    SSO_SAML_SECURE_SIGNATURE_ALGORITHMS = (SSO_SAML_SIGNATURE_ALGORITHMS.values - ["http://www.w3.org/2000/09/xmldsig#rsa-sha1"]).uniq.freeze
    SSO_SAML_SECURE_DIGEST_ALGORITHMS = (SSO_SAML_DIGEST_ALGORITHMS.values - ["http://www.w3.org/2000/09/xmldsig#sha1"]).uniq.freeze
    SSO_SAML_SECURE_KEY_ENCRYPTION_ALGORITHMS = %w[
      http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
      http://www.w3.org/2009/xmlenc11#rsa-oaep
    ].freeze
    SSO_SAML_SECURE_DATA_ENCRYPTION_ALGORITHMS = %w[
      http://www.w3.org/2001/04/xmlenc#aes128-cbc
      http://www.w3.org/2001/04/xmlenc#aes192-cbc
      http://www.w3.org/2001/04/xmlenc#aes256-cbc
      http://www.w3.org/2009/xmlenc11#aes128-gcm
      http://www.w3.org/2009/xmlenc11#aes192-gcm
      http://www.w3.org/2009/xmlenc11#aes256-gcm
    ].freeze
    SSO_DEFAULT_MAX_SAML_RESPONSE_SIZE = 256 * 1024
    SSO_DEFAULT_MAX_SAML_METADATA_SIZE = 100 * 1024
    SSO_SAML_RELAY_STATE_KEY_PREFIX = "saml-relay-state:"
    SSO_SAML_AUTHN_REQUEST_KEY_PREFIX = "saml-authn-request:"
    SSO_DEFAULT_AUTHN_REQUEST_TTL_MS = 5 * 60 * 1000
    SSO_SAML_USED_ASSERTION_KEY_PREFIX = "saml-used-assertion:"
    SSO_DEFAULT_ASSERTION_TTL_MS = 15 * 60 * 1000
    SSO_DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000
    SSO_SAML_SESSION_KEY_PREFIX = "saml-session:"
    SSO_SAML_SESSION_BY_ID_KEY_PREFIX = "saml-session-by-id:"
    SSO_SAML_LOGOUT_REQUEST_KEY_PREFIX = "saml-logout-request:"
    SSO_SAML_STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
    SSO_DEFAULT_LOGOUT_REQUEST_TTL_MS = 5 * 60 * 1000
  end
end

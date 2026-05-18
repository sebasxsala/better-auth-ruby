# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_provider_schema
      {
        oauthClient: {
          modelName: "oauthClient",
          fields: {
            clientId: {type: "string", unique: true, required: true},
            clientSecret: {type: "string", required: false},
            disabled: {type: "boolean", default_value: false, required: false},
            skipConsent: {type: "boolean", required: false},
            enableEndSession: {type: "boolean", required: false},
            clientSecretExpiresAt: {type: "number", required: false},
            scopes: {type: "string[]", required: false},
            userId: {type: "string", required: false, index: true},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }},
            name: {type: "string", required: false},
            uri: {type: "string", required: false},
            icon: {type: "string", required: false},
            contacts: {type: "string[]", required: false},
            tos: {type: "string", required: false},
            policy: {type: "string", required: false},
            softwareId: {type: "string", required: false},
            softwareVersion: {type: "string", required: false},
            softwareStatement: {type: "string", required: false},
            redirectUris: {type: "string[]", required: true},
            postLogoutRedirectUris: {type: "string[]", required: false},
            tokenEndpointAuthMethod: {type: "string", required: false},
            grantTypes: {type: "string[]", required: false},
            responseTypes: {type: "string[]", required: false},
            public: {type: "boolean", required: false},
            type: {type: "string", required: false},
            requirePKCE: {type: "boolean", required: false},
            subjectType: {type: "string", required: false},
            referenceId: {type: "string", required: false, index: true},
            metadata: {type: "json", required: false}
          }
        },
        oauthRefreshToken: {
          fields: {
            token: {type: "string", required: true},
            clientId: {type: "string", required: true, index: true},
            sessionId: {type: "string", required: false},
            userId: {type: "string", required: false, index: true},
            referenceId: {type: "string", required: false, index: true},
            authTime: {type: "date", required: false},
            expiresAt: {type: "date", required: false},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            revoked: {type: "date", required: false},
            scopes: {type: "string[]", required: true}
          }
        },
        oauthAccessToken: {
          modelName: "oauthAccessToken",
          fields: {
            token: {type: "string", unique: true, required: true},
            expiresAt: {type: "date", required: true},
            clientId: {type: "string", required: true, index: true},
            userId: {type: "string", required: false, index: true},
            sessionId: {type: "string", required: false},
            scopes: {type: "string[]", required: true},
            revoked: {type: "date", required: false},
            referenceId: {type: "string", required: false},
            authTime: {type: "date", required: false},
            refreshId: {type: "string", required: false, index: true},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }}
          }
        },
        oauthConsent: {
          modelName: "oauthConsent",
          fields: {
            clientId: {type: "string", required: true, index: true},
            userId: {type: "string", required: false, index: true},
            referenceId: {type: "string", required: false, index: true},
            scopes: {type: "string[]", required: true},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }}
          }
        }
      }
    end
  end
end

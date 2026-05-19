# frozen_string_literal: true

require "securerandom"
require "time"
require "json"

require "better_auth/api_key"
require "better_auth/oauth_provider"
require "better_auth/passkey"
require "better_auth/scim"
require "better_auth/sso"
require "better_auth/stripe"

module BetterAuthExamples
  module PluginCatalog
    EXCLUDED_PLUGIN_IDS = [].freeze
    PLUGIN_DOCS = {
      "additional-fields" => {
        description: "Adds custom fields to the user and session payloads. This example accepts nickname, exampleRole, and deviceName during sign-up/session creation.",
        allows: ["Store app-specific user profile fields.", "Attach custom session metadata."],
        examples: [
          {label: "Use fields in sign up", method: "POST", path: "/api/auth/sign-up/email", body: {"name" => "Fields Example", "email" => "fields@example.com", "password" => "password123", "nickname" => "Ada", "exampleRole" => "member", "deviceName" => "browser"}}
        ]
      },
      "admin" => {
        description: "Adds administrative user and session management endpoints.",
        allows: ["List users.", "Ban, unban, impersonate, and update users when the caller is authorized."],
        examples: [
          {label: "List users", method: "GET", path: "/api/auth/admin/list-users"}
        ]
      },
      "anonymous" => {
        description: "Lets visitors create an anonymous account before they provide an email or social identity.",
        allows: ["Start a session without credentials.", "Later link the anonymous user to a real account."],
        examples: [
          {label: "Sign in anonymously", method: "POST", path: "/api/auth/sign-in/anonymous", body: {}}
        ]
      },
      "api-key" => {
        description: "Adds API key management for machine-to-machine or developer-token access.",
        allows: ["Create, list, update, verify, and revoke API keys.", "Attach metadata, permissions, and expiration to keys."],
        examples: [
          {label: "Create API key", method: "POST", path: "/api/auth/api-key/create", body: {"name" => "Example key"}},
          {label: "List API keys", method: "GET", path: "/api/auth/api-key/list"}
        ]
      },
      "bearer" => {
        description: "Accepts bearer tokens as an auth transport for clients that cannot rely on cookies.",
        allows: ["Authenticate requests with Authorization: Bearer tokens.", "Use session tokens from API clients."],
        examples: [
          {label: "Read current session", method: "GET", path: "/api/auth/get-session"}
        ]
      },
      "captcha" => {
        description: "Adds bot protection checks to selected auth endpoints. The example uses a local verifier so no external captcha key is required.",
        allows: ["Require captcha tokens on configured routes.", "Reject automated sign-up or sign-in attempts."],
        examples: [
          {label: "Try protected sign up", method: "POST", path: "/api/auth/sign-up/email", body: {"name" => "Captcha Example", "email" => "captcha@example.com", "password" => "password123", "captchaResponse" => "example-token"}}
        ]
      },
      "custom-session" => {
        description: "Extends the session response with app-specific data.",
        allows: ["Add computed fields to get-session responses.", "Keep framework examples close to real app session shapes."],
        examples: [
          {label: "Get custom session", method: "GET", path: "/api/auth/get-session"}
        ]
      },
      "device-authorization" => {
        description: "Implements OAuth 2.0 device authorization flow for TVs, CLIs, and limited-input devices.",
        allows: ["Create device codes.", "Poll for tokens after a user approves the code."],
        examples: [
          {label: "Create device code", method: "POST", path: "/api/auth/device/code", body: {"client_id" => "example-client", "scope" => "openid email"}}
        ]
      },
      "dub" => {
        description: "Integrates Dub short links/referral tracking around auth flows.",
        allows: ["Carry referral context through sign-up.", "Link auth users to Dub tracking data."],
        examples: [
          {label: "Start Dub link flow", method: "POST", path: "/api/auth/dub/link", body: {"callbackURL" => "/"}}
        ]
      },
      "email-otp" => {
        description: "Sends one-time passwords to email for verification and login flows.",
        allows: ["Send verification OTPs.", "Verify email-based one-time codes."],
        examples: [
          {label: "Send email OTP", method: "POST", path: "/api/auth/email-otp/send-verification-otp", body: {"email" => "ada@example.com", "type" => "email-verification"}}
        ]
      },
      "expo" => {
        description: "Supports Expo/mobile OAuth redirects and proxy callbacks.",
        allows: ["Handle mobile auth callbacks.", "Bridge OAuth URLs back into Expo clients."],
        examples: [
          {label: "Get session for mobile", method: "GET", path: "/api/auth/get-session"}
        ]
      },
      "generic-oauth" => {
        description: "Registers custom OAuth providers that are not built into the social provider list.",
        allows: ["Configure provider-specific authorize/token URLs.", "Start custom OAuth sign-in flows."],
        examples: [
          {label: "Start example OAuth", method: "POST", path: "/api/auth/sign-in/oauth2", body: {"providerId" => "example-oauth", "callbackURL" => "/", "disableRedirect" => true}}
        ]
      },
      "have-i-been-pwned" => {
        description: "Checks passwords against Have I Been Pwned before accepting them.",
        allows: ["Block compromised passwords.", "Keep the k-anonymity lookup pluggable for tests and local examples."],
        examples: [
          {label: "Try sign up check", method: "POST", path: "/api/auth/sign-up/email", body: {"name" => "Pwned Check", "email" => "pwned-check@example.com", "password" => "password123"}}
        ]
      },
      "jwt" => {
        description: "Adds JWT/JWKS endpoints for services that need signed tokens instead of cookie sessions.",
        allows: ["Issue JWTs for the current session.", "Expose public keys for token verification."],
        examples: [
          {label: "Get JWT token", method: "GET", path: "/api/auth/token"},
          {label: "Get JWKS", method: "GET", path: "/api/auth/jwks"}
        ]
      },
      "last-login-method" => {
        description: "Tracks the last method a user used to sign in.",
        allows: ["Show users their recent login method.", "Drive login UX from historical auth data."],
        examples: [
          {label: "Get current session", method: "GET", path: "/api/auth/get-session"}
        ]
      },
      "magic-link" => {
        description: "Sends passwordless sign-in links by email. This example writes the link to the local delivery inbox.",
        allows: ["Request email magic links.", "Complete passwordless sign-in from the tokenized URL."],
        examples: [
          {label: "Send magic link", method: "POST", path: "/api/auth/sign-in/magic-link", body: {"email" => "ada@example.com", "callbackURL" => "/"}}
        ]
      },
      "mcp" => {
        description: "Adds Model Context Protocol OAuth resource metadata and session endpoints.",
        allows: ["Advertise OAuth protected-resource metadata.", "Expose auth context for MCP clients."],
        examples: [
          {label: "Protected resource metadata", method: "GET", path: "/api/auth/.well-known/oauth-protected-resource"},
          {label: "MCP session", method: "GET", path: "/api/auth/mcp/get-session"}
        ]
      },
      "multi-session" => {
        description: "Lets a user keep and manage several active sessions/devices.",
        allows: ["List device sessions.", "Revoke or switch active sessions."],
        examples: [
          {label: "List device sessions", method: "GET", path: "/api/auth/multi-session/list-device-sessions"}
        ]
      },
      "oauth-provider" => {
        description: "Turns the app into an OAuth/OIDC provider for first-party or third-party clients.",
        allows: ["Expose OAuth metadata.", "Register clients and issue authorization codes/tokens."],
        examples: [
          {label: "Authorization server metadata", method: "GET", path: "/api/auth/.well-known/oauth-authorization-server"},
          {label: "Register client", method: "POST", path: "/api/auth/oauth2/register", body: {"client_name" => "Example client", "redirect_uris" => ["http://localhost:3000/callback"]}}
        ]
      },
      "oauth-proxy" => {
        description: "Proxies OAuth callbacks for environments that need an intermediate redirect handler.",
        allows: ["Forward OAuth callback parameters.", "Support hosted callback proxy deployments."],
        examples: [
          {label: "Start social flow", method: "POST", path: "/api/auth/sign-in/social", body: {"provider" => "github", "callbackURL" => "/", "disableRedirect" => true}}
        ]
      },
      "one-tap" => {
        description: "Adds Google One Tap style sign-in. The example uses a fake token verifier for local demos.",
        allows: ["Verify an ID token.", "Create or sign in the matching user."],
        examples: [
          {label: "Verify One Tap token", method: "POST", path: "/api/auth/one-tap/callback", body: {"idToken" => "example-token"}}
        ]
      },
      "one-time-token" => {
        description: "Generates one-time tokens for flows that need short-lived handoff credentials.",
        allows: ["Create one-time tokens for the current user.", "Verify a one-time token once."],
        examples: [
          {label: "Generate one-time token", method: "GET", path: "/api/auth/one-time-token/generate"}
        ]
      },
      "open-api" => {
        description: "Generates an OpenAPI schema for the enabled auth endpoints.",
        allows: ["Inspect the runtime auth API surface.", "Generate client/testing docs from enabled plugins."],
        examples: [
          {label: "Generate schema", method: "GET", path: "/api/auth/open-api/generate-schema"}
        ]
      },
      "organization" => {
        description: "Adds organization, member, invite, role, and team management.",
        allows: ["Create organizations.", "Invite members and manage active organization context."],
        examples: [
          {label: "Create organization", method: "POST", path: "/api/auth/organization/create", body: {"name" => "Example Org", "slug" => "example-org"}},
          {label: "List organizations", method: "GET", path: "/api/auth/organization/list"}
        ]
      },
      "passkey" => {
        description: "Adds WebAuthn/passkey registration and authentication endpoints.",
        allows: ["Register platform passkeys.", "Authenticate with browser WebAuthn instead of passwords."],
        examples: [
          {label: "Register options", method: "GET", path: "/api/auth/passkey/generate-register-options"},
          {label: "List user passkeys", method: "GET", path: "/api/auth/passkey/list-user-passkeys"}
        ]
      },
      "phone-number" => {
        description: "Adds phone number sign-in and verification with OTP delivery. This example writes OTPs to the local inbox.",
        allows: ["Send SMS-style OTP codes.", "Sign in or verify users by phone number."],
        examples: [
          {label: "Send phone OTP", method: "POST", path: "/api/auth/phone-number/send-otp", body: {"phoneNumber" => "+15555550100"}}
        ]
      },
      "scim" => {
        description: "Adds SCIM 2.0 provisioning endpoints for enterprise identity management.",
        allows: ["Expose SCIM service provider config.", "Provision users and groups from an IdP."],
        examples: [
          {label: "SCIM config", method: "GET", path: "/api/auth/scim/v2/ServiceProviderConfig"}
        ]
      },
      "siwe" => {
        description: "Adds Sign-In with Ethereum nonce and verification endpoints.",
        allows: ["Generate wallet login nonces.", "Verify signed wallet messages."],
        examples: [
          {label: "Create SIWE nonce", method: "POST", path: "/api/auth/siwe/nonce", body: {"walletAddress" => "0x0000000000000000000000000000000000000001"}}
        ]
      },
      "sso" => {
        description: "Adds enterprise SSO provider management and SAML/OIDC sign-in flows.",
        allows: ["Register SSO providers.", "Start SSO sign-in by domain or provider."],
        examples: [
          {label: "List SSO providers", method: "GET", path: "/api/auth/sso/providers"}
        ]
      },
      "stripe" => {
        description: "Adds Stripe customer, checkout, portal, subscription, and webhook flows using the local fake Stripe client.",
        allows: ["Create checkout and portal sessions.", "List or update subscriptions for the current user."],
        examples: [
          {label: "List subscriptions", method: "GET", path: "/api/auth/subscription/list"}
        ]
      },
      "two-factor" => {
        description: "Adds TOTP/OTP two-factor enrollment, verification, backup codes, and disable flows.",
        allows: ["Enroll TOTP.", "Verify OTP codes and manage backup codes."],
        examples: [
          {label: "Generate TOTP", method: "POST", path: "/api/auth/totp/generate", body: {}},
          {label: "Get TOTP URI", method: "POST", path: "/api/auth/two-factor/get-totp-uri", body: {"password" => "password123"}}
        ]
      },
      "username" => {
        description: "Adds username availability checks and username/password sign-in.",
        allows: ["Reserve usernames on user records.", "Sign in with username instead of email."],
        examples: [
          {label: "Check username", method: "POST", path: "/api/auth/is-username-available", body: {"username" => "ada"}},
          {label: "Sign in with username", method: "POST", path: "/api/auth/sign-in/username", body: {"username" => "ada", "password" => "password123"}}
        ]
      }
    }.freeze

    ENDPOINT_EXAMPLE_BODIES = {
      ["admin", "POST", "/admin/ban-user"] => {"userId" => "user-id", "banReason" => "Example reason"},
      ["admin", "POST", "/admin/create-user"] => {"email" => "created-by-admin@example.com", "password" => "password123", "name" => "Admin Created"},
      ["admin", "POST", "/admin/has-permission"] => {"permissions" => {"user" => ["list"]}},
      ["admin", "POST", "/admin/impersonate-user"] => {"userId" => "user-id"},
      ["admin", "POST", "/admin/revoke-user-session"] => {"sessionToken" => "session-token"},
      ["admin", "POST", "/admin/revoke-user-sessions"] => {"userId" => "user-id"},
      ["admin", "POST", "/admin/set-role"] => {"userId" => "user-id", "role" => "admin"},
      ["admin", "POST", "/admin/stop-impersonating"] => {},
      ["admin", "POST", "/admin/unban-user"] => {"userId" => "user-id"},
      ["api-key", "POST", "/api-key/create"] => {"name" => "Example key"},
      ["api-key", "POST", "/api-key/delete"] => {"keyId" => "api-key-id"},
      ["api-key", "POST", "/api-key/update"] => {"keyId" => "api-key-id", "name" => "Updated example key"},
      ["api-key", "POST", "/api-key/verify"] => {"key" => "better-auth-api-key"},
      ["device-authorization", "POST", "/device/code"] => {"client_id" => "example-client", "scope" => "openid email"},
      ["device-authorization", "POST", "/device/token"] => {"client_id" => "example-client", "device_code" => "device-code", "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"},
      ["device-authorization", "POST", "/device/approve"] => {"user_code" => "USER-CODE"},
      ["email-otp", "POST", "/email-otp/send-verification-otp"] => {"email" => "ada@example.com", "type" => "email-verification"},
      ["email-otp", "POST", "/email-otp/verify-email"] => {"email" => "ada@example.com", "otp" => "000000"},
      ["email-otp", "POST", "/sign-in/email-otp"] => {"email" => "ada@example.com", "otp" => "000000"},
      ["generic-oauth", "POST", "/sign-in/oauth2"] => {"providerId" => "example-oauth", "callbackURL" => "/", "disableRedirect" => true},
      ["magic-link", "POST", "/sign-in/magic-link"] => {"email" => "ada@example.com", "callbackURL" => "/"},
      ["oauth-provider", "POST", "/oauth2/register"] => {"client_name" => "Example client", "redirect_uris" => ["http://localhost:3000/callback"]},
      ["one-tap", "POST", "/one-tap/callback"] => {"idToken" => "example-token"},
      ["organization", "POST", "/organization/create"] => {"name" => "Example Org", "slug" => "example-org"},
      ["organization", "POST", "/organization/invite-member"] => {"email" => "member@example.com", "role" => "member"},
      ["organization", "POST", "/organization/set-active"] => {"organizationId" => "organization-id"},
      ["passkey", "POST", "/passkey/delete-passkey"] => {"id" => "passkey-id"},
      ["passkey", "POST", "/passkey/update-passkey"] => {"id" => "passkey-id", "name" => "Example passkey"},
      ["phone-number", "POST", "/phone-number/send-otp"] => {"phoneNumber" => "+15555550100"},
      ["phone-number", "POST", "/phone-number/verify"] => {"phoneNumber" => "+15555550100", "code" => "000000"},
      ["phone-number", "POST", "/sign-in/phone-number"] => {"phoneNumber" => "+15555550100", "code" => "000000"},
      ["siwe", "POST", "/siwe/nonce"] => {"walletAddress" => "0x0000000000000000000000000000000000000001"},
      ["siwe", "POST", "/siwe/verify"] => {"message" => "example message", "signature" => "0xsignature"},
      ["stripe", "POST", "/subscription/billing-portal"] => {"returnUrl" => "/"},
      ["stripe", "POST", "/subscription/cancel"] => {"subscriptionId" => "subscription-id", "returnUrl" => "/"},
      ["stripe", "POST", "/subscription/restore"] => {"subscriptionId" => "subscription-id"},
      ["stripe", "POST", "/subscription/upgrade"] => {"plan" => "example", "successUrl" => "/", "cancelUrl" => "/"},
      ["stripe", "POST", "/stripe/webhook"] => {"type" => "customer.subscription.created", "data" => {"object" => {"id" => "sub_example"}}},
      ["two-factor", "POST", "/totp/generate"] => {},
      ["two-factor", "POST", "/two-factor/disable"] => {"password" => "password123"},
      ["two-factor", "POST", "/two-factor/enable"] => {"code" => "000000"},
      ["two-factor", "POST", "/two-factor/generate-backup-codes"] => {"password" => "password123"},
      ["two-factor", "POST", "/two-factor/get-totp-uri"] => {"password" => "password123"},
      ["two-factor", "POST", "/two-factor/send-otp"] => {},
      ["two-factor", "POST", "/two-factor/verify-backup-code"] => {"code" => "backup-code"},
      ["two-factor", "POST", "/two-factor/verify-otp"] => {"code" => "000000"},
      ["two-factor", "POST", "/two-factor/verify-totp"] => {"code" => "000000"},
      ["username", "POST", "/is-username-available"] => {"username" => "ada"},
      ["username", "POST", "/sign-in/username"] => {"username" => "ada", "password" => "password123"}
    }.freeze

    module_function

    def plugins(app_name:)
      [
        BetterAuth::Plugins.additional_fields(
          user: {
            exampleRole: {type: "string", required: false},
            nickname: {type: "string", required: false}
          },
          session: {
            deviceName: {type: "string", required: false}
          }
        ),
        BetterAuth::Plugins.username(min_username_length: 3),
        BetterAuth::Plugins.anonymous,
        BetterAuth::Plugins.magic_link(send_magic_link: delivery_recorder("magic-link", :email, :url, :token)),
        BetterAuth::Plugins.email_otp(
          send_verification_otp: delivery_recorder("email-otp", :email, :otp, :type),
          send_verification_on_sign_up: true
        ),
        BetterAuth::Plugins.phone_number(send_otp: delivery_recorder("phone-number", :phone_number, :code)),
        BetterAuth::Plugins.one_time_token,
        BetterAuth::Plugins.custom_session(->(session, _ctx) { session.merge("examplePluginPage" => true) }),
        BetterAuth::Plugins.last_login_method,
        BetterAuth::Plugins.multi_session,
        BetterAuth::Plugins.bearer,
        BetterAuth::Plugins.jwt,
        BetterAuth::Plugins.open_api,
        BetterAuth::Plugins.generic_oauth(
          config: [
            {
              provider_id: "example-oauth",
              client_id: "example-client",
              client_secret: "example-secret",
              authorization_url: "https://example.com/oauth/authorize",
              token_url: "https://example.com/oauth/token",
              scopes: ["profile", "email"]
            }
          ]
        ),
        BetterAuth::Plugins.one_tap(
          client_id: "example-google-client",
          verify_id_token: ->(_id_token, _ctx, **_options) {
            {
              sub: SecureRandom.hex(8),
              email: "one-tap@example.test",
              email_verified: true,
              name: "One Tap Example"
            }
          }
        ),
        BetterAuth::Plugins.siwe(
          get_nonce: -> { SecureRandom.hex(16) },
          verify_message: ->(*_args) { true },
          email_domain_name: "wallet.example.test"
        ),
        BetterAuth::Plugins.dub,
        BetterAuth::Plugins.oauth_proxy,
        BetterAuth::Plugins.expo,
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.admin,
        BetterAuth::Plugins.api_key,
        BetterAuth::Plugins.passkey,
        BetterAuth::Plugins.oauth_provider(
          login_page: "/",
          consent_page: "/oauth2/consent",
          allow_dynamic_client_registration: true,
          allow_unauthenticated_client_registration: true
        ),
        BetterAuth::Plugins.scim,
        BetterAuth::Plugins.sso,
        BetterAuth::Plugins.stripe(
          stripe_client: StripeClient.new,
          subscription: {
            enabled: true,
            plans: [
              {
                name: "example",
                price_id: "price_example_monthly",
                annual_discount_price_id: "price_example_yearly"
              }
            ]
          }
        ),
        BetterAuth::Plugins.device_authorization,
        BetterAuth::Plugins.mcp(login_page: "/"),
        BetterAuth::Plugins.two_factor(
          issuer: app_name,
          otp_options: {send_otp: delivery_recorder("two-factor", :email, :otp)}
        ),
        BetterAuth::Plugins.captcha(
          secret_key: "example-secret",
          provider: "google-recaptcha",
          endpoints: ["/sign-up/email"],
          verifier: ->(_params) { {success: true} }
        ),
        BetterAuth::Plugins.have_i_been_pwned(range_lookup: ->(_prefix) { "" })
      ]
    end

    def metadata_for(auth)
      auth.context.options.plugins.map do |plugin|
        docs = PLUGIN_DOCS.fetch(plugin.id, fallback_docs_for(plugin))
        endpoints = endpoint_signatures(plugin)
        {
          id: plugin.id,
          description: docs.fetch(:description),
          allows: docs.fetch(:allows),
          examples: docs.fetch(:examples),
          endpoints: endpoints.map { |endpoint| "#{endpoint.fetch(:method)} #{endpoint.fetch(:path)}" },
          endpoint_actions: endpoints.map { |endpoint| endpoint_action_for(plugin, endpoint) },
          schema_tables: plugin.schema.keys.map(&:to_s).sort,
          hooks: {
            before: plugin.hooks.fetch(:before, []).length,
            after: plugin.hooks.fetch(:after, []).length
          }
        }
      end.sort_by { |plugin| plugin[:id] }
    end

    def endpoint_signatures(plugin)
      plugin.endpoints.values.flat_map do |endpoint|
        endpoint.methods.map do |method|
          {
            method: method.to_s.upcase,
            path: normalize_endpoint_path(endpoint.path)
          }
        end
      end.sort_by { |endpoint| [endpoint.fetch(:path), endpoint.fetch(:method)] }
    end

    def endpoint_action_for(plugin, endpoint)
      method = endpoint.fetch(:method)
      path = endpoint.fetch(:path)
      body = endpoint_body_for(plugin.id, method, path)
      {
        label: "#{method} #{path}",
        method: method,
        path: auth_path(path),
        body: body
      }.compact
    end

    def endpoint_body_for(plugin_id, method, path)
      doc_example = PLUGIN_DOCS
        .fetch(plugin_id, {})
        .fetch(:examples, [])
        .find { |example| example[:method].to_s.upcase == method && normalize_endpoint_path(example[:path].to_s.sub(%r{\A/api/auth}, "")) == path && example.key?(:body) }
      return doc_example[:body] if doc_example
      return ENDPOINT_EXAMPLE_BODIES.fetch([plugin_id, method, path]) if ENDPOINT_EXAMPLE_BODIES.key?([plugin_id, method, path])

      %w[POST PUT PATCH DELETE].include?(method) ? {} : nil
    end

    def normalize_endpoint_path(path)
      value = path.to_s.strip
      return "/" if value.empty?

      value.start_with?("/") ? value : "/#{value}"
    end

    def auth_path(path)
      (path == "/") ? "/api/auth" : "/api/auth#{path}"
    end

    def fallback_docs_for(plugin)
      {
        description: "#{plugin.id} is enabled in this example app.",
        allows: ["Inspect its generated endpoints, schema tables, and hooks."],
        examples: [
          {label: "Read session", method: "GET", path: "/api/auth/get-session"}
        ]
      }
    end

    def deliveries
      (@deliveries ||= []).last(30).reverse
    end

    def clear_deliveries!
      (@deliveries ||= []).clear
    end

    def delivery_recorder(plugin_id, *keys)
      lambda do |data, *_args|
        payload = normalize_hash(data)
        values = keys.each_with_object({}) do |key, result|
          value = payload[key] || payload[key.to_s] || payload[camelize(key)]
          result[key] = value unless value.nil?
        end
        record_delivery(plugin_id, values)
      end
    end

    def record_delivery(plugin_id, payload)
      @deliveries ||= []
      @deliveries << {
        plugin: plugin_id,
        payload: payload,
        created_at: Time.now.utc.iso8601
      }
      @deliveries.shift while @deliveries.length > 30
    end

    def normalize_hash(value)
      return {} unless value.is_a?(Hash)

      value
    end

    def camelize(key)
      parts = key.to_s.split("_")
      ([parts.first] + parts.drop(1).map(&:capitalize)).join
    end

    class StripeClient
      def customers
        CustomerResource.new
      end

      def checkout
        CheckoutResource.new
      end

      def billing_portal
        BillingPortalResource.new
      end

      def subscriptions
        SubscriptionResource.new
      end

      def webhooks
        WebhookResource.new
      end
    end

    class CustomerResource
      def create(params = {})
        {"id" => "cus_example", "email" => params[:email] || params["email"], "name" => params[:name] || params["name"]}
      end

      def retrieve(id)
        {"id" => id, "deleted" => false}
      end

      def search(**_params)
        {"data" => []}
      end

      def list(**_params)
        {"data" => []}
      end

      def update(id, params = {})
        {"id" => id}.merge(params.transform_keys(&:to_s))
      end
    end

    class CheckoutResource
      def sessions
        CheckoutSessionResource.new
      end
    end

    class CheckoutSessionResource
      def create(_params = {})
        {"id" => "cs_example", "url" => "/example/stripe/checkout"}
      end
    end

    class BillingPortalResource
      def sessions
        BillingPortalSessionResource.new
      end
    end

    class BillingPortalSessionResource
      def create(_params = {})
        {"id" => "bps_example", "url" => "/example/stripe/billing"}
      end
    end

    class SubscriptionResource
      def retrieve(id)
        {"id" => id, "status" => "active"}
      end

      def update(id, params = {})
        {"id" => id}.merge(params.transform_keys(&:to_s))
      end

      def cancel(id, params = {})
        {"id" => id, "status" => "canceled"}.merge(params.transform_keys(&:to_s))
      end

      def list(**_params)
        {"data" => []}
      end
    end

    class WebhookResource
      def construct_event(payload, _signature, _secret)
        JSON.parse(payload)
      end
    end
  end
end

# frozen_string_literal: true

require "securerandom"
require "json"
require "time"

module BetterAuthExamples
  module ExampleSeeder
    PASSWORD = "password123"
    USER_FIXTURES = [
      ["admin@example.test", "Example Admin", "admin", "Platform"],
      ["owner@example.test", "Olivia Owner", "user", "Product"],
      ["member@example.test", "Mina Member", "user", "Product"],
      ["billing@example.test", "Ben Billing", "user", "Finance"],
      ["support@example.test", "Sofia Support", "user", "Support"],
      ["viewer@example.test", "Victor Viewer", "user", "Support"],
      ["developer@example.test", "Devon Developer", "user", "Engineering"],
      ["designer@example.test", "Dina Designer", "user", "Design"],
      ["qa@example.test", "Quinn QA", "user", "Quality"],
      ["solo@example.test", "Sam Solo", "user", "Independent"],
      ["banned@example.test", "Blair Banned", "user", "Risk"],
      ["oauth@example.test", "Oscar OAuth", "user", "Identity"]
    ].freeze

    ORGANIZATION_FIXTURES = [
      ["acme-labs", "Acme Labs"],
      ["northwind", "Northwind"],
      ["orbit-studio", "Orbit Studio"]
    ].freeze

    module_function

    def reset_and_seed!(registry, settings)
      auth = registry.reset_database!(settings)
      seed!(auth)
    end

    def seed!(auth)
      now = Time.now
      users = seed_users(auth, now)
      organizations = seed_organizations(auth, users, now)
      seed_plugin_records(auth, users, organizations, now)

      {users: users_for_dashboard(auth), organizations: organizations}
    end

    def organizations_for_dashboard(auth)
      organizations = find_many_or_empty(auth, "organization")
      members = find_many_or_empty(auth, "member")
      users = auth.context.internal_adapter.list_users(limit: 500).to_h { |user| [user["id"], user] }
      members_by_organization = members.group_by { |member| member["organizationId"] }

      organizations.sort_by { |organization| organization["name"].to_s }.map do |organization|
        {
          id: organization["id"],
          name: organization["name"],
          slug: organization["slug"],
          metadata: organization["metadata"],
          members: Array(members_by_organization[organization["id"]]).map do |member|
            user = users[member["userId"]] || {}
            {
              id: member["id"],
              user_id: member["userId"],
              name: user["name"],
              email: user["email"],
              username: user["username"],
              role: member["role"],
              global_role: user["role"] || "user",
              created_at: member["createdAt"]
            }
          end.sort_by { |member| [(member[:role].to_s == "owner") ? 0 : 1, member[:email].to_s] }
        }
      end
    end

    def users_for_dashboard(auth)
      users = auth.context.internal_adapter.list_users(limit: 200, sort_by: {field: "email", direction: "asc"})
      members = find_many_or_empty(auth, "member")
      organizations = find_many_or_empty(auth, "organization")
      orgs_by_id = organizations.to_h { |org| [org["id"], org] }
      memberships_by_user = members.group_by { |member| member["userId"] }

      users.map do |user|
        {
          id: user["id"],
          email: user["email"],
          name: user["name"],
          role: user["role"] || "user",
          email_verified: user["emailVerified"],
          organizations: Array(memberships_by_user[user["id"]]).map do |member|
            organization = orgs_by_id[member["organizationId"]] || {}
            {
              id: member["organizationId"],
              name: organization["name"],
              slug: organization["slug"],
              role: member["role"]
            }
          end
        }
      end
    end

    def seed_users(auth, now)
      USER_FIXTURES.map.with_index do |(email, name, role, example_role), index|
        response = auth.api.sign_up_email(
          body: {
            email: email,
            password: PASSWORD,
            name: name,
            image: "https://api.dicebear.com/9.x/initials/svg?seed=#{email}",
            nickname: name.split.first,
            exampleRole: example_role,
            captchaResponse: "example-token"
          },
          return_headers: true
        )
        user = (response[:response] || response["response"]).fetch(:user) { |key| (response[:response] || response["response"]).fetch(key.to_s) }
        updates = {emailVerified: true}
        updates[:role] = "admin" if role == "admin"
        updates[:banned] = true if email == "banned@example.test"
        updates[:banReason] = "Seeded banned user for admin testing" if email == "banned@example.test"
        updates[:phoneNumber] = "+1555000#{format("%04d", index)}"
        updates[:phoneNumberVerified] = true
        auth.context.internal_adapter.update_user(user.fetch("id"), updates)
      end
    end

    def find_many_or_empty(auth, model)
      auth.context.adapter.find_many(model: model, where: [])
    rescue KeyError, NoMethodError, BetterAuth::APIError
      []
    end

    def seed_organizations(auth, users, now)
      admin, owner, member, billing, support, viewer, developer, designer, qa = users
      created = ORGANIZATION_FIXTURES.map.with_index do |(slug, name), index|
        owner_user = [admin, owner, support][index]
        organization = auth.api.create_organization(body: {name: name, slug: slug, userId: owner_user.fetch("id")})
        organization.fetch(:response) { organization }
      end

      add_member(auth, created[0], owner, "owner")
      add_member(auth, created[0], member, "member")
      add_member(auth, created[0], billing, "admin")
      add_member(auth, created[1], viewer, "member")
      add_member(auth, created[1], developer, "admin")
      add_member(auth, created[2], designer, "member")
      add_member(auth, created[2], qa, "member")

      created.each_with_index do |organization, index|
        safe_create(auth, "invitation", {
          organizationId: organization.fetch("id"),
          email: "invitee-#{index + 1}@example.test",
          role: "member",
          status: "pending",
          expiresAt: now + 172_800,
          inviterId: users[index].fetch("id")
        })
      end
      created
    end

    def add_member(auth, organization, user, role)
      existing = auth.context.adapter.find_one(
        model: "member",
        where: [{field: "organizationId", value: organization.fetch("id")}, {field: "userId", value: user.fetch("id")}]
      )
      return existing if existing

      auth.context.adapter.create(model: "member", data: {organizationId: organization.fetch("id"), userId: user.fetch("id"), role: role, createdAt: Time.now})
    end

    def seed_plugin_records(auth, users, organizations, now)
      admin = users.first
      oauth_client_id = "example-seeded-client"
      safe_create(auth, "oauthClient", {
        clientId: oauth_client_id,
        clientSecret: "example-secret",
        name: "Seeded MCP Client",
        redirectUris: ["http://localhost:3000/callback"],
        scopes: ["openid", "profile", "email"],
        userId: admin.fetch("id"),
        disabled: false,
        public: false
      })
      safe_create(auth, "oauthAccessToken", {
        token: SecureRandom.hex(24),
        clientId: oauth_client_id,
        userId: admin.fetch("id"),
        scopes: ["profile"],
        expiresAt: now + 3600
      })
      safe_create(auth, "oauthRefreshToken", {
        token: SecureRandom.hex(24),
        clientId: oauth_client_id,
        userId: admin.fetch("id"),
        referenceId: admin.fetch("id"),
        scopes: ["openid", "profile", "email"],
        expiresAt: now + 86_400,
        createdAt: now
      })
      safe_create(auth, "oauthConsent", {clientId: oauth_client_id, userId: admin.fetch("id"), scopes: ["profile", "email"], consentGiven: true})
      safe_create(auth, "ssoProvider", {
        issuer: "https://sso.example.test",
        domain: "example.test",
        providerId: "seeded-sso",
        userId: admin.fetch("id"),
        organizationId: organizations.first.fetch("id"),
        oidcConfig: JSON.generate(clientId: "sso-client", clientSecret: "sso-secret", discoveryUrl: "https://sso.example.test/.well-known/openid-configuration")
      })
      safe_create(auth, "apikey", {name: "Seeded API key", start: "ba_seed", prefix: "ba", key: SecureRandom.hex(24), referenceId: admin.fetch("id"), enabled: true, createdAt: now, updatedAt: now})
      safe_create(auth, "twoFactor", {userId: admin.fetch("id"), secret: "seeded-secret", backupCodes: "seeded-backup-code"})
      safe_create(auth, "passkey", {userId: admin.fetch("id"), name: "Seeded passkey", publicKey: "seeded-public-key", credentialID: "seeded-credential", counter: 0, deviceType: "singleDevice", backedUp: false, transports: "internal"})
      safe_create(auth, "scimProvider", {providerId: "seeded-scim", scimToken: SecureRandom.hex(18), organizationId: organizations.first.fetch("id")})
      safe_create(auth, "subscription", {plan: "example", referenceId: admin.fetch("id"), stripeCustomerId: "cus_seeded", stripeSubscriptionId: "sub_seeded", status: "active", periodStart: now, periodEnd: now + 2_592_000, seats: 3, billingInterval: "month"})
      safe_create(auth, "deviceCode", {deviceCode: SecureRandom.hex(20), userCode: "SEED2026", userId: admin.fetch("id"), expiresAt: now + 1800, status: "approved", pollingInterval: 5000, clientId: oauth_client_id, scope: "openid profile"})
      safe_create(auth, "walletAddress", {userId: admin.fetch("id"), address: "0x0000000000000000000000000000000000000001", chainId: 1, isPrimary: true, createdAt: now})
      ensure_jwks!(auth)
    end

    def safe_create(auth, model, data)
      auth.context.adapter.create(model: model, data: data)
    rescue KeyError, NoMethodError, BetterAuth::APIError
      nil
    end

    def ensure_jwks!(auth)
      auth.api.get_jwks
    rescue KeyError, NoMethodError, BetterAuth::APIError
      safe_create(auth, "jwks", {publicKey: "seeded-public-key", privateKey: "seeded-private-key", createdAt: Time.now})
    end
  end
end

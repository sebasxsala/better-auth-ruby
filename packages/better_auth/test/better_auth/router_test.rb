# frozen_string_literal: true

require "json"
require_relative "../test_helper"

class BetterAuthRouterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_rack_router_serves_ok_under_base_path
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    status, headers, body = auth.call(rack_env("GET", "/api/auth/ok"))

    assert_equal 200, status
    assert_equal "application/json", headers["content-type"]
    assert_equal({ok: true}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_router_supports_params_and_method_checks
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            user: BetterAuth::Endpoint.new(path: "/users/:id", method: "GET") do |ctx|
              {id: ctx.params[:id]}
            end
          }
        }
      ]
    )

    status, _headers, body = auth.call(rack_env("GET", "/api/auth/users/user-1"))
    assert_equal 200, status
    assert_equal({id: "user-1"}, JSON.parse(body.join, symbolize_names: true))

    status, headers, _body = auth.call(rack_env("POST", "/api/auth/users/user-1"))
    assert_equal 405, status
    assert_equal "GET", headers["allow"]
  end

  def test_trailing_slash_behavior_matches_option
    default_auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    tolerant_auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      advanced: {skip_trailing_slashes: true}
    )

    assert_equal 404, default_auth.call(rack_env("GET", "/api/auth/ok/")).first
    assert_equal 200, tolerant_auth.call(rack_env("GET", "/api/auth/ok/")).first
  end

  def test_trailing_slash_normalization_applies_to_post_requests
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      advanced: {skip_trailing_slashes: true},
      plugins: [
        {
          id: "test",
          endpoints: {
            submit: BetterAuth::Endpoint.new(path: "/submit", method: "POST") { {ok: true} }
          }
        }
      ]
    )

    status, _headers, body = auth.call(rack_env("POST", "/api/auth/submit/", body: {name: "Ada"}))

    assert_equal 200, status
    assert_equal({ok: true}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_disable_body_endpoint_receives_raw_body_without_parsing
    captured = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            raw: BetterAuth::Endpoint.new(path: "/raw", method: "POST", disable_body: true) do |ctx|
              captured << {body: ctx.body, raw_body: ctx.raw_body}
              {ok: true}
            end
          }
        }
      ]
    )
    payload = {"event" => "checkout.session.completed", "nested" => {"amount" => 123}}

    status, _headers, body = auth.call(rack_env("POST", "/api/auth/raw", body: payload))

    assert_equal 200, status
    assert_equal({ok: true}, JSON.parse(body.join, symbolize_names: true))
    assert_equal({}, captured.fetch(0).fetch(:body))
    assert_equal JSON.generate(payload), captured.fetch(0).fetch(:raw_body)
  end

  def test_rack_requests_prepare_context_before_endpoint_execution
    captured = []
    auth = BetterAuth.auth(
      secret: SECRET,
      trusted_origins: ->(request) { [request.get_header("HTTP_ORIGIN")] },
      plugins: [
        {
          id: "test",
          endpoints: {
            inspect: BetterAuth::Endpoint.new(path: "/inspect", method: "GET") do |ctx|
              captured << {
                base_url: ctx.context.base_url,
                trusted_origins: ctx.context.trusted_origins,
                current_session: ctx.context.current_session
              }
              {ok: true}
            end
          }
        }
      ]
    )
    auth.context.set_current_session({user_id: "stale"})

    auth.call(
      rack_env(
        "GET",
        "/api/auth/inspect",
        headers: {
          "HTTP_HOST" => "tenant.example",
          "HTTP_ORIGIN" => "https://frontend.example",
          "rack.url_scheme" => "https"
        }
      )
    )

    assert_equal "https://tenant.example/api/auth", captured.first[:base_url]
    assert_includes captured.first[:trusted_origins], "https://frontend.example"
    assert_nil captured.first[:current_session]
  end

  def test_disabled_paths_are_normalized_and_blocked
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      disabled_paths: ["/blocked"],
      plugins: [
        {
          id: "test",
          endpoints: {
            blocked: BetterAuth::Endpoint.new(path: "/blocked", method: "POST") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 404, auth.call(rack_env("POST", "/api/auth/blocked")).first
    assert_equal 404, auth.call(rack_env("POST", "/api/auth/blocked%2F")).first
    assert_equal 404, auth.call(rack_env("POST", "/api/auth/%62locked")).first
    assert_equal 404, auth.call(rack_env("POST", "/api/auth/blocked%00")).first
  end

  def test_plugin_request_and_response_chain_runs_around_endpoint
    order = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "a",
          on_request: lambda do |request, _ctx|
            order << "a"
            request.env["HTTP_X_FROM_A"] = "yes"
            {request: request}
          end,
          on_response: lambda do |response, _ctx|
            order << "a-response"
            response[1]["x-after-a"] = "yes"
            {response: response}
          end
        },
        {
          id: "b",
          endpoints: {
            chain: BetterAuth::Endpoint.new(path: "/chain", method: "GET") do |ctx|
              {from_a: ctx.headers["x-from-a"]}
            end
          },
          on_request: lambda do |_request, _ctx|
            order << "b"
            nil
          end
        }
      ]
    )

    status, headers, body = auth.call(rack_env("GET", "/api/auth/chain"))

    assert_equal 200, status
    assert_equal ["a", "b", "a-response"], order
    assert_equal "yes", headers["x-after-a"]
    assert_equal({from_a: "yes"}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_rack_requests_run_endpoint_hooks_like_direct_api
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            echo: BetterAuth::Endpoint.new(path: "/echo", method: "GET") do |ctx|
              {message: ctx.query["message"] || ctx.query[:message] || "endpoint"}
            end
          },
          hooks: {
            after: [
              {
                matcher: ->(ctx) { ctx.path == "/echo" },
                handler: ->(_ctx) { {message: "after"} }
              }
            ]
          }
        }
      ],
      hooks: {
        before: lambda do |ctx|
          next unless ctx.path == "/echo"

          {context: {query: {"message" => "before"}}}
        end
      }
    )

    status, _headers, body = auth.call(rack_env("GET", "/api/auth/echo"))

    assert_equal 200, status
    assert_equal({message: "after"}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_rack_before_hook_can_short_circuit
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            blocked: BetterAuth::Endpoint.new(path: "/blocked", method: "GET") { {ok: true} }
          }
        }
      ],
      hooks: {
        before: ->(_ctx) { {blocked: true} }
      }
    )

    status, _headers, body = auth.call(rack_env("GET", "/api/auth/blocked"))

    assert_equal 200, status
    assert_equal({blocked: true}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_rack_api_errors_keep_error_status_and_body
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            fail: BetterAuth::Endpoint.new(path: "/fail", method: "GET") do |ctx|
              raise ctx.error("FORBIDDEN", message: "Blocked")
            end
          }
        }
      ]
    )

    status, _headers, body = auth.call(rack_env("GET", "/api/auth/fail"))

    assert_equal 403, status
    assert_equal({code: "FORBIDDEN", message: "Blocked"}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_on_response_wraps_early_on_request_responses
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "early",
          endpoints: {
            blocked: BetterAuth::Endpoint.new(path: "/blocked", method: "GET") { {ok: true} }
          },
          on_request: ->(_request, _ctx) { {response: [403, {"content-type" => "text/plain"}, ["blocked"]]} },
          on_response: lambda do |response, _ctx|
            response[1]["x-wrapped"] = "yes"
            {response: response}
          end
        }
      ]
    )

    status, headers, body = auth.call(rack_env("GET", "/api/auth/blocked"))

    assert_equal 403, status
    assert_equal "yes", headers["x-wrapped"]
    assert_equal ["blocked"], body
  end

  def test_on_request_response_short_circuits_remaining_requests_but_runs_responses
    order = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "a",
          endpoints: {
            blocked: BetterAuth::Endpoint.new(path: "/blocked", method: "GET") { {ok: true} }
          },
          on_request: lambda do |_request, _ctx|
            order << "a-request"
            {response: [403, {"content-type" => "text/plain"}, ["blocked"]]}
          end,
          on_response: lambda do |response, _ctx|
            order << "a-response"
            response[1]["x-a"] = "yes"
            {response: response}
          end
        },
        {
          id: "b",
          on_request: lambda do |_request, _ctx|
            order << "b-request"
            nil
          end,
          on_response: lambda do |response, _ctx|
            order << "b-response"
            response[1]["x-b"] = "yes"
            {response: response}
          end
        }
      ]
    )

    status, headers, body = auth.call(rack_env("GET", "/api/auth/blocked"))

    assert_equal 403, status
    assert_equal ["blocked"], body
    assert_equal ["a-request", "a-response", "b-response"], order
    assert_equal "yes", headers["x-a"]
    assert_equal "yes", headers["x-b"]
  end

  def test_origin_check_validates_callbacks_origins_and_fetch_metadata
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            post: BetterAuth::Endpoint.new(path: "/post", method: "POST") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 403, auth.call(rack_env("POST", "/api/auth/post", body: {"callbackURL" => "https://evil.com"})).first
    assert_equal 403, auth.call(rack_env("POST", "/api/auth/post", headers: {"HTTP_ORIGIN" => "https://evil.com", "HTTP_COOKIE" => "session=1"})).first
    assert_equal 200, auth.call(rack_env("POST", "/api/auth/post", headers: {"HTTP_ORIGIN" => "https://evil.com"})).first

    status, _headers, body = auth.call(
      rack_env(
        "POST",
        "/api/auth/post",
        headers: {
          "HTTP_ORIGIN" => "https://evil.com",
          "HTTP_SEC_FETCH_SITE" => "cross-site",
          "HTTP_SEC_FETCH_MODE" => "navigate",
          "HTTP_SEC_FETCH_DEST" => "document"
        }
      )
    )
    assert_equal 403, status
    assert_equal "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
      JSON.parse(body.join)["message"]
  end

  def test_origin_check_allows_safe_methods_and_rejects_missing_or_malformed_origins_with_cookies
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            safe: BetterAuth::Endpoint.new(path: "/safe", method: "GET") { {ok: true} },
            post: BetterAuth::Endpoint.new(path: "/post", method: "POST") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/safe", headers: {"HTTP_ORIGIN" => "https://evil.com", "HTTP_COOKIE" => "session=1"})).first

    missing_status, _headers, missing_body = auth.call(rack_env("POST", "/api/auth/post", headers: {"HTTP_COOKIE" => "session=1"}))
    assert_equal 403, missing_status
    assert_equal "Missing or null Origin", JSON.parse(missing_body.join)["message"]

    assert_equal 403, auth.call(rack_env("POST", "/api/auth/post", headers: {"HTTP_ORIGIN" => "null", "HTTP_COOKIE" => "session=1"})).first
    assert_equal 403, auth.call(rack_env("POST", "/api/auth/post", headers: {"HTTP_ORIGIN" => "malicious.com", "HTTP_COOKIE" => "session=1"})).first
  end

  def test_origin_check_validates_callback_variants_and_relative_path_policy
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      trusted_origins: ["https://trusted.example"],
      plugins: [
        {
          id: "test",
          endpoints: {
            post: BetterAuth::Endpoint.new(path: "/post", method: "POST") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("POST", "/api/auth/post", body: {"callbackURL" => "/dashboard?next=/profile"})).first
    assert_equal 200, auth.call(rack_env("POST", "/api/auth/post", body: {"redirectTo" => "https://trusted.example/reset"})).first
    assert_equal 403, auth.call(rack_env("POST", "/api/auth/post", body: {"callbackURL" => "//evil.example"})).first
    assert_equal 403, auth.call(rack_env("POST", "/api/auth/post", body: {"errorCallbackURL" => "https://evil.example/error"})).first
    assert_equal 403, auth.call(rack_env("POST", "/api/auth/post", body: {"newUserCallbackURL" => "https://evil.example/welcome"})).first
  end

  def test_fetch_metadata_same_site_modes_and_missing_metadata
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      trusted_origins: ["https://app.example"],
      plugins: [
        {
          id: "test",
          endpoints: {
            post: BetterAuth::Endpoint.new(path: "/post", method: "POST") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("POST", "/api/auth/post", headers: {"HTTP_ORIGIN" => "http://localhost:3000"})).first
    assert_equal 200, auth.call(rack_env("POST", "/api/auth/post", headers: fetch_metadata_headers(site: "same-origin", mode: "navigate", origin: "http://localhost:3000"))).first
    assert_equal 200, auth.call(rack_env("POST", "/api/auth/post", headers: fetch_metadata_headers(site: "same-site", mode: "navigate", origin: "https://app.example"))).first
    assert_equal 200, auth.call(rack_env("POST", "/api/auth/post", headers: fetch_metadata_headers(site: "same-origin", mode: "cors", dest: "empty", origin: "http://localhost:3000"))).first
    assert_equal 403, auth.call(rack_env("POST", "/api/auth/post", headers: fetch_metadata_headers(site: "cross-site", mode: "no-cors", dest: "empty", origin: "https://evil.example"))).first
  end

  def test_origin_check_disable_flags_match_upstream_split
    endpoint_plugin = {
      id: "test",
      endpoints: {
        post: BetterAuth::Endpoint.new(path: "/post", method: "POST") { {ok: true} }
      }
    }

    csrf_disabled = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      advanced: {disable_csrf_check: true, disable_origin_check: false},
      plugins: [endpoint_plugin]
    )
    origin_disabled = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      advanced: {disable_origin_check: true},
      plugins: [endpoint_plugin]
    )

    assert_equal 200, csrf_disabled.call(rack_env("POST", "/api/auth/post", headers: {"HTTP_ORIGIN" => "https://evil.com", "HTTP_COOKIE" => "session=1"})).first
    assert_equal 403, csrf_disabled.call(rack_env("POST", "/api/auth/post", body: {"callbackURL" => "https://evil.com"})).first
    assert_equal 200, origin_disabled.call(rack_env("POST", "/api/auth/post", body: {"callbackURL" => "https://evil.com"})).first
  end

  def test_origin_check_can_skip_origin_validation_for_configured_paths_only
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      advanced: {disable_origin_check: ["/public"]},
      plugins: [
        {
          id: "test",
          endpoints: {
            public_post: BetterAuth::Endpoint.new(path: "/public/data", method: "POST") { {ok: true} },
            protected_post: BetterAuth::Endpoint.new(path: "/protected/data", method: "POST") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("POST", "/api/auth/public/data", headers: {"HTTP_ORIGIN" => "https://evil.com", "HTTP_COOKIE" => "session=1"})).first
    assert_equal 403, auth.call(rack_env("POST", "/api/auth/protected/data", headers: {"HTTP_ORIGIN" => "https://evil.com", "HTTP_COOKIE" => "session=1"})).first
    assert_equal 200, auth.call(rack_env("POST", "/api/auth/public/data", body: {"callbackURL" => "https://evil.com"})).first
    assert_equal 403, auth.call(rack_env("POST", "/api/auth/protected/data", body: {"callbackURL" => "https://evil.com"})).first
  end

  def test_rate_limit_runs_after_plugin_on_request
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      rate_limit: {enabled: true, window: 60, max: 1},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/limited")).first
  end

  def test_rate_limit_uses_custom_storage_with_upstream_retry_header
    storage = RateLimitStorage.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      rate_limit: {enabled: true, window: 60, max: 1, custom_storage: storage},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    status, headers, body = auth.call(rack_env("GET", "/api/auth/limited"))

    assert_equal 429, status
    assert_match(/\A\d+\z/, headers["x-retry-after"])
    assert_equal({"message" => "Too many requests. Please try again later."}, JSON.parse(body.join))
    assert_equal ["127.0.0.1|/limited"], storage.keys
  end

  def test_rate_limit_resets_after_window_and_ignores_query_params
    storage = RateLimitStorage.new
    storage.set(
      "127.0.0.1|/limited",
      {key: "127.0.0.1|/limited", count: 1, last_request: Time.now.to_f - 61},
      ttl: 60,
      update: false
    )
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      rate_limit: {enabled: true, window: 60, max: 1, custom_storage: storage},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited?nonce=1")).first
    assert_equal 1, storage.data.fetch("127.0.0.1|/limited")[:count]
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/limited?nonce=2")).first
    assert_equal ["127.0.0.1|/limited"], storage.keys
  end

  def test_rate_limit_applies_upstream_special_auth_rules
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      rate_limit: {enabled: true, window: 10, max: 100},
      plugins: [
        {
          id: "test",
          endpoints: {
            sign_in: BetterAuth::Endpoint.new(path: "/sign-in/email", method: "POST") { {ok: true} }
          }
        }
      ]
    )

    3.times do
      assert_equal 200, auth.call(rack_env("POST", "/api/auth/sign-in/email", body: {"email" => "a@example.com"})).first
    end
    assert_equal 429, auth.call(rack_env("POST", "/api/auth/sign-in/email", body: {"email" => "a@example.com"})).first
  end

  def test_rate_limit_applies_upstream_password_and_verification_special_rules
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      email_and_password: {
        enabled: true,
        send_reset_password: ->(_data, _request) {}
      },
      email_verification: {
        send_verification_email: ->(_data, _request) {}
      },
      rate_limit: {enabled: true, window: 60, max: 100}
    )

    3.times do
      assert_equal 200, auth.call(rack_env("POST", "/api/auth/request-password-reset", body: {"email" => "missing@example.com"})).first
      assert_equal 200, auth.call(rack_env("POST", "/api/auth/send-verification-email", body: {"email" => "missing@example.com"})).first
    end

    assert_equal 429, auth.call(rack_env("POST", "/api/auth/request-password-reset?nonce=1", body: {"email" => "missing@example.com"})).first
    assert_equal 429, auth.call(rack_env("POST", "/api/auth/send-verification-email?nonce=1", body: {"email" => "missing@example.com"})).first
  end

  def test_rate_limit_applies_upstream_forget_password_and_email_otp_special_rules
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      rate_limit: {enabled: true, window: 60, max: 100},
      plugins: [
        {
          id: "special-rule-paths",
          endpoints: {
            forget_password: BetterAuth::Endpoint.new(path: "/forget-password/callback", method: "POST") { {ok: true} },
            email_otp_verification: BetterAuth::Endpoint.new(path: "/email-otp/send-verification-otp", method: "POST") { {ok: true} },
            email_otp_reset: BetterAuth::Endpoint.new(path: "/email-otp/request-password-reset", method: "POST") { {ok: true} }
          }
        }
      ]
    )

    [
      "/forget-password/callback",
      "/email-otp/send-verification-otp",
      "/email-otp/request-password-reset"
    ].each do |path|
      3.times do
        assert_equal 200, auth.call(rack_env("POST", "/api/auth#{path}", body: {"email" => "missing@example.com"})).first
      end
      assert_equal 429, auth.call(rack_env("POST", "/api/auth#{path}?nonce=1", body: {"email" => "missing@example.com"})).first
    end
  end

  def test_rate_limit_honors_custom_rules_and_false_disables
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      rate_limit: {
        enabled: true,
        window: 60,
        max: 100,
        custom_rules: {
          "/custom/*" => {window: 60, max: 2},
          "/unlimited" => false
        }
      },
      plugins: [
        {
          id: "test",
          endpoints: {
            custom: BetterAuth::Endpoint.new(path: "/custom/action", method: "GET") { {ok: true} },
            unlimited: BetterAuth::Endpoint.new(path: "/unlimited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/custom/action")).first
    assert_equal 200, auth.call(rack_env("GET", "/api/auth/custom/action")).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/custom/action")).first

    4.times do
      assert_equal 200, auth.call(rack_env("GET", "/api/auth/unlimited")).first
    end
  end

  def test_rate_limit_can_use_secondary_storage_with_ttl
    storage = SecondaryStorage.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      secondary_storage: storage,
      rate_limit: {enabled: true, window: 60, max: 1, storage: "secondary-storage"},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    stored = JSON.parse(storage.data.fetch("127.0.0.1|/limited"))
    assert_equal ["count", "key", "lastRequest"], stored.keys.sort
    assert_kind_of Integer, stored.fetch("lastRequest")
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/limited")).first
    assert_equal 60, storage.ttls["127.0.0.1|/limited"]
  end

  def test_rate_limit_can_use_database_storage
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      rate_limit: {enabled: true, window: 60, max: 1, storage: "database"},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    stored = auth.context.adapter.find_one(model: "rateLimit", where: [{field: "key", value: "127.0.0.1|/limited"}])
    assert_equal 1, stored.fetch("count")
    assert_kind_of Integer, stored.fetch("lastRequest")
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/limited")).first
  end

  def test_rate_limit_reads_upstream_secondary_storage_last_request_milliseconds
    storage = SecondaryStorage.new
    storage.set(
      "127.0.0.1|/limited",
      JSON.generate({key: "127.0.0.1|/limited", count: 1, lastRequest: ((Time.now.to_f - 1) * 1000).to_i}),
      60
    )
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      secondary_storage: storage,
      rate_limit: {enabled: true, window: 60, max: 1, storage: "secondary-storage"},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    status, headers, = auth.call(rack_env("GET", "/api/auth/limited"))

    assert_equal 429, status
    assert_operator headers.fetch("x-retry-after").to_i, :<=, 60
  end

  def test_rate_limit_normalizes_configured_ip_headers
    storage = RateLimitStorage.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      advanced: {ip_address: {ip_address_headers: ["x-forwarded-for"], ipv6_subnet: 64}},
      rate_limit: {enabled: true, window: 60, max: 1, custom_storage: storage},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    first_ip = "2001:db8:abcd:1234:0000:0000:0000:0001"
    second_ip = "2001:db8:abcd:1234:ffff:ffff:ffff:ffff"
    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited", headers: {"HTTP_X_FORWARDED_FOR" => first_ip})).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/limited", headers: {"HTTP_X_FORWARDED_FOR" => second_ip})).first
    assert_equal 1, storage.keys.length
    assert_match(/\A2001:db8:abcd:1234::\|\/limited\z/, storage.keys.first)
  end

  def test_rate_limit_can_disable_ip_tracking
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      advanced: {ip_address: {disable_ip_tracking: true}},
      rate_limit: {enabled: true, window: 60, max: 1},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
  end

  def test_rate_limit_warns_and_skips_when_client_ip_is_missing_outside_development
    previous_rack_env = ENV["RACK_ENV"]
    ENV["RACK_ENV"] = "production"
    messages = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      logger: ->(level, message) { messages << [level, message] },
      rate_limit: {enabled: true, window: 60, max: 1},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    env = rack_env("GET", "/api/auth/limited")
    env.delete("REMOTE_ADDR")
    status, = auth.call(env)

    assert_equal 200, status
    assert messages.any? { |level, message| level == :warn && message.include?("could not determine client IP address") }
    refute messages.any? { |_level, message| message.include?("trustedProxies") }
  ensure
    if previous_rack_env
      ENV["RACK_ENV"] = previous_rack_env
    else
      ENV.delete("RACK_ENV")
    end
  end

  def test_form_media_type_is_rejected_unless_endpoint_allows_it
    json_only = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            post: BetterAuth::Endpoint.new(path: "/post", method: "POST") { {ok: true} }
          }
        }
      ]
    )
    form_allowed = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            post: BetterAuth::Endpoint.new(
              path: "/post",
              method: "POST",
              metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}
            ) { |ctx| {name: ctx.body["name"]} }
          }
        }
      ]
    )

    assert_equal 415, json_only.call(rack_env("POST", "/api/auth/post", form: {"name" => "Ada"})).first
    status, _headers, body = form_allowed.call(rack_env("POST", "/api/auth/post", form: {"name" => "Ada"}))

    assert_equal 200, status
    assert_equal({"name" => "Ada"}, JSON.parse(body.join))
  end

  def test_trusted_proxy_headers_reject_malformed_forwarded_values
    captured = []
    auth = BetterAuth.auth(
      secret: SECRET,
      advanced: {trusted_proxy_headers: true},
      hooks: {
        before: lambda do |ctx|
          captured << ctx.context.base_url
          nil
        end
      }
    )

    auth.call(rack_env("GET", "/api/auth/ok", headers: {"HTTP_X_FORWARDED_HOST" => "example.com:8080", "HTTP_X_FORWARDED_PROTO" => "https"}))
    auth.call(rack_env("GET", "/api/auth/ok", headers: {"HTTP_X_FORWARDED_HOST" => "evil.com:99999", "HTTP_X_FORWARDED_PROTO" => "http"}))
    auth.call(rack_env("GET", "/api/auth/ok", headers: {"HTTP_X_FORWARDED_HOST" => "<script>alert(1)</script>", "HTTP_X_FORWARDED_PROTO" => "http"}))
    auth.call(rack_env("GET", "/api/auth/ok", headers: {"HTTP_X_FORWARDED_HOST" => "example.com", "HTTP_X_FORWARDED_PROTO" => "javascript"}))

    assert_equal "https://example.com:8080/api/auth", captured[0]
    assert_equal "http://localhost:3000/api/auth", captured[1]
    assert_equal "http://localhost:3000/api/auth", captured[2]
    assert_equal "http://localhost:3000/api/auth", captured[3]
  end

  def test_endpoint_conflict_logging
    messages = []

    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      logger: ->(level, message) { messages << [level, message] },
      plugins: [
        {
          id: "one",
          endpoints: {
            shared: BetterAuth::Endpoint.new(path: "/shared", method: "GET") { {ok: true} }
          }
        },
        {
          id: "two",
          endpoints: {
            shared: BetterAuth::Endpoint.new(path: "/shared", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert messages.any? { |level, message| level == :error && message.include?("Endpoint path conflicts detected") }
    assert messages.any? { |_level, message| message.include?("\"/shared\" [GET] used by plugins: one, two") }
  end

  def test_endpoint_conflict_matrix_matches_upstream
    no_conflict_messages = []
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      logger: ->(level, message) { no_conflict_messages << [level, message] },
      plugins: [
        {
          id: "one",
          endpoints: {
            read: BetterAuth::Endpoint.new(path: "/resource", method: "GET") { {ok: true} },
            create: BetterAuth::Endpoint.new(path: "/same-plugin", method: "POST") { {ok: true} }
          }
        },
        {
          id: "two",
          endpoints: {
            create: BetterAuth::Endpoint.new(path: "/resource", method: "POST") { {ok: true} },
            delete: BetterAuth::Endpoint.new(path: "/resource", method: "DELETE") { {ok: true} }
          }
        }
      ]
    )

    refute no_conflict_messages.any? { |level, _message| level == :error }

    conflict_messages = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      logger: ->(level, message) { conflict_messages << [level, message] },
      plugins: [
        {
          id: "one",
          endpoints: {
            duplicate_one: BetterAuth::Endpoint.new(path: "/duplicate", method: "GET") { {ok: true} },
            duplicate_two: BetterAuth::Endpoint.new(path: "/duplicate", method: "GET") { {ok: true} },
            array_methods: BetterAuth::Endpoint.new(path: "/array", method: ["GET", "POST"]) { {ok: true} }
          }
        },
        {
          id: "two",
          endpoints: {
            wildcard: BetterAuth::Endpoint.new(path: "/array", method: "*") { {ok: true} },
            array_conflict: BetterAuth::Endpoint.new(path: "/duplicate-array", method: ["PATCH", "PUT"]) { {ok: true} }
          }
        },
        {
          id: "three",
          endpoints: {
            array_conflict: BetterAuth::Endpoint.new(path: "/duplicate-array", method: ["DELETE", "PATCH"]) { {ok: true} },
            pathless: BetterAuth::Endpoint.new(method: "GET") { {ok: true} }
          }
        },
        {
          id: "empty"
        }
      ]
    )

    assert_instance_of BetterAuth::Auth, auth
    error_messages = conflict_messages.filter_map { |level, message| message if level == :error }
    assert_equal 1, error_messages.length
    assert_includes error_messages.first, "Endpoint path conflicts detected"
    assert_includes error_messages.first, "\"/duplicate\" [GET] used by plugins: one"
    assert_match(/"\/array" \[(?=.*GET)(?=.*POST)(?=.*\*)[^\]]+\]/, error_messages.first)
    assert_includes error_messages.first, "used by plugins: one, two"
    assert_includes error_messages.first, "\"/duplicate-array\" [PATCH] used by plugins: two, three"
  end

  private

  def rack_env(method, path, body: nil, form: nil, headers: {})
    path_info, query_string = path.split("?", 2)
    payload = if form
      URI.encode_www_form(form)
    elsif body
      JSON.generate(body)
    else
      ""
    end
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path_info,
      "QUERY_STRING" => query_string || "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(payload),
      "CONTENT_TYPE" => content_type_for(body, form),
      "CONTENT_LENGTH" => payload.bytesize.to_s
    }.merge(headers).compact
  end

  def fetch_metadata_headers(site:, mode:, origin:, dest: "document")
    {
      "HTTP_ORIGIN" => origin,
      "HTTP_SEC_FETCH_SITE" => site,
      "HTTP_SEC_FETCH_MODE" => mode,
      "HTTP_SEC_FETCH_DEST" => dest
    }
  end

  def content_type_for(body, form)
    return "application/x-www-form-urlencoded" if form
    return "application/json" if body

    nil
  end

  class RateLimitStorage
    attr_reader :data

    def initialize
      @data = {}
    end

    def get(key)
      data[key]
    end

    def set(key, value, ttl: nil, update: false)
      data[key] = value.merge(ttl: ttl, update: update)
    end

    def keys
      data.keys
    end
  end

  class SecondaryStorage
    attr_reader :data, :ttls

    def initialize
      @data = {}
      @ttls = {}
    end

    def get(key)
      data[key]
    end

    def set(key, value, ttl)
      data[key] = value
      ttls[key] = ttl
    end
  end
end

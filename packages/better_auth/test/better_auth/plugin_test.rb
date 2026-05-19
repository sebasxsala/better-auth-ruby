# frozen_string_literal: true

require "json"
require_relative "../test_helper"

class BetterAuthPluginTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_plugin_contract_normalizes_upstream_fields
    endpoint = BetterAuth::Endpoint.new(path: "/plugin", method: "GET") { {ok: true} }
    plugin = BetterAuth::Plugin.new(
      "id" => "sample",
      "endpoints" => {"sampleAction" => endpoint},
      "version" => "1.2.3",
      "client" => {"id" => "sample-client", "version" => "1.2.3"},
      "onRequest" => ->(request, _context) { {request: request} },
      "onResponse" => ->(response, _context) { {response: response} },
      "rateLimit" => [{pathMatcher: ->(path) { path == "/plugin" }, window: 10, max: 2}],
      "$ERROR_CODES" => {"PLUGIN_FAILURE" => "Plugin failed"}
    )

    assert_equal "sample", plugin.id
    assert_equal endpoint, plugin.endpoints[:sample_action]
    assert_equal endpoint, plugin[:endpoints][:sample_action]
    assert_equal "1.2.3", plugin.version
    assert_equal({"id" => "sample-client", "version" => "1.2.3"}, plugin.client)
    assert_equal 1, plugin.rate_limit.length
    assert_equal({"PLUGIN_FAILURE" => "Plugin failed"}, plugin.error_codes)
    assert plugin.on_request
    assert plugin.on_response
  end

  def test_plugin_init_runs_in_sequence_and_merges_context_and_options_as_defaults
    order = []

    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      email_and_password: {enabled: false},
      plugins: [
        BetterAuth::Plugin.new(
          id: "first",
          init: lambda do |context|
            order << "first"
            {
              context: {app_name: "Changed by first"},
              options: {
                email_and_password: {enabled: true, max_password_length: 256},
                session: {fresh_age: 600}
              }
            }
          end
        ),
        BetterAuth::Plugin.new(
          id: "second",
          init: lambda do |context|
            order << "second:#{context.app_name}"
            {context: {plugin_state: {seen_app_name: context.app_name}}}
          end
        )
      ]
    )

    assert_equal ["first", "second:Changed by first"], order
    assert_equal "Changed by first", auth.context.app_name
    assert_equal({seen_app_name: "Changed by first"}, auth.context.plugin_state)
    assert_equal false, auth.options.email_and_password[:enabled]
    assert_equal 256, auth.options.email_and_password[:max_password_length]
    assert_equal 600, auth.options.session[:fresh_age]
  end

  def test_registry_merges_plugin_endpoints_schema_error_codes_and_hooks
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        BetterAuth::Plugin.new(
          id: "alpha",
          endpoints: {
            plugin_status: BetterAuth::Endpoint.new(path: "/plugin-status", method: "GET") do |ctx|
              ctx.json({source: ctx.context.plugin_state[:source]})
            end
          },
          schema: {
            session: {
              fields: {
                activePluginId: {type: "string", required: false}
              }
            },
            pluginAudit: {
              fields: {
                userId: {type: "string", required: true}
              }
            }
          },
          error_codes: {"PLUGIN_BLOCKED" => "Plugin blocked"},
          init: ->(_context) { {context: {plugin_state: {source: "alpha"}}} }
        ),
        BetterAuth::Plugin.new(
          id: "beta",
          hooks: {
            after: [
              {
                matcher: ->(ctx) { ctx.path == "/plugin-status" },
                handler: ->(_ctx) { {source: "beta-hook"} }
              }
            ]
          }
        )
      ]
    )

    assert_respond_to auth.api, :plugin_status
    assert_equal({source: "beta-hook"}, auth.api.plugin_status)
    assert_equal "Plugin blocked", auth.error_codes["PLUGIN_BLOCKED"]

    tables = BetterAuth::Schema.auth_tables(auth.options)
    assert_equal "string", tables["session"][:fields]["activePluginId"][:type]
    assert_equal "plugin_audits", tables["pluginAudit"][:model_name]
    assert_equal "user_id", tables["pluginAudit"][:fields]["userId"][:field_name]
  end

  def test_plugin_middlewares_and_request_response_callbacks_run_through_contract
    order = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        BetterAuth::Plugin.new(
          id: "chain",
          endpoints: {
            chain: BetterAuth::Endpoint.new(path: "/chain", method: "GET") do |ctx|
              {middleware: ctx.headers["x-plugin-middleware"], request: ctx.headers["x-plugin-request"]}
            end
          },
          middlewares: [
            {
              path: "/chain",
              middleware: lambda do |ctx|
                order << "middleware"
                ctx.headers["x-plugin-middleware"] = "yes"
                nil
              end
            }
          ],
          on_request: lambda do |request, _context|
            order << "request"
            request.env["HTTP_X_PLUGIN_REQUEST"] = "yes"
            {request: request}
          end,
          on_response: lambda do |response, _context|
            order << "response"
            response[1]["x-plugin-response"] = "yes"
            {response: response}
          end
        )
      ]
    )

    status, headers, body = auth.call(rack_env("GET", "/api/auth/chain"))

    assert_equal 200, status
    assert_equal ["middleware", "request", "response"], order
    assert_equal "yes", headers["x-plugin-response"]
    assert_equal({"middleware" => "yes", "request" => "yes"}, JSON.parse(body.join))
  end

  private

  def rack_env(method, path)
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(""),
      "CONTENT_LENGTH" => "0"
    }
  end
end

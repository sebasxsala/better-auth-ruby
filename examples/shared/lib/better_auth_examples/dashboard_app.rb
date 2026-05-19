# frozen_string_literal: true

require "erb"
require "json"
require "rack/request"
require "rack/response"

module BetterAuthExamples
  class DashboardApp
    attr_reader :registry, :framework_name

    def initialize(registry, framework_name:)
      @registry = registry
      @framework_name = framework_name
    end

    def call(env)
      request = Rack::Request.new(env)
      case [request.request_method, request.path_info]
      when ["GET", "/"]
        html_response(render_html)
      when ["GET", "/example/settings"]
        json_response({settings: Settings.from_request(request), framework: framework_name})
      when ["POST", "/example/settings"]
        update_settings(request)
      when ["GET", "/example/database"]
        settings = Settings.from_request(request)
        json_response(registry.explore(settings).merge(settings: settings))
      when ["POST", "/example/database/delete"]
        delete_records(request)
      when ["GET", "/example/plugins"]
        settings = Settings.from_request(request)
        json_response(
          {
            plugins: PluginCatalog.metadata_for(registry.auth_for(settings)),
            deliveries: PluginCatalog.deliveries,
            excluded: PluginCatalog::EXCLUDED_PLUGIN_IDS
          }
        )
      when ["POST", "/example/plugins/clear-deliveries"]
        PluginCatalog.clear_deliveries!
        json_response({ok: true, deliveries: []})
      when ["GET", "/example/social-providers"]
        json_response({providers: SocialProviderCatalog.metadata})
      when ["POST", "/example/reset"]
        reset_database(request)
      else
        not_found
      end
    rescue => error
      json_response({error: "#{error.class}: #{error.message}"}, status: 500)
    end

    private

    def update_settings(request)
      previous = Settings.from_request(request)
      settings = Settings.normalize(parsed_body(request))
      registry.reset!(previous) if previous != settings
      json_response(
        {settings: settings},
        headers: {"set-cookie" => ([Settings.set_cookie_header(settings)] + Settings.clear_auth_cookie_headers).join("\n")}
      )
    end

    def reset_database(request)
      settings = Settings.from_request(request)
      registry.reset_database!(settings)
      json_response(
        {ok: true, settings: settings},
        headers: {"set-cookie" => Settings.clear_auth_cookie_headers.join("\n")}
      )
    end

    def delete_records(request)
      settings = Settings.from_request(request)
      body = parsed_body(request)
      result = registry.delete_records!(settings, body["table"] || body[:table], body["ids"] || body[:ids])
      json_response({ok: true}.merge(result))
    end

    def parsed_body(request)
      body = request.body.read.to_s
      request.body.rewind
      return request.params if body.empty?

      if request.media_type == "application/json"
        JSON.parse(body)
      else
        request.params
      end
    rescue JSON::ParserError
      {}
    end

    def json_response(payload, status: 200, headers: {})
      [
        status,
        {"content-type" => "application/json"}.merge(headers),
        [JSON.pretty_generate(payload)]
      ]
    end

    def html_response(body)
      [200, {"content-type" => "text/html; charset=utf-8"}, [body]]
    end

    def not_found
      [404, {"content-type" => "text/plain"}, ["Not Found"]]
    end

    def render_html
      template.result_with_hash(framework_name: framework_name)
    end

    def template
      ERB.new(HTML)
    end

    HTML = <<~HTML
      <!doctype html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Better Auth Ruby Examples</title>
        <style>
          :root {
            color-scheme: light;
            --bg: #fafafa;
            --panel: #ffffff;
            --panel-2: #f4f4f5;
            --panel-3: #ededee;
            --line: #e5e5e5;
            --line-strong: #d4d4d4;
            --text: #171717;
            --muted: #666666;
            --soft: #8a8a8a;
            --accent: #171717;
            --accent-2: #f0f0f0;
            --danger: #b42318;
            --danger-bg: #fff1f0;
            --ok: #166534;
            --ok-bg: #f0fdf4;
            --shadow: 0 1px 2px rgba(0, 0, 0, .05), 0 16px 34px rgba(0, 0, 0, .05);
            --mono: "SFMono-Regular", "SF Mono", Consolas, "Liberation Mono", monospace;
          }
          * { box-sizing: border-box; }
          body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family: "Geist", ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
            font-size: 14px;
            line-height: 1.45;
          }
          button, input, select { font: inherit; }
          textarea { width: 100%; min-width: 0; font: inherit; }
          .shell { display: grid; grid-template-columns: 244px minmax(0, 1fr); min-height: 100dvh; }
          .sidebar { border-right: 1px solid var(--line); background: #fff; padding: 18px 12px; position: sticky; top: 0; height: 100dvh; }
          .brand { display: flex; align-items: center; gap: 10px; font-weight: 650; letter-spacing: -.02em; margin: 0 8px 4px; }
          .brand-mark { width: 28px; height: 28px; border-radius: 7px; background: #171717; color: #fff; display: grid; place-items: center; font-family: var(--mono); font-size: 12px; box-shadow: inset 0 1px 0 rgba(255,255,255,.16); }
          .framework { color: var(--muted); font-size: 12px; margin: 0 8px 26px 46px; }
          .nav { display: grid; gap: 5px; }
          .nav button { border: 1px solid transparent; background: transparent; color: #525252; text-align: left; border-radius: 8px; padding: 9px 10px; cursor: pointer; transition: background .18s ease, border-color .18s ease, color .18s ease, transform .18s ease; display: flex; align-items: center; gap: 10px; font-weight: 500; }
          .nav button:active, .button:active { transform: translateY(1px); }
          .nav button.active { background: #ededed; border-color: transparent; color: var(--text); }
          .nav button:hover { background: var(--panel-2); color: var(--text); }
          .nav-icon, .icon { width: 17px; height: 17px; display: inline-block; flex: 0 0 auto; }
          .nav-icon svg, .icon svg { width: 100%; height: 100%; stroke: currentColor; stroke-width: 1.8; fill: none; stroke-linecap: round; stroke-linejoin: round; }
          main { padding: 22px 30px 30px; min-width: 0; }
          .topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin: -22px -30px 24px; padding: 14px 30px; border-bottom: 1px solid var(--line); background: #fff; position: sticky; top: 0; z-index: 3; }
          h1 { font-size: 22px; margin: 0 0 5px; line-height: 1.08; letter-spacing: -.045em; }
          h2 { font-size: 15px; margin: 0 0 14px; letter-spacing: -.018em; }
          .status { display: flex; gap: 8px; flex-wrap: wrap; color: var(--muted); font-size: 12px; }
          .pill { border: 1px solid var(--line); background: #fff; border-radius: 999px; padding: 4px 8px; }
          .grid { display: grid; gap: 14px; }
          .two { grid-template-columns: repeat(2, minmax(0, 1fr)); }
          .panel { background: #fff; border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); padding: 18px; }
          label { display: grid; gap: 6px; color: var(--muted); font-size: 12px; }
          input, select {
            width: 100%;
            border: 1px solid var(--line);
            border-radius: 8px;
            background: #ffffff;
            color: var(--text);
            padding: 9px 10px;
            transition: border-color .18s ease, box-shadow .18s ease;
          }
          input:focus, select:focus, button:focus { outline: 2px solid rgba(0, 0, 0, .12); outline-offset: 1px; }
          .form { display: grid; gap: 10px; }
          .actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
          .button {
            border: 1px solid var(--line);
            background: #ffffff;
            color: var(--text);
            border-radius: 8px;
            padding: 8px 12px;
            cursor: pointer;
            transition: background .18s ease, border-color .18s ease, color .18s ease, transform .18s ease, box-shadow .18s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
          }
          .button.primary { background: var(--accent); color: white; border-color: var(--accent); box-shadow: none; }
          .button.danger { color: var(--danger); background: var(--danger-bg); border-color: #ffd0cc; }
          .button:hover { border-color: var(--line-strong); box-shadow: 0 2px 8px rgba(0,0,0,.05); }
          .button:disabled { opacity: .42; cursor: not-allowed; box-shadow: none; }
          .button.icon-only { width: 38px; height: 38px; display: inline-grid; place-items: center; padding: 0; }
          .avatar { width: 44px; height: 44px; border-radius: 50%; background: var(--panel-2); display: inline-grid; place-items: center; overflow: hidden; border: 1px solid var(--line); font-weight: 650; }
          .avatar img { width: 100%; height: 100%; object-fit: cover; }
          .profile { display: flex; align-items: center; gap: 12px; }
          .muted { color: var(--muted); }
          pre { margin: 0; white-space: pre-wrap; overflow: auto; max-height: 280px; background: #fafafa; border: 1px solid var(--line); border-radius: 8px; padding: 11px; font: 12px/1.55 var(--mono); }
          .database-studio { display: grid; grid-template-columns: 304px minmax(0, 1fr); height: min(760px, calc(100dvh - 132px)); border: 1px solid var(--line); background: #fff; border-radius: 8px; overflow: hidden; box-shadow: var(--shadow); }
          .database-rail { border-right: 1px solid var(--line); background: #fbfbfb; padding: 16px 14px; min-width: 0; display: grid; grid-template-rows: auto auto auto minmax(0, 1fr) auto auto; overflow: hidden; }
          .rail-title { font-size: 24px; font-weight: 700; letter-spacing: -.05em; margin: 0 0 2px; }
          .rail-subtitle { color: #404040; font-size: 13px; margin: 0 0 18px; font-weight: 500; }
          .database-select { border: 1px solid var(--line-strong); border-radius: 8px; background: #fff; padding: 10px 11px; margin-bottom: 8px; font-weight: 600; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
          .schema-card { border: 0; background: transparent; padding: 0; margin-bottom: 10px; min-height: 0; display: grid; grid-template-rows: auto auto minmax(0, 1fr); }
          .schema-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 10px; }
          .schema-name { font-weight: 620; }
          .table-search { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; margin-bottom: 10px; }
          .table-search input { padding: 8px 10px; }
          .icon-button { width: 36px; height: 36px; display: inline-grid; place-items: center; padding: 0; }
          .table-tabs { display: grid; gap: 2px; min-height: 0; overflow: auto; padding-right: 3px; align-content: start; grid-auto-rows: min-content; }
          .table-tabs button { border: 1px solid transparent; background: transparent; border-radius: 7px; padding: 8px 9px; min-height: 36px; cursor: pointer; color: #525252; display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 8px; text-align: left; font-weight: 500; }
          .table-tabs button:hover { background: #fff; border-color: var(--line); color: var(--text); }
          .table-tabs button.active { color: var(--text); background: #ededed; border-color: transparent; }
          .table-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
          .table-count { color: var(--soft); font: 11px var(--mono); }
          .database-main { min-width: 0; display: grid; grid-template-rows: auto auto minmax(0, 1fr) auto; background: #fff; }
          .db-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 12px; border-bottom: 1px solid var(--line); background: #fff; position: relative; z-index: 5; }
          .toolbar-left, .toolbar-right { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
          .table-meta { padding: 8px 12px; border-bottom: 1px solid var(--line); display: flex; justify-content: space-between; gap: 12px; color: var(--muted); font-size: 12px; }
          .columns-popover { position: relative; z-index: 6; }
          .columns { position: absolute; right: 0; top: calc(100% + 8px); width: min(320px, 76vw); display: none; grid-template-columns: 1fr; gap: 7px; padding: 12px; background: #fff; border: 1px solid var(--line); border-radius: 10px; box-shadow: 0 18px 44px rgba(0,0,0,.16); max-height: 360px; overflow: auto; z-index: 20; }
          .columns.open { display: grid; }
          .columns label { display: flex; align-items: center; gap: 7px; color: var(--text); font-size: 12px; min-width: 0; }
          .columns input { width: auto; }
          .records { min-height: 0; overflow: auto; background: #fff; }
          table { width: 100%; border-collapse: separate; border-spacing: 0; font: 12px/1.45 var(--mono); }
          th, td { border-right: 1px solid var(--line); border-bottom: 1px solid var(--line); padding: 8px 10px; text-align: left; vertical-align: top; max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
          th { position: sticky; top: 0; background: #fafafa; z-index: 1; color: #666; font-weight: 600; }
          tr:hover td { background: #fafafa; }
          .row-selector { width: 28px; min-width: 28px; max-width: 28px; text-align: center; padding: 7px; }
          .row-checkbox { width: 16px; height: 16px; border: 1px solid var(--line-strong); border-radius: 3px; display: inline-block; vertical-align: middle; background: #fff; }
          .record-checkbox { width: 16px; height: 16px; margin: 0; vertical-align: middle; accent-color: #171717; }
          .empty-row { padding: 32px 12px; text-align: center; color: var(--muted); font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
          .pager { display: flex; align-items: center; justify-content: flex-end; gap: 8px; padding: 9px 12px; border-top: 1px solid var(--line); background: #fff; color: var(--muted); font-size: 12px; }
          .pager strong { color: var(--text); font-weight: 600; }
          .empty-state { padding: 42px 20px; text-align: center; color: var(--muted); }
          .plugins-panel { padding: 0; overflow: hidden; }
          .plugins-toolbar { display: flex; justify-content: space-between; gap: 12px; align-items: center; padding: 14px 16px; border-bottom: 1px solid var(--line); background: oklch(0.985 0.004 260); }
          .plugins-toolbar h2 { margin: 0 0 3px; }
          .plugins-panel > .notice { margin: 10px 16px 0; }
          .plugin-tabs { display: flex; gap: 6px; overflow-x: auto; padding: 12px 16px; border-bottom: 1px solid var(--line); background: oklch(0.975 0.004 260); }
          .plugin-tab { border: 1px solid transparent; background: transparent; color: #52525b; border-radius: 999px; padding: 7px 10px; cursor: pointer; white-space: nowrap; display: inline-flex; gap: 7px; align-items: center; font-size: 12px; font-weight: 600; }
          .plugin-tab:hover { background: oklch(0.94 0.006 260); color: var(--text); }
          .plugin-tab.active { background: oklch(0.24 0.012 260); color: oklch(0.98 0.004 260); }
          .plugin-tab-count { opacity: .68; font: 11px var(--mono); }
          .plugin-sections { display: grid; background: #fff; }
          .plugin-section { display: grid; gap: 16px; padding: 22px 22px 26px; border-top: 1px solid var(--line); }
          .plugin-section:first-child { border-top: 0; }
          .plugin-section-header { display: grid; gap: 12px; }
          .plugin-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
          .plugin-heading h3 { margin: 0; font-size: 22px; line-height: 1.1; letter-spacing: -.035em; }
          .plugin-summary { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
          .plugin-description { max-width: 74ch; margin: 0; color: #3f3f46; font-size: 15px; line-height: 1.55; }
          .plugin-details { display: flex; gap: 8px; flex-wrap: wrap; color: var(--muted); font: 12px/1.4 var(--mono); }
          .plugin-capabilities { margin: 0; padding-left: 18px; color: #52525b; display: grid; gap: 4px; max-width: 76ch; }
          .endpoint-actions { display: grid; gap: 9px; }
          .action-group { display: grid; gap: 9px; }
          .action-group-title { margin: 2px 0 0; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; font-weight: 700; }
          .endpoint-action { border: 1px solid var(--line); border-radius: 8px; background: oklch(0.995 0.002 260); overflow: hidden; }
          .endpoint-line { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; gap: 10px; align-items: center; padding: 10px; }
          .method-badge { min-width: 52px; text-align: center; border-radius: 6px; padding: 4px 7px; font: 11px var(--mono); color: oklch(0.26 0.012 260); background: oklch(0.93 0.008 260); }
          .method-badge.post { color: oklch(0.34 0.08 255); background: oklch(0.94 0.028 255); }
          .method-badge.get { color: oklch(0.34 0.07 155); background: oklch(0.95 0.03 155); }
          .method-badge.delete { color: oklch(0.42 0.12 28); background: oklch(0.95 0.035 28); }
          .endpoint-path { overflow-wrap: anywhere; font: 13px/1.35 var(--mono); color: #27272a; }
          .action-label { display: block; color: #18181b; font-weight: 650; margin-bottom: 2px; font-family: "Geist", ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
          .endpoint-payload { border-top: 1px solid var(--line); padding: 8px 10px 10px; }
          .endpoint-payload summary { cursor: pointer; color: #52525b; font-size: 12px; margin-bottom: 8px; font-weight: 650; }
          .endpoint-payload textarea { display: block; min-height: 154px; resize: vertical; font: 12px/1.55 var(--mono); border-radius: 7px; background: oklch(0.985 0.003 260); color: #27272a; border: 1px solid var(--line); padding: 11px 12px; tab-size: 2; }
          .endpoint-payload textarea:focus { outline: 2px solid oklch(0.72 0.08 255 / .45); outline-offset: 1px; border-color: oklch(0.72 0.08 255); background: #fff; }
          .endpoint-output { margin: 0 10px 10px; max-height: 220px; font-size: 11px; background: oklch(0.985 0.003 260); }
          .plugin-empty { padding: 32px 18px; color: var(--muted); }
          .delivery-list { display: grid; gap: 8px; }
          .delivery-item { border: 1px solid var(--line); border-radius: 8px; padding: 10px; background: #fafafa; }
          .social-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(168px, 1fr)); gap: 10px; }
          .social-button { min-height: 42px; justify-content: flex-start; }
          .notice { min-height: 20px; color: var(--muted); margin: 10px 0 0; }
          .notice.error { color: var(--danger); }
          .notice.ok { color: var(--ok); }
          dialog { border: 0; border-radius: 16px; padding: 0; width: min(460px, calc(100vw - 32px)); box-shadow: 0 24px 80px rgba(15, 23, 42, .28); }
          dialog::backdrop { background: rgba(15, 23, 42, .32); backdrop-filter: blur(4px); }
          .dialog-body { padding: 22px; background: #fff; border: 1px solid var(--line); border-radius: 16px; }
          .dialog-body p { color: var(--muted); margin: 0 0 18px; }
          .dialog-title { font-size: 18px; font-weight: 720; letter-spacing: -.025em; margin: 0 0 8px; }
          [hidden] { display: none !important; }
          @media (max-width: 840px) {
            .shell { grid-template-columns: 1fr; }
            .sidebar { position: static; height: auto; }
            .two { grid-template-columns: 1fr; }
            main { padding: 16px; }
            .plugins-toolbar, .plugin-heading, .endpoint-line { grid-template-columns: 1fr; display: grid; }
            .plugin-summary { justify-content: flex-start; }
            .database-studio { grid-template-columns: 1fr; }
            .database-rail { border-right: 0; border-bottom: 1px solid var(--line); }
            .records { max-height: 58dvh; }
          }
        </style>
      </head>
      <body>
        <div class="shell">
          <aside class="sidebar">
            <p class="brand"><span class="brand-mark">ba</span><span>Better Auth Ruby</span></p>
            <p class="framework"><%= framework_name %> example</p>
            <nav class="nav">
              <button data-view-button="home" class="active"><span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M4 10.5 12 4l8 6.5V20a1 1 0 0 1-1 1h-5v-6h-4v6H5a1 1 0 0 1-1-1v-9.5Z"/></svg></span>Home</button>
              <button data-view-button="sessions"><span class="nav-icon"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg></span>Sessions</button>
              <button data-view-button="social"><span class="nav-icon"><svg viewBox="0 0 24 24"><circle cx="8" cy="8" r="3"/><circle cx="16" cy="16" r="3"/><path d="m10.2 10.2 3.6 3.6M16 5v5M19 8h-6M5 16h6M8 13v6"/></svg></span>Social</button>
              <button data-view-button="plugins"><span class="nav-icon"><svg viewBox="0 0 24 24"><path d="m12 2 2.4 6.8 7.2.2-5.7 4.4 2 7-5.9-4-5.9 4 2-7L2.4 9l7.2-.2L12 2Z"/></svg></span>Plugins</button>
              <button data-view-button="database"><span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M4 7c0 1.7 3.6 3 8 3s8-1.3 8-3-3.6-3-8-3-8 1.3-8 3Z"/><path d="M4 7v5c0 1.7 3.6 3 8 3s8-1.3 8-3V7"/><path d="M4 12v5c0 1.7 3.6 3 8 3s8-1.3 8-3v-5"/></svg></span>Database</button>
              <button data-view-button="settings"><span class="nav-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.4-2.4 1a7 7 0 0 0-1.7-1L14.5 3h-5l-.4 3.1a7 7 0 0 0-1.7 1l-2.4-1-2 3.4L5.1 11a7 7 0 0 0 0 2l-2 1.5 2 3.4 2.4-1a7 7 0 0 0 1.7 1l.4 3.1h5l.4-3.1a7 7 0 0 0 1.7-1l2.4 1 2-3.4-2.1-1.5a7 7 0 0 0 .1-1Z"/></svg></span>Settings</button>
            </nav>
          </aside>
          <main>
            <div class="topbar">
              <div>
                <h1 id="view-title">Home</h1>
                <div class="status">
                  <span class="pill" id="database-pill">database: memory</span>
                  <span class="pill" id="rate-pill">rate: memory</span>
                </div>
              </div>
              <button class="button icon-only" id="refresh-all" title="Reload" aria-label="Reload">
                <span class="icon"><svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-15.2 6.5"/><path d="M3 12A9 9 0 0 1 18.2 5.5"/><path d="M18 2v4h-4"/><path d="M6 22v-4h4"/></svg></span>
              </button>
            </div>

            <section data-view="home" class="grid two">
              <div class="panel">
                <h2>Current user</h2>
                <div id="profile" class="muted">No active session.</div>
              </div>
              <div class="panel">
                <h2>Sign out</h2>
                <div class="actions">
                  <button class="button" id="sign-out">Sign out</button>
                </div>
                <p class="notice" id="auth-notice"></p>
              </div>
              <div class="panel">
                <h2>Sign up</h2>
                <form class="form" id="signup-form">
                  <label>Name <input name="name" value="Ada Lovelace" required></label>
                  <label>Email <input name="email" type="email" value="ada@example.com" required></label>
                  <label>Password <input name="password" type="password" value="password123" required></label>
                  <label>Nickname <input name="nickname" value="Ada"></label>
                  <label>Example role <input name="exampleRole" value="member"></label>
                  <label>Avatar URL <input name="image" placeholder="https://..."></label>
                  <button class="button primary" type="submit">Create account</button>
                </form>
              </div>
              <div class="panel">
                <h2>Sign in</h2>
                <form class="form" id="signin-form">
                  <label>Email <input name="email" type="email" value="ada@example.com" required></label>
                  <label>Password <input name="password" type="password" value="password123" required></label>
                  <button class="button primary" type="submit">Sign in</button>
                </form>
              </div>
            </section>

            <section data-view="sessions" hidden class="grid">
              <div class="panel">
                <div class="actions">
                  <button class="button" id="load-session">Get session</button>
                  <button class="button" id="load-sessions">List sessions</button>
                </div>
              </div>
              <div class="panel"><h2>Current session</h2><pre id="session-json">null</pre></div>
              <div class="panel"><h2>Session list</h2><pre id="sessions-json">[]</pre></div>
            </section>

            <section data-view="social" hidden class="grid">
              <div class="panel">
                <div class="social-grid" id="social-provider-buttons">
                  <% BetterAuthExamples::SocialProviderCatalog.all.each do |provider| %>
                    <button class="button social-button" type="button" data-social-provider="<%= BetterAuthExamples::SocialProviderCatalog.lookup_id(provider) %>"><%= provider.fetch(:name) %></button>
                  <% end %>
                </div>
                <p class="notice" id="social-notice"></p>
              </div>
            </section>

            <section data-view="plugins" hidden class="grid">
              <div class="panel plugins-panel">
                <div class="plugins-toolbar">
                  <div>
                    <h2>Enabled plugins</h2>
                    <div class="muted">Pick one plugin or keep All selected to scan every section in one column.</div>
                  </div>
                  <div class="actions">
                    <button class="button" id="load-plugins" type="button">Reload plugins</button>
                    <button class="button" id="clear-deliveries" type="button">Clear inbox</button>
                  </div>
                </div>
                <p class="notice" id="plugins-notice"></p>
                <div class="plugin-tabs" id="plugin-tabs"></div>
                <div class="plugin-sections" id="plugin-sections"></div>
              </div>
              <div class="panel">
                <h2>Local delivery inbox</h2>
                <div class="delivery-list" id="delivery-list"></div>
              </div>
              <div class="panel">
                <h2>Excluded packages</h2>
                <pre id="excluded-plugins">[]</pre>
              </div>
            </section>

            <section data-view="database" hidden class="grid">
              <div class="database-studio">
                <aside class="database-rail">
                  <p class="rail-title">Tables</p>
                  <p class="rail-subtitle">Better Auth schema explorer</p>
                  <div class="database-select">
                    <span id="database-provider-label">memory</span>
                    <span class="muted">provider</span>
                  </div>
                  <div class="schema-card">
                    <div class="schema-header">
                      <span class="schema-name">auth</span>
                      <span class="muted" id="table-total">0 tables</span>
                    </div>
                    <div class="table-search">
                      <input id="table-filter" placeholder="Search tables">
                      <button class="button icon-button" id="reload-db" title="Reload tables" aria-label="Reload tables" type="button">
                        <span class="icon"><svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-15.2 6.5"/><path d="M3 12A9 9 0 0 1 18.2 5.5"/><path d="M18 2v4h-4"/><path d="M6 22v-4h4"/></svg></span>
                      </button>
                    </div>
                    <div class="table-tabs" id="table-tabs"></div>
                  </div>
                  <button class="button danger" id="drop-db" type="button">Drop and migrate database</button>
                  <p class="notice" id="db-notice"></p>
                </aside>
                <div class="database-main">
                  <div class="db-toolbar">
                    <div class="toolbar-left">
                      <button class="button icon-only" id="reload-db-toolbar" title="Reload records" aria-label="Reload records" type="button">
                        <span class="icon"><svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-15.2 6.5"/><path d="M3 12A9 9 0 0 1 18.2 5.5"/><path d="M18 2v4h-4"/><path d="M6 22v-4h4"/></svg></span>
                      </button>
                      <div class="columns-popover">
                        <button class="button" id="columns-button" type="button"><span class="icon"><svg viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/><path d="M8 4v4M16 10v4M11 16v4"/></svg></span>Columns</button>
                        <div class="columns" id="column-toggles"></div>
                      </div>
                      <button class="button danger" id="delete-records" type="button" disabled>Delete selected</button>
                    </div>
                    <div class="toolbar-right">
                      <span class="muted" id="active-table-label">No table selected</span>
                    </div>
                  </div>
                  <div id="table-meta" class="table-meta"></div>
                  <div class="records" id="records"></div>
                  <div class="pager">
                    <span id="page-label">0 rows</span>
                    <button class="button icon-only" id="prev-page" title="Previous page" aria-label="Previous page" type="button">
                      <span class="icon"><svg viewBox="0 0 24 24"><path d="m15 18-6-6 6-6"/></svg></span>
                    </button>
                    <strong id="page-size-label">50</strong>
                    <button class="button icon-only" id="next-page" title="Next page" aria-label="Next page" type="button">
                      <span class="icon"><svg viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg></span>
                    </button>
                  </div>
                </div>
              </div>
            </section>

            <section data-view="settings" hidden class="grid two">
              <div class="panel">
                <h2>Database settings</h2>
                <form class="form" id="settings-form">
                  <label>Database provider
                    <select name="database">
                      <option value="memory">Memory</option>
                      <option value="sqlite">SQLite</option>
                      <option value="postgres">Postgres</option>
                      <option value="mysql">MySQL</option>
                      <option value="mssql">MSSQL</option>
                      <option value="mongodb">MongoDB</option>
                    </select>
                  </label>
                  <label>Rate limit adapter
                    <select name="rate_adapter">
                      <option value="memory">Memory</option>
                      <option value="redis">Redis</option>
                    </select>
                  </label>
                  <label>Window seconds <input name="rate_window" type="number" min="1" value="10"></label>
                  <label>Max requests <input name="rate_max" type="number" min="1" value="100"></label>
                  <button class="button primary" type="submit">Apply settings</button>
                </form>
                <p class="notice" id="settings-notice"></p>
              </div>
              <div class="panel">
                <h2>Active settings</h2>
                <pre id="settings-json">{}</pre>
              </div>
            </section>
          </main>
        </div>
        <dialog id="drop-dialog">
          <div class="dialog-body">
            <p class="dialog-title">Drop and migrate database?</p>
            <p>This removes Better Auth data for the selected provider, clears auth cookies, and runs schema setup again.</p>
            <div class="actions">
              <button class="button danger" id="confirm-drop-db" type="button">Drop and migrate</button>
              <button class="button" id="cancel-drop-db" type="button">Cancel</button>
            </div>
          </div>
        </dialog>
        <script>
          const state = { settings: {}, tables: [], activeTable: null, visibleColumns: new Set(), selectedIds: new Set(), page: 0, pageSize: 50, plugins: [], activePlugin: "all", deliveries: [], excludedPlugins: [] };
          const SETTINGS_STORAGE_KEY = "better_auth_example_settings";
          const $ = (selector) => document.querySelector(selector);
          const $$ = (selector) => Array.from(document.querySelectorAll(selector));

          function showNotice(id, message, type = "") {
            const el = $(id);
            el.textContent = message || "";
            el.className = `notice ${type}`;
          }

          function jsonFetch(url, options = {}) {
            const headers = { "content-type": "application/json", ...(options.headers || {}) };
            return fetch(url, {
              credentials: "include",
              ...options,
              headers
            }).then(async (response) => {
              const text = await response.text();
              let data = null;
              try { data = text ? JSON.parse(text) : null; } catch { data = text; }
              if (!response.ok) throw new Error((data && data.message) || (data && data.error) || response.statusText);
              return data;
            });
          }

          function formData(form) {
            return Object.fromEntries(new FormData(form).entries());
          }

          function authRequestOptions(method, body, headers = {}) {
            const payload = body && typeof body === "object" && !Array.isArray(body) ? {...body} : body;
            const options = { method, headers: {...headers} };
            if (payload && typeof payload === "object" && !Array.isArray(payload)) {
              const captcha = payload.captchaResponse || payload.captcha_response || payload.captcha;
              if (captcha) {
                options.headers["x-captcha-response"] = captcha;
                delete payload.captchaResponse;
                delete payload.captcha_response;
                delete payload.captcha;
              }
              options.body = JSON.stringify(payload);
            } else if (payload !== undefined && payload !== null) {
              options.body = payload;
            }
            return options;
          }

          function escapeHTML(value) {
            return String(value ?? "").replace(/[&<>"']/g, (char) => ({
              "&": "&amp;",
              "<": "&lt;",
              ">": "&gt;",
              '"': "&quot;",
              "'": "&#39;"
            })[char]);
          }

          function setView(view) {
            $$("[data-view]").forEach((el) => el.hidden = el.dataset.view !== view);
            $$("[data-view-button]").forEach((el) => el.classList.toggle("active", el.dataset.viewButton === view));
            $("#view-title").textContent = view[0].toUpperCase() + view.slice(1);
            if (view === "database") loadDatabase();
            if (view === "plugins") loadPlugins();
          }

          function renderSettings() {
            $("#database-pill").textContent = `database: ${state.settings.database || "memory"}`;
            $("#rate-pill").textContent = `rate: ${state.settings.rate_adapter || "memory"} (${state.settings.rate_max || 100}/${state.settings.rate_window || 10}s)`;
            $("#settings-json").textContent = JSON.stringify(state.settings, null, 2);
            $("#database-provider-label").textContent = state.settings.database || "memory";
            const form = $("#settings-form");
            for (const [key, value] of Object.entries(state.settings)) {
              if (form.elements[key]) form.elements[key].value = value;
            }
            localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(state.settings));
          }

          function renderProfile(session) {
            if (!session || !session.user) {
              $("#profile").innerHTML = "No active session.";
              return;
            }
            const user = session.user;
            const initials = (user.name || user.email || "?").split(/\\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
            const avatar = user.image ? `<img src="${escapeHTML(user.image)}" alt="">` : escapeHTML(initials);
            $("#profile").innerHTML = `<div class="profile"><span class="avatar">${avatar}</span><div><strong>${escapeHTML(user.name || "Unnamed user")}</strong><div class="muted">${escapeHTML(user.email || "")}</div></div></div>`;
          }

          async function loadSettings() {
            const localSettings = localStorage.getItem(SETTINGS_STORAGE_KEY);
            if (localSettings) {
              try {
                state.settings = JSON.parse(localSettings);
                renderSettings();
              } catch {}
            }
            const data = await jsonFetch("/example/settings");
            state.settings = data.settings;
            renderSettings();
          }

          async function loadCurrentSession() {
            try {
              const session = await jsonFetch("/api/auth/get-session");
              $("#session-json").textContent = JSON.stringify(session, null, 2);
              renderProfile(session);
              return session;
            } catch (error) {
              $("#session-json").textContent = JSON.stringify({ error: error.message }, null, 2);
              renderProfile(null);
              return null;
            }
          }

          async function loadSessions() {
            try {
              const sessions = await jsonFetch("/api/auth/list-sessions");
              $("#sessions-json").textContent = JSON.stringify(sessions, null, 2);
            } catch (error) {
              $("#sessions-json").textContent = JSON.stringify({ error: error.message }, null, 2);
            }
          }

          async function signInWithSocialProvider(button) {
            const provider = button.dataset.socialProvider;
            const buttons = $$("[data-social-provider]");
            const originalLabel = button.textContent;
            let navigating = false;
            buttons.forEach((entry) => entry.disabled = true);
            button.textContent = "Loading...";
            showNotice("#social-notice", "");
            try {
              const data = await jsonFetch("/api/auth/sign-in/social", {
                method: "POST",
                body: JSON.stringify({provider, callbackURL: "/", errorCallbackURL: "/", disableRedirect: true})
              });
              if (data && data.url) {
                navigating = true;
                window.location.assign(data.url);
              } else {
                showNotice("#social-notice", `${provider}: signed in.`, "ok");
                await loadCurrentSession();
                await loadSessions();
              }
            } catch (error) {
              showNotice("#social-notice", error.message, "error");
            } finally {
              if (!navigating) {
                button.textContent = originalLabel;
                buttons.forEach((entry) => entry.disabled = false);
              }
            }
          }

          function renderPlugins() {
            if (!state.plugins.some((plugin) => plugin.id === state.activePlugin)) state.activePlugin = "all";
            renderPluginTabs();
            const visiblePlugins = state.activePlugin === "all"
              ? state.plugins
              : state.plugins.filter((plugin) => plugin.id === state.activePlugin);
            $("#plugin-sections").innerHTML = visiblePlugins.map(renderPluginSection).join("") || `<div class="plugin-empty">No plugins enabled.</div>`;
            $$("[data-run-endpoint]").forEach((button) => {
              button.onclick = () => runPluginEndpoint(button);
            });

            renderDeliveries();
            $("#excluded-plugins").textContent = JSON.stringify(state.excludedPlugins, null, 2);
          }

          function renderPluginTabs() {
            const totalEndpoints = state.plugins.reduce((sum, plugin) => sum + ((plugin.endpoint_actions || plugin.endpoints || []).length), 0);
            const tabs = [{id: "all", label: "All", count: totalEndpoints}].concat(
              state.plugins.map((plugin) => ({id: plugin.id, label: plugin.id, count: (plugin.endpoint_actions || plugin.endpoints || []).length}))
            );
            $("#plugin-tabs").innerHTML = tabs.map((tab) => (
              `<button class="plugin-tab ${state.activePlugin === tab.id ? "active" : ""}" type="button" data-plugin-tab="${escapeHTML(tab.id)}">
                <span>${escapeHTML(tab.label)}</span><span class="plugin-tab-count">${escapeHTML(tab.count)}</span>
              </button>`
            )).join("");
            $$("[data-plugin-tab]").forEach((button) => {
              button.onclick = () => {
                state.activePlugin = button.dataset.pluginTab;
                renderPlugins();
              };
            });
          }

          function renderPluginSection(plugin) {
            const schema = plugin.schema_tables && plugin.schema_tables.length ? plugin.schema_tables.join(", ") : "none";
            const allows = (plugin.allows || []).map((item) => `<li>${escapeHTML(item)}</li>`).join("");
            const endpointKeys = new Set((plugin.endpoint_actions || []).map((action) => `${action.method || "GET"} ${action.path}`));
            const workflowActions = (plugin.examples || [])
              .map((example) => ({...example, method: example.method || "GET"}))
              .filter((example) => !endpointKeys.has(`${example.method} ${example.path}`));
            const workflows = workflowActions.map((action) => renderEndpointAction(action, "workflow")).join("");
            const actions = (plugin.endpoint_actions || []).map((action) => renderEndpointAction(action, "endpoint")).join("");
            return `<section class="plugin-section" id="plugin-${escapeHTML(plugin.id)}">
              <header class="plugin-section-header">
                <div class="plugin-heading">
                  <div>
                    <h3>${escapeHTML(plugin.id)}</h3>
                    <p class="plugin-description">${escapeHTML(plugin.description || "Enabled plugin.")}</p>
                  </div>
                  <div class="plugin-summary">
                    <span class="pill">${escapeHTML((plugin.endpoint_actions || plugin.endpoints || []).length)} endpoints</span>
                    <span class="pill">${escapeHTML((plugin.schema_tables || []).length)} tables</span>
                  </div>
                </div>
                ${allows ? `<ul class="plugin-capabilities">${allows}</ul>` : ""}
                <div class="plugin-details">
                  <span>schema: ${escapeHTML(schema)}</span>
                  <span>hooks: ${escapeHTML(plugin.hooks.before)} before, ${escapeHTML(plugin.hooks.after)} after</span>
                </div>
              </header>
              ${workflows ? `<div class="action-group"><p class="action-group-title">Workflow examples</p>${workflows}</div>` : ""}
              <div class="action-group">
                <p class="action-group-title">Endpoint actions</p>
                <div class="endpoint-actions">${actions || `<div class="plugin-empty">This plugin does not expose endpoints, but its hooks or schema are active.</div>`}</div>
              </div>
            </section>`;
          }

          function renderEndpointAction(action, kind) {
            const method = action.method || "GET";
            const methodClass = method.toLowerCase();
            const hasPayload = action.body !== undefined && action.body !== null && method !== "GET";
            const body = hasPayload ? JSON.stringify(action.body, null, 2) : "";
            const pathLabel = kind === "workflow" && action.label ? `<span class="action-label">${escapeHTML(action.label)}</span>` : "";
            return `<article class="endpoint-action" data-endpoint-action>
              <div class="endpoint-line">
                <span class="method-badge ${escapeHTML(methodClass)}">${escapeHTML(method)}</span>
                <code class="endpoint-path">${pathLabel}${escapeHTML(action.path)}</code>
                <button class="button" type="button" data-run-endpoint data-method="${escapeHTML(method)}" data-path="${escapeHTML(action.path)}">Send</button>
              </div>
              ${hasPayload ? `<details class="endpoint-payload"><summary>Request body</summary><textarea data-endpoint-body spellcheck="false">${escapeHTML(body)}</textarea></details>` : ""}
              <pre class="endpoint-output" data-endpoint-output hidden></pre>
            </article>`;
          }

          function renderDeliveries() {
            $("#delivery-list").innerHTML = state.deliveries.map((delivery) => (
              `<div class="delivery-item">
                <div class="plugin-title"><span>${escapeHTML(delivery.plugin)}</span><span class="muted">${escapeHTML(delivery.created_at)}</span></div>
                <pre>${escapeHTML(JSON.stringify(delivery.payload, null, 2))}</pre>
              </div>`
            )).join("") || `<div class="empty-state">No local deliveries yet.</div>`;
          }

          async function runPluginEndpoint(button) {
            const method = button.dataset.method || "GET";
            const path = button.dataset.path;
            const originalLabel = button.textContent;
            const action = button.closest("[data-endpoint-action]");
            const output = action.querySelector("[data-endpoint-output]");
            const bodyInput = action.querySelector("[data-endpoint-body]");
            button.disabled = true;
            button.textContent = "Loading...";
            output.hidden = false;
            output.textContent = "Loading...";
            showNotice("#plugins-notice", "");
            try {
              const options = { method };
              if (bodyInput) Object.assign(options, authRequestOptions(method, JSON.parse(bodyInput.value || "{}")));
              const data = await jsonFetch(path, options);
              output.textContent = JSON.stringify(data, null, 2);
              showNotice("#plugins-notice", `${method} ${path} completed.`, "ok");
              await loadCurrentSession();
              await loadSessions();
              const refreshed = await jsonFetch("/example/plugins");
              state.deliveries = refreshed.deliveries || [];
              renderDeliveries();
            } catch (error) {
              output.textContent = JSON.stringify({ error: error.message }, null, 2);
              showNotice("#plugins-notice", error.message, "error");
            } finally {
              button.disabled = false;
              button.textContent = originalLabel;
            }
          }

          async function loadPlugins() {
            showNotice("#plugins-notice", "Loading plugins...");
            try {
              const data = await jsonFetch("/example/plugins");
              state.plugins = data.plugins || [];
              state.deliveries = data.deliveries || [];
              state.excludedPlugins = data.excluded || [];
              renderPlugins();
              showNotice("#plugins-notice", "Plugins loaded.", "ok");
            } catch (error) {
              showNotice("#plugins-notice", error.message, "error");
            }
          }

          function renderDatabase() {
            const tabs = $("#table-tabs");
            tabs.innerHTML = "";
            const query = $("#table-filter").value.trim().toLowerCase();
            const filteredTables = state.tables.filter((table) => !query || table.name.toLowerCase().includes(query));
            $("#table-total").textContent = `${state.tables.length} tables`;
            filteredTables.forEach((table) => {
              const button = document.createElement("button");
              button.innerHTML = `<span class="nav-icon"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="1.5"/><path d="M4 10h16M10 4v16"/></svg></span><span class="table-name">${escapeHTML(table.name)}</span><span class="table-count">${escapeHTML(table.count)}</span>`;
              button.classList.toggle("active", table.name === state.activeTable);
              button.onclick = () => {
                state.activeTable = table.name;
                state.visibleColumns = new Set(table.columns);
                state.selectedIds = new Set();
                state.page = 0;
                renderDatabase();
              };
              tabs.appendChild(button);
            });
            const table = state.tables.find((entry) => entry.name === state.activeTable) || state.tables[0];
            if (!table) {
              $("#active-table-label").textContent = "No table selected";
              $("#table-meta").textContent = "No tables found.";
              $("#column-toggles").innerHTML = "";
              $("#records").innerHTML = `<div class="empty-state">No tables found for this provider.</div>`;
              updatePager(null, 0, 0);
              updateSelectionToolbar();
              return;
            }
            state.activeTable = table.name;
            if (!state.visibleColumns.size) state.visibleColumns = new Set(table.columns);
            $("#active-table-label").textContent = table.name;
            $("#table-meta").innerHTML = table.error
              ? `<span class="notice error">${escapeHTML(table.error)}</span>`
              : `<span>${escapeHTML(table.name)}</span><span>${escapeHTML(table.count)} rows, ${escapeHTML(table.columns.length)} columns</span>`;
            $("#column-toggles").innerHTML = table.columns.map((column) => `<label><input type="checkbox" data-column="${escapeHTML(column)}" ${state.visibleColumns.has(column) ? "checked" : ""}>${escapeHTML(column)}</label>`).join("");
            $$("#column-toggles input").forEach((input) => {
              input.onchange = () => {
                input.checked ? state.visibleColumns.add(input.dataset.column) : state.visibleColumns.delete(input.dataset.column);
                renderRows(table);
              };
            });
            renderRows(table);
            updateSelectionToolbar();
          }

          function renderRows(table) {
            const columns = table.columns.filter((column) => state.visibleColumns.has(column));
            if (!columns.length) {
              $("#records").innerHTML = `<div class="empty-state">No columns selected.</div>`;
              updatePager(table, 0, 0);
              updateSelectionToolbar();
              return;
            }
            const totalRows = table.rows.length;
            const totalPages = Math.max(1, Math.ceil(totalRows / state.pageSize));
            state.page = Math.min(state.page, totalPages - 1);
            const start = state.page * state.pageSize;
            const visibleRows = table.rows.slice(start, start + state.pageSize);
            const head = `<thead><tr><th class="row-selector"><span class="row-checkbox"></span></th>${columns.map((column) => `<th>${escapeHTML(column)}</th>`).join("")}</tr></thead>`;
            if (!table.rows.length) {
              $("#records").innerHTML = `<table>${head}<tbody><tr><td colspan="${columns.length + 1}" class="empty-row">This table has no records yet.</td></tr></tbody></table>`;
              updatePager(table, 0, 0);
              updateSelectionToolbar();
              return;
            }
            const body = `<tbody>${visibleRows.map((row) => {
              const id = recordId(row);
              const checked = state.selectedIds.has(id) ? "checked" : "";
              return `<tr><td class="row-selector"><input class="record-checkbox" type="checkbox" data-record-id="${escapeHTML(id)}" ${checked}></td>${columns.map((column) => {
              const value = formatValue(row[column]);
              return `<td title="${escapeHTML(value)}">${escapeHTML(value)}</td>`;
            }).join("")}</tr>`;
            }).join("")}</tbody>`;
            $("#records").innerHTML = `<table>${head}${body}</table>`;
            $$("#records .record-checkbox").forEach((checkbox) => {
              checkbox.onchange = () => {
                checkbox.checked ? state.selectedIds.add(checkbox.dataset.recordId) : state.selectedIds.delete(checkbox.dataset.recordId);
                updateSelectionToolbar();
              };
            });
            updatePager(table, start + 1, Math.min(start + state.pageSize, totalRows));
            updateSelectionToolbar();
          }

          function recordId(row) {
            return String(row.id ?? row._id ?? "");
          }

          function updateSelectionToolbar() {
            const count = state.selectedIds.size;
            $("#delete-records").disabled = count === 0;
            $("#delete-records").textContent = count ? `Delete selected (${count})` : "Delete selected";
          }

          function updatePager(table, start, end) {
            if (!table) {
              $("#page-label").textContent = "0 rows";
              return;
            }
            const total = table.rows.length;
            $("#page-label").textContent = total ? `${start}-${end} of ${total} loaded rows` : `${table.count} rows`;
            $("#page-size-label").textContent = String(state.pageSize);
            $("#prev-page").disabled = state.page <= 0;
            $("#next-page").disabled = end >= total;
          }

          function formatValue(value) {
            if (value === null || value === undefined) return "";
            if (typeof value === "object") return JSON.stringify(value);
            return String(value);
          }

          async function loadDatabase() {
            showNotice("#db-notice", "Loading tables...");
            try {
              const previousTable = state.activeTable;
              const data = await jsonFetch("/example/database");
              state.tables = data.tables || [];
              const nextTable = state.tables.find((table) => table.name === previousTable) || state.tables[0];
              state.activeTable = nextTable && nextTable.name;
              state.visibleColumns = new Set((nextTable && nextTable.columns) || []);
              state.selectedIds = new Set();
              state.page = 0;
              renderDatabase();
              showNotice("#db-notice", "Tables loaded.", "ok");
            } catch (error) {
              state.tables = [];
              state.activeTable = null;
              state.visibleColumns = new Set();
              renderDatabase();
              showNotice("#db-notice", error.message, "error");
            }
          }

          async function boot() {
            await loadSettings();
            const session = await loadCurrentSession();
            if (session) {
              await loadSessions();
            } else {
              $("#sessions-json").textContent = "[]";
            }
          }

          async function refreshCurrentView() {
            await boot();
            if (!$("[data-view='database']").hidden) await loadDatabase();
          }

          $$("[data-view-button]").forEach((button) => button.onclick = () => setView(button.dataset.viewButton));
          $("#refresh-all").onclick = refreshCurrentView;
          $("#load-session").onclick = loadCurrentSession;
          $("#load-sessions").onclick = loadSessions;
          $$("[data-social-provider]").forEach((button) => button.onclick = () => signInWithSocialProvider(button));
          $("#load-plugins").onclick = loadPlugins;
          $("#clear-deliveries").onclick = async () => {
            await jsonFetch("/example/plugins/clear-deliveries", { method: "POST", body: "{}" });
            await loadPlugins();
          };
          $("#reload-db").onclick = loadDatabase;
          $("#reload-db-toolbar").onclick = loadDatabase;
          $("#table-filter").oninput = renderDatabase;
          $("#columns-button").onclick = () => $("#column-toggles").classList.toggle("open");
          $("#prev-page").onclick = () => {
            state.page = Math.max(0, state.page - 1);
            renderDatabase();
          };
          $("#next-page").onclick = () => {
            state.page += 1;
            renderDatabase();
          };
          $("#delete-records").onclick = async () => {
            const ids = Array.from(state.selectedIds);
            if (!ids.length || !state.activeTable) return;

            try {
              const data = await jsonFetch("/example/database/delete", {
                method: "POST",
                body: JSON.stringify({table: state.activeTable, ids})
              });
              showNotice("#db-notice", `Deleted ${data.deleted || 0} records.`, "ok");
              state.selectedIds = new Set();
              await loadDatabase();
            } catch (error) {
              showNotice("#db-notice", error.message, "error");
            }
          };
          document.addEventListener("click", (event) => {
            if (!event.target.closest(".columns-popover")) $("#column-toggles").classList.remove("open");
          });

          $("#signup-form").onsubmit = async (event) => {
            event.preventDefault();
            try {
              const body = formData(event.currentTarget);
              body.captchaResponse = "example-token";
              await jsonFetch("/api/auth/sign-up/email", authRequestOptions("POST", body));
              showNotice("#auth-notice", "Account created.", "ok");
              await loadCurrentSession();
              await loadSessions();
              if (!$("[data-view='database']").hidden) await loadDatabase();
            } catch (error) {
              showNotice("#auth-notice", error.message, "error");
            }
          };

          $("#signin-form").onsubmit = async (event) => {
            event.preventDefault();
            try {
              await jsonFetch("/api/auth/sign-in/email", { method: "POST", body: JSON.stringify(formData(event.currentTarget)) });
              showNotice("#auth-notice", "Signed in.", "ok");
              await loadCurrentSession();
              await loadSessions();
            } catch (error) {
              showNotice("#auth-notice", error.message, "error");
            }
          };

          $("#sign-out").onclick = async () => {
            try {
              await jsonFetch("/api/auth/sign-out", { method: "POST", body: "{}" });
              showNotice("#auth-notice", "Signed out.", "ok");
            } catch (error) {
              showNotice("#auth-notice", error.message, "error");
            }
            await loadCurrentSession();
            await loadSessions();
          };

          $("#settings-form").onsubmit = async (event) => {
            event.preventDefault();
            try {
              const data = await jsonFetch("/example/settings", { method: "POST", body: JSON.stringify(formData(event.currentTarget)) });
              state.settings = data.settings;
              renderSettings();
              renderProfile(null);
              showNotice("#settings-notice", "Settings applied. Session cookies were cleared.", "ok");
              await loadCurrentSession();
              await loadSessions();
              if (!$("[data-view='database']").hidden) await loadDatabase();
            } catch (error) {
              showNotice("#settings-notice", error.message, "error");
            }
          };

          $("#drop-db").onclick = () => $("#drop-dialog").showModal();
          $("#cancel-drop-db").onclick = () => $("#drop-dialog").close();

          $("#confirm-drop-db").onclick = async () => {
            $("#drop-dialog").close();
            try {
              await jsonFetch("/example/reset", { method: "POST", body: "{}" });
              showNotice("#db-notice", "Database reset and migrated.", "ok");
              await loadCurrentSession();
              await loadSessions();
              await loadDatabase();
            } catch (error) {
              showNotice("#db-notice", error.message, "error");
            }
          };

          boot();
        </script>
      </body>
      </html>
    HTML
  end
end

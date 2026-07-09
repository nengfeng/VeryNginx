-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : config controller - config get/set, status, metrics, summary, csrf, audit, export/import

local _M = {}

local json = require "dkjson"
local audit = require "core.audit"

--- POST /config - update config
local function handle_set_config()
    -- Rate limit config saves
    local rl = require "api.rate_limit"
    if not rl.allow("config_save:" .. (ngx.var.remote_addr or ""), 30, 60) then
        ngx.status = 429
        return json.encode({ ret = "failed", message = "too many requests" })
    end

    -- Limit request body size to prevent memory exhaustion (DoS)
    local cl = tonumber(ngx.var.content_length) or 0
    if cl > 1048576 then
        ngx.status = 413
        return json.encode({ ret = "failed", message = "request body too large (max 1MB)" })
    end

    ngx.req.read_body()
    local content_type = ngx.var.content_type or ""
    local raw_body = ngx.req.get_body_data()
    if not raw_body or raw_body == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end

    local new_config

    -- Support both JSON body and form-encoded + base64
    if content_type:lower():find("application/json", 1, true) then
        new_config = json.decode(raw_body)
    else
        local args = ngx.req.get_post_args()
        if args and args.config then
            local decoded = ngx.decode_base64(args.config)
            if decoded then
                local unescaped = ngx.unescape_uri(decoded)
                new_config = json.decode(unescaped)
            end
        end
    end

    if not new_config then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid config" })
    end

    local ok, err = require("core.config").save(new_config)
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = err })
    end

    return json.encode({ ret = "success" })
end

--- GET /status - return runtime status
local function handle_get_status()
    local status_info = {
        ret = "success",
        time = ngx.now(),
        connections_active = ngx.var.connections_active,
        connections_reading = ngx.var.connections_reading,
        connections_writing = ngx.var.connections_writing,
        connections_waiting = ngx.var.connections_waiting,
    }
    return json.encode(status_info)
end

--- GET /metrics - return Prometheus metrics
local function handle_get_metrics()
    ngx.header["Content-Type"] = "text/plain; version=0.0.4"
    return require("core.metrics").export_prometheus()
end

--- GET /summary - return request statistics
local function handle_get_summary()
    local args = ngx.req.get_uri_args()
    return require("core.statistics").report(args.type or "short")
end

--- GET /csrf - return a CSRF token (stored in session for later verification)
local function handle_get_csrf()
    local ctx = ngx.ctx.vn_ctx
    if not ctx then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "no request context" })
    end
    local csrf = require "api.csrf"
    local token = csrf.generate(ctx)
    return json.encode({ ret = "success", csrf_token = token })
end

--- GET /config - sanitize config dump (remove password hashes)
local function handle_get_config()
    local raw = require("core.config").report()
    local ok, decoded = pcall(json.decode, raw)
    if ok and decoded and decoded.admin then
        for _, a in ipairs(decoded.admin) do
            a.password_hash = "(redacted)"
        end
    end
    if ok then
        return json.encode(decoded)
    end
    return raw
end

--- GET /config/export - download config.json
local function handle_export_config()
    local path = require("core.config").resolve_path() .. "configs/config.json"
    local f = io.open(path, "r")
    if not f then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "config file not found" })
    end
    local content = f:read("*all")
    f:close()
    ngx.header["content-type"] = "application/json; charset=utf-8"
    ngx.header["content-disposition"] = 'attachment; filename="config.json"'
    return content
end

--- POST /config/import - upload config.json
local function handle_import_config()
    local cl = tonumber(ngx.var.content_length) or 0
    if cl > 1048576 then
        ngx.status = 413
        return json.encode({ ret = "failed", message = "request body too large" })
    end
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or raw == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "body required" })
    end
    local ok, parsed = pcall(json.decode, raw)
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid json" })
    end
    local ok2, err = require("core.config").save(parsed)
    if not ok2 then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(err) })
    end
    return json.encode({ ret = "success" })
end

--- GET /audit - recent audit log entries
local function handle_get_audit()
    local limit = tonumber(ngx.var.arg_limit) or 200
    if limit > 1000 then limit = 1000 end
    local user_filter = ngx.var.arg_user
    local action_filter = ngx.var.arg_action
    local since_ts = tonumber(ngx.var.arg_since)
    local until_ts = tonumber(ngx.var.arg_until)
    local entries = audit.get_filtered(user_filter, action_filter, since_ts, until_ts, limit)
    return json.encode({ ret = "success", data = entries })
end

function _M.register(api)
    api.register("GET", "/config", handle_get_config, true)
    api.register("POST", "/config", handle_set_config, true)
    api.register("GET", "/status", handle_get_status, true)
    api.register("GET", "/metrics", handle_get_metrics, false)
    api.register("GET", "/summary", handle_get_summary, true)
    api.register("GET", "/csrf", handle_get_csrf, true)
    api.register("GET", "/audit", handle_get_audit, true)
    api.register("GET", "/config/export", handle_export_config, true)
    api.register("POST", "/config/import", handle_import_config, true)
end

return _M

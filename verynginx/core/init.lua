-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : initialization entry - config load, shared dict, matcher/plugin registration

local _M = {}

local config = require "core.config"
local plugin = require "core.plugin"

-- ---------------------------------------------------------------------------
-- init_by_lua
-- ---------------------------------------------------------------------------
function _M.init()
    config.load_from_file()
    _M.init_shared_dict()
    _M._validate_config()
    _M.register_matchers()
    _M.register_plugins()
    plugin.init_all()

    -- Restore persisted IP reputation data
    local ip_reputation = require "core.ip_reputation"
    ip_reputation.restore()
end

function _M._validate_config()
    local c = require "core.config"
    if not c.security or not c.security.session_secret or c.security.session_secret == "" then
        ngx.log(ngx.WARN, "init: security.session_secret is not configured; " ..
                          "session auth will fail until it is set in config.json")
    end
    if c.admin then
        for _, a in ipairs(c.admin) do
            if a.password_hash and a.password_hash ~= "" then
                return
            end
        end
        ngx.log(ngx.WARN, "init: no admin has a password_hash set; " ..
                          "login will be impossible until you set password_hash in config.json")
    end
end

function _M.init_shared_dict()
    local shared = ngx.shared.vn_config
    if shared then
        shared:set("config_hash", config.local_hash or "")
    end
end

function _M.register_matchers()
    local matcher = require "matcher.init"
    matcher.register("URI", require("matcher.uri").test)
    matcher.register("IP", require("matcher.ip").test)
    matcher.register("UserAgent", require("matcher.ua").test)
    matcher.register("Host", require("matcher.host").test)
    matcher.register("Referer", require("matcher.referer").test)
    matcher.register("Args", require("matcher.args").test)
    matcher.register("Header", require("matcher.header").test)
    matcher.register("Cookie", require("matcher.cookie").test)
    matcher.register("Method", require("matcher.method").test)
    matcher.register("Composite", require("matcher.composite").test)
end

function _M.register_plugins()
    plugin.register(require "plugin.filter.init")
    plugin.register(require "plugin.frequency_limit.init")
    plugin.register(require "plugin.browser_verify.init")
    plugin.register(require "plugin.router.init")
    plugin.register(require "plugin.proxy_pass.init")
    plugin.register(require "plugin.static_file.init")
    plugin.register(require "plugin.summary.init")
end

-- ---------------------------------------------------------------------------
-- init_worker_by_lua
-- ---------------------------------------------------------------------------
function _M.init_worker()
    local metrics = require "core.metrics"
    local observability = require "core.observability"
    local statistics = require "core.statistics"
    local health_check = require "plugin.proxy_pass.health_check"
    local waf_manager = require "waf-rule-manager"

    metrics.init()
    observability.init()
    statistics.init()
    health_check.init()
    waf_manager.init_worker()
    local alerting = require "core.alerting"
    alerting.init()

    -- Only worker 0 does I/O for persistence
    local ip_reputation = require "core.ip_reputation"
    local geoip_updater = require "core.geoip_updater"
    geoip_updater.init()
    if ngx.worker.id() == 0 then
        ngx.timer.every(600, function()
            ip_reputation.persist()
        end)
        -- Persist ip_reputation on worker shutdown
        local function ip_rep_persist_on_exit(premature)
            if premature then return end
            if ngx.worker.exiting() then
                ip_reputation.persist()
                return
            end
            ngx.timer.at(1, ip_rep_persist_on_exit)
        end
        ngx.timer.at(1, ip_rep_persist_on_exit)
    end
end

return _M
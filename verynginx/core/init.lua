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

    -- Initialize GeoIP database
    local geoip = require "core.geoip"
    local geoip_cfg = config.geoip or {}
    if not geoip_cfg.geodb_path or geoip_cfg.geodb_path == "" then
        -- Auto-detect: derive VN_PREFIX from this module's path
        -- module path is @/VN_PREFIX/core/init.lua
        local prefix = debug.getinfo(1, "S").source:match("^@(.+)/core/")
            or "/opt/verynginx"
        geoip_cfg.geodb_path = prefix .. "/geoip/GeoLite2-City.mmdb"
    end
    geoip.init(geoip_cfg.geodb_path)

    -- Restore persisted IP reputation data
    local ip_reputation = require "core.ip_reputation"
    ip_reputation.restore()

    -- Initialize whitelist generation epoch (Phase 1)
    local wlg = require "core.kernel_blocking.whitelist_generation"
    wlg.init_epoch()
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

    -- Only worker 0 does I/O for persistence and background evaluation
    local ip_reputation = require "core.ip_reputation"
    local geoip_updater = require "core.geoip_updater"
    geoip_updater.init()
    if ngx.worker.id() == 0 then
        -- IP reputation persistence (every 600s)
        ngx.timer.every(600, function()
            ip_reputation.persist()
        end)

        -- Phase 1: Kernel blocking promotion policy (observe-only).
        -- Self-rescheduling timer for hot-reloadable batch_interval.
        local promotion = require "core.kernel_blocking.promotion"
        local function promotion_timer(_batch_interval)
            if ngx.worker.exiting() then return end
            local ok, err = pcall(function()
                promotion.process_candidates(ngx.time())
            end)
            if not ok then
                ngx.log(ngx.WARN, "kernel_blocking promotion eval error: ", err)
            end
            -- Re-read config for hot-reloadable interval, then reschedule
            local kb_cfg = config.kernel_ip_blocking
            local interval = (kb_cfg and kb_cfg.batch_interval) or 1
            ngx.timer.at(math.max(interval, 1), function(premature)
                if premature then return end
                promotion_timer(interval)
            end)
        end
        -- Start after a short delay (don't block startup)
        ngx.timer.at(1, function(premature)
            if premature then return end
            promotion_timer(1)
        end)

        -- Phase 2: Kernel blocking reconciliation (dry-run observer).
        -- Self-rescheduling timer for hot-reloadable reconcile_interval.
        local reconcile_mod = require "core.kernel_blocking.reconciliation"
        local function reconcile_timer(_unused)
            if ngx.worker.exiting() then return end
            local ok, err = pcall(function()
                reconcile_mod.reconcile(ngx.time())
            end)
            if not ok then
                ngx.log(ngx.WARN, "kernel_blocking reconcile error: ", err)
            end
            local kb_cfg = config.kernel_ip_blocking
            local interval = (kb_cfg and kb_cfg.reconcile_interval) or 30
            ngx.timer.at(math.max(interval, 5), function(premature)
                if premature then return end
                reconcile_timer(interval)
            end)
        end
        -- Start reconcile shortly after promotion starts
        ngx.timer.at(5, function(premature)
            if premature then return end
            reconcile_timer(30)
        end)

        -- Persist kernel state on worker shutdown (Phase 1: candidates in shared dict survive)
        local function kernel_blocking_persist_on_exit(premature)
            if premature then return end
            if ngx.worker.exiting() then
                -- Phase 1 observes only; no desired-state to persist yet.
                -- Phase 3+ will persist desired state here.
                return
            end
            ngx.timer.at(1, kernel_blocking_persist_on_exit)
        end
        ngx.timer.at(1, kernel_blocking_persist_on_exit)

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
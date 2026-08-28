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

    -- Kernel blocking: restore desired state only (no socket I/O here)
    local kb = require "core.kernel_blocking.init"
    kb.restore()
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
        local kb = require "core.kernel_blocking.init"
        local wlg = require "core.kernel_blocking.whitelist_generation"

        -- Unified persistence every 600s (ip reputation + kernel blocking)
        -- Fixed interval: timer.every is fine (not hot-reloaded).
        -- On a graceful reload OpenResty cancels the timer with premature=true;
        -- we must still flush here, otherwise up to 10 minutes of in-memory
        -- state (ip_reputation scores / kernel_blocking desired state) is lost.
        ngx.timer.every(600, function(premature)
            if premature then
                pcall(function() ip_reputation.persist() end)
                pcall(function() kb.persist() end)
                return
            end
            if ngx.worker.exiting() then return end
            pcall(function() ip_reputation.persist() end)
            pcall(function() kb.persist() end)
        end)

        -- Periodically refresh the kernel allow snapshot so expired
        -- auto-whitelist entries drop out of the Helper allow list without
        -- waiting for the next whitelist change to bump the sequence.
        ngx.timer.every(60, function(premature)
            if premature or ngx.worker.exiting() then return end
            pcall(function() wlg.push_allow_snapshot() end)
        end)

        -- Helper bootstrap then first reconcile (Design §10.3)
        ngx.timer.at(1, function(premature)
            if premature or ngx.worker.exiting() then return end
            local ok, err = pcall(function() kb.bootstrap() end)
            if not ok then
                ngx.log(ngx.WARN, "kernel_blocking bootstrap error: ", err)
            end
            local rok, rerr = pcall(function() return kb.reconcile(ngx.time()) end)
            if not rok then
                ngx.log(ngx.WARN, "kernel_blocking initial reconcile error: ", rerr)
            elseif type(rerr) == "table" and rerr.skipped == "lease_busy" then
                ngx.log(ngx.INFO, "kernel_blocking initial reconcile skipped: lease_busy")
            end
        end)

        -- Batch callback: process candidates + flush dispatch (self-rescheduling).
        -- Hot-reloadable interval; lease inside process_candidates prevents overlap
        -- when a slow call outlives the next fire or after graceful reload.
        local function promotion_timer()
            if ngx.worker.exiting() then return end
            local ok, res = pcall(function()
                return kb.process_candidates(ngx.time())
            end)
            if not ok then
                ngx.log(ngx.WARN, "kernel_blocking promotion eval error: ", res)
            elseif type(res) == "table" and res.skipped == "lease_busy" then
                ngx.log(ngx.INFO, "kernel_blocking batch skipped: lease_busy")
            end
            if ngx.worker.exiting() then return end
            local kb_cfg = config.kernel_ip_blocking
            local interval = (kb_cfg and kb_cfg.batch_interval) or 1
            local delay = math.max(tonumber(interval) or 1, 1)
            local at_ok, at_err = ngx.timer.at(delay, function(premature)
                if premature or ngx.worker.exiting() then return end
                promotion_timer()
            end)
            if not at_ok then
                ngx.log(ngx.ERR, "kernel_blocking batch timer reschedule failed: ", at_err)
            end
        end
        ngx.timer.at(2, function(premature)
            if premature or ngx.worker.exiting() then return end
            promotion_timer()
        end)

        -- Reconcile callback (self-rescheduling, lease-guarded)
        local function reconcile_timer()
            if ngx.worker.exiting() then return end
            local ok, res = pcall(function()
                return kb.reconcile(ngx.time())
            end)
            if not ok then
                ngx.log(ngx.WARN, "kernel_blocking reconcile error: ", res)
            elseif type(res) == "table" and res.skipped == "lease_busy" then
                ngx.log(ngx.INFO, "kernel_blocking reconcile skipped: lease_busy")
            end
            if ngx.worker.exiting() then return end
            local kb_cfg = config.kernel_ip_blocking
            local interval = (kb_cfg and kb_cfg.reconcile_interval) or 30
            local delay = math.max(tonumber(interval) or 30, 5)
            local at_ok, at_err = ngx.timer.at(delay, function(premature)
                if premature or ngx.worker.exiting() then return end
                reconcile_timer()
            end)
            if not at_ok then
                ngx.log(ngx.ERR, "kernel_blocking reconcile timer reschedule failed: ", at_err)
            end
        end
        ngx.timer.at(5, function(premature)
            if premature or ngx.worker.exiting() then return end
            reconcile_timer()
        end)

        -- Exit polling: persist state once when worker is exiting.
        -- Merged kb + ip_rep into a single timer at 3s interval to reduce idle overhead.
        local function persist_on_exit(premature)
            if premature then return end
            if ngx.worker.exiting() then
                pcall(function() kb.persist() end)
                pcall(function() ip_reputation.persist() end)
                return
            end
            ngx.timer.at(3, persist_on_exit)
        end
        ngx.timer.at(3, persist_on_exit)
    end
end

return _M
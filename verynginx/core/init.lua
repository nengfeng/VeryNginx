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
    _M.register_matchers()
    _M.register_plugins()
    plugin.init_all()
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
end

function _M.register_plugins()
    plugin.register(require "plugin.filter.init")
    plugin.register(require "plugin.frequency_limit.init")
    plugin.register(require "plugin.browser_verify.init")
    plugin.register(require "plugin.router.init")
    plugin.register(require "plugin.proxy_pass.init")
    plugin.register(require "plugin.static_file.init")
    -- summary     plugin.register(require "plugin.summary.init")     -- Phase 6
end

-- ---------------------------------------------------------------------------
-- init_worker_by_lua
-- ---------------------------------------------------------------------------
function _M.init_worker()
    local metrics = require "core.metrics"
    local observability = require "core.observability"
    local statistics = require "core.statistics"
    local health_check = require "plugin.proxy_pass.health_check"

    metrics.init()
    observability.init()
    statistics.init()
    health_check.init()
end

return _M
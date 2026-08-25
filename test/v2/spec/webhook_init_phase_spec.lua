-- -*- coding: utf-8 -*-
-- Regression: a domain-shaped webhook in config.json bricked nginx startup.
-- Chain: init_by_lua -> load_from_file -> validate_config ->
-- validate_webhook_url -> DNS cosocket -> "no request found" (cosockets are
-- forbidden in the init phase) raised straight through and exited(1).
--
-- Contract now: in the init/init_worker phases validate_webhook_url must
-- accept on literal checks alone (send-time dispatch re-validates WITH DNS);
-- outside those phases, resolver-unavailable stays fail-closed DENY.
package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
_G.ngx.WARN = 6
local warns = {}
_G.ngx.log = function(_, ...) warns[#warns + 1] = table.concat({ ... }, "") end

local phase = "init"
_G.ngx.get_phase = function() return phase end

describe("webhook 校验的阶段感知(init 阶段不得 brick 启动)", function()
    local alerting

    setup(function()
        package.preload["core.config"] = function()
            return { nameservers = { "8.8.8.8" } }
        end
        -- resty.dns.resolver must NEVER be reached from init; if it is, this
        -- stub explodes loudly so the test fails for the right reason.
        package.preload["resty.dns.resolver"] = function()
            error("cosocket used in init phase!", 2)
        end
        package.loaded["core.alerting"] = nil
        alerting = require("core.alerting")
    end)

    teardown(function()
        package.preload["core.config"] = nil
        package.preload["resty.dns.resolver"] = nil
        package.loaded["core.alerting"] = nil
    end)

    it("init 阶段: 域名 webhook 仅凭字面检查通过(不碰 cosocket)", function()
        phase = "init"
        warns = {}
        local ok, err = alerting.validate_webhook_url("https://hooks.example.com/x")
        assert.is_true(ok, tostring(err))
        assert.equals(0, #warns) -- 不走 fail-closed 告警路径
    end)

    it("init 阶段: 字面违规仍然拒绝(私网/非https)", function()
        phase = "init"
        assert.is_false(alerting.validate_webhook_url("http://hooks.example.com/x"))
        assert.is_false(alerting.validate_webhook_url("https://10.0.0.5/hook"))
        assert.is_false(alerting.validate_webhook_url("https://127.0.0.1/hook"))
    end)

    it("request 阶段: 解析器不可用保持 fail-closed 拒绝", function()
        phase = "timer" -- 非 init, 允许尝试 cosocket → 我们的桩会 error → pcall 降级为不可用
        warns = {}
        local ok, err = alerting.validate_webhook_url("https://hooks.example.com/x")
        assert.is_false(ok)
        assert.matches("DNS resolution unavailable", tostring(err))
        assert.equals(1, #warns)
    end)

    it("字面 IP 公网直通不触发解析", function()
        phase = "init"
        local ok = alerting.validate_webhook_url("https://93.184.216.34/hook")
        assert.is_true(ok)
    end)
end)

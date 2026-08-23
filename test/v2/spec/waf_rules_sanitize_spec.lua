-- -*- coding: utf-8 -*-
-- Coverage for waf-rule-manager.sanitize_rule_list: a hand-edited/imported
-- rules file can contain [null] holes. cjson decodes them to cjson.null
-- (lightuserdata, NOT nil) — they must never reach the API response
-- (dashboard "r.id" render crash) or per-request rule evaluation.
package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
_G.ngx.WARN = 6
local logs = {}
_G.ngx.log = function(_, ...)
    logs[#logs + 1] = table.concat({ ... }, "")
end

describe("waf 规则列表消毒(sanitize_rule_list)", function()
    local waf

    setup(function()
        package.loaded["waf-rule-manager"] = nil
        -- config/matcher are required by the module; minimal fakes keep this
        -- spec focused on list sanitation.
        package.preload["core.config"] = function()
            return { resolve_path = function() return "/tmp/" end }
        end
        package.preload["matcher.init"] = function()
            return { register = function() end, resolve = function() return nil end,
                     test = function() return false end }
        end
        waf = require("waf-rule-manager")
    end)

    teardown(function()
        package.preload["core.config"] = nil
        package.preload["matcher.init"] = nil
        package.loaded["waf-rule-manager"] = nil
    end)

    it("剔除非 table 条目(垃圾值), 保留合法规则与顺序", function()
        local clean = waf.sanitize_rule_list({
            { id = "a", name = "A" },
            "garbage",
            { id = "b", name = "B" },
            42,
        })
        assert.equals(2, #clean)
        assert.equals("a", clean[1].id)
        assert.equals("b", clean[2].id)
    end)

    it("丢弃条目时记录 WARN 日志且计数正确", function()
        logs = {}
        local clean = waf.sanitize_rule_list({ { id = "ok" }, false, true })
        assert.equals(1, #clean)
        assert.equals(1, #logs)
        assert.truthy(logs[1]:find("dropped 2 corrupt"))
    end)

    it("nil 洞数组与非 table 入参归一为空表", function()
        assert.equals(0, #waf.sanitize_rule_list({ nil, nil }))
        assert.equals(0, #waf.sanitize_rule_list(nil))
        assert.equals(0, #waf.sanitize_rule_list("not-a-list"))
    end)

    it("干净列表零日志通过", function()
        logs = {}
        local out = waf.sanitize_rule_list({ { id = "r1" }, { id = "r2" }, { id = "r3" } })
        assert.equals(3, #out)
        assert.equals("r1", out[1].id)
        assert.equals("r3", out[3].id)
        assert.equals(0, #logs)
    end)
end)

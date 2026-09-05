-- -*- coding: utf-8 -*-
-- Coverage for plugin/router/init.lua static-path mapping.
--
-- Regression: the Lua fallback mapped /verynginx/static/style.css to
-- <prefix>/dashboard/static/style.css (file lives FLAT in dashboard/), so
-- every dashboard asset 404'd whenever the nginx alias location was absent
-- from the active server block (reinstall scenarios). The fallback must now
-- strip the /static/ segment — identical mapping to the alias location.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
_G.ngx.unescape_uri = function(s) return s end
local exited_with = nil
_G.ngx.exit = function(code) exited_with = code; return nil end
_G.ngx.status = 0

describe("router 静态资源路径映射", function()
    local router, captured, decision, saved

    local function make_ctx(uri)
        return {
            request = { uri = uri },
            set_data = function() end,
            has_decision = function() return decision end,
            set_action = function(_, t, d) captured = { type = t, data = d } end,
        }
    end

    before_each(function()
        captured, decision, exited_with = nil, false, nil
        saved = {
            cfg_pre = package.preload["core.config"],
            cfg = package.loaded["core.config"],
            api = package.loaded["api.init"],
            router = package.loaded["plugin.router.init"],
        }
        package.preload["core.config"] = function()
            return {
                base_uri = "/verynginx",
                resolve_path = function() return "/opt/vn/" end,
            }
        end
        package.loaded["core.config"] = nil
        package.loaded["api.init"] = { dispatch = function() end }
        package.loaded["plugin.router.init"] = nil
        router = require "plugin.router.init"
    end)

    after_each(function()
        package.preload["core.config"] = saved.cfg_pre
        package.loaded["core.config"] = saved.cfg
        package.loaded["api.init"] = saved.api
        package.loaded["plugin.router.init"] = saved.router
    end)

    it("资产 URL 剥离 /static/ 段 → 映射到 dashboard 根下的扁平文件", function()
        router.on_access(make_ctx("/verynginx/static/style.css"))
        assert.equals("static", captured.type)
        assert.equals("/opt/vn/dashboard", captured.data.root)
        assert.equals("style.css", captured.data.path)
    end)

    it("嵌套静态文件同样剥离(vue.global.prod.js / vn-kb.js)", function()
        router.on_access(make_ctx("/verynginx/static/vue.global.prod.js"))
        assert.equals("vue.global.prod.js", captured.data.path)
    end)

    it("面板根 URI → index.html(原有行为不变)", function()
        router.on_access(make_ctx("/verynginx"))
        assert.equals("static", captured.type)
        assert.equals("/index.html", captured.data.path)
        router.on_access(make_ctx("/verynginx/index.html"))
        assert.equals("/index.html", captured.data.path)
    end)

    it("裸 /static 也归一为 index.html", function()
        router.on_access(make_ctx("/verynginx/static"))
        assert.equals("/index.html", captured.data.path)
    end)

    it("API 已裁决(has_decision)时不再覆盖为静态动作", function()
        decision = true
        router.on_access(make_ctx("/verynginx/static/style.css"))
        assert.is_nil(captured)
    end)

    it("穿越攻击仍然 403(剥离前已完成消毒)", function()
        router.on_access(make_ctx("/verynginx/static/../config.json"))
        -- Must be set via ctx.set_action("block"), not ngx.exit (which would be
        -- swallowed by the pcall wrapper in core/plugin.lua).
        assert.is_not_nil(captured)
        assert.equals("block", captured.type)
        assert.equals(403, captured.data.code)
    end)

    it("非 base_uri 请求完全不处理", function()
        router.on_access(make_ctx("/other/page"))
        assert.is_nil(captured)
        assert.is_nil(exited_with)
    end)
end)

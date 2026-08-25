-- -*- coding: utf-8 -*-
-- Regression: static_file.serve() used ngx.say() for the response body.
-- ngx.say APPENDS a trailing newline — every Lua-served file grew by exactly
-- one byte, silently breaking SRI pins (vue.global.prod.js integrity error)
-- while the on-disk file stayed pristine (nothing to find in forensics).
-- serve() must emit the body verbatim via ngx.print().
package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
-- Save every global we touch; restore in after_each (process-global hygiene —
-- busted runs all specs in one Lua process, leaked stubs poison later files).
local __saved = {}
for _, k in ipairs({ "print", "say", "exit", "header", "http_time",
                     "parse_http_time", "var", "fs_time" }) do
    __saved[k] = _G.ngx[k]
end
_G.ngx.EXIT_OK = 0
local printed, said, exited, headers = {}, {}, nil, {}
_G.ngx.print = function(s) printed[#printed + 1] = tostring(s) end
_G.ngx.say = function(s) said[#said + 1] = tostring(s) end
_G.ngx.exit = function(c) exited = c; error("EXIT:" .. tostring(c)) end
_G.ngx.header = headers
function _G.ngx.http_time() return "now" end
function _G.ngx.parse_http_time() return nil end
_G.ngx.var = {}
if not _G.ngx.fs_time then _G.ngx.fs_time = function() return 1700000000 end end

describe("static_file.serve 字节保真(禁 ngx.say)", function()
    local sf, body_path
    local __cfg_pre, __cfg_loaded

    setup(function()
        -- Take explicit control of core.config for THIS spec: clear loaded so
        -- our preload wins regardless of what earlier specs left behind
        -- (§9.3 poison pattern), then restore BOTH layers afterwards.
        __cfg_pre = package.preload["core.config"]
        __cfg_loaded = package.loaded["core.config"]
        package.preload["core.config"] = function()
            return { resolve_path = function() return "/tmp/" end,
                     static_file = { x_accel_threshold = 1e9 } }
        end
        package.loaded["core.config"] = nil
        package.loaded["plugin.static_file.init"] = nil
        sf = require("plugin.static_file.init")
        body_path = "/tmp/opencode/vn_sri_probe.js"
    end)

    teardown(function()
        package.preload["core.config"] = __cfg_pre
        package.loaded["core.config"] = __cfg_loaded
        package.loaded["plugin.static_file.init"] = nil
    end)

    before_each(function()
        printed, said, exited, headers = {}, {}, nil, {}
        _G.ngx.header = headers
        local f = io.open(body_path, "wb")
        f:write("})();\n")
        f:close()
    end)

    after_each(function()
        for k, v in pairs(__saved) do _G.ngx[k] = v end
        if not __saved.print then _G.ngx.print = nil end
        if not __saved.say then _G.ngx.say = nil end
        if not __saved.exit then _G.ngx.exit = nil end
        package.loaded["plugin.static_file.init"] = nil
    end)

    local function serve_capturing_exit()
        local ok, err = pcall(sf.serve, "/tmp/opencode", "/vn_sri_probe.js", "epoch")
        -- serve ends with ngx.exit which we turn into an error to stop execution
        return ok, err
    end

    it("响应体与磁盘字节完全一致(无追加换行)", function()
        serve_capturing_exit()
        assert.equals(1, #printed)
        assert.equals("})();\n", printed[1])
    end)

    it("绝不调用 ngx.say", function()
        serve_capturing_exit()
        assert.equals(0, #said)
    end)

    it("epoch 策略设置 no-store 缓存头", function()
        serve_capturing_exit()
        assert.equals("no-cache, no-store, must-revalidate",
                      tostring(headers["Cache-Control"]))
    end)
end)

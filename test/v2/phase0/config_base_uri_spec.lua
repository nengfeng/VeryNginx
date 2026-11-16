-- -*- coding: utf-8 -*-
-- base_uri must not be changeable through the configuration API.
--
-- base_uri is the management path, and THREE layers have to agree on it:
--
--   * the nginx location block that serves the dashboard
--     (/verynginx/static/ and /verynginx/), written at install time and
--     only re-read on reload;
--   * the Lua route matcher (api/init.lua);
--   * the dashboard's own API calls, which hard-code the prefix.
--
-- Changing base_uri in the config alone therefore produces a panel that
-- cannot load its own page or call its own API. Measured on a running
-- instance: with base_uri changed, the dashboard page AND every static
-- asset return 404, and only an SSH edit of config.json plus an nginx
-- reload brings the panel back — the operator has locked themselves out
-- of their own panel with a save that reported success.
--
-- The configuration save now refuses the change and explains what it
-- would take. The field stays in the schema: a deployment may legitimately
-- run a custom base_uri, set at install time or by hand — only a CHANGE
-- made through the config API is rejected.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local function ensure_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.WARN = 6; ngx.ERR = 5
    ngx.time = function() return 1700000000 end
    ngx.md5 = function(s) return "x" end
    ngx.now = function() return os.time() end
    ngx.random_bytes = function(n) return string.rep("R", n) end
    ngx.shared = setmetatable({}, {
        __index = function(_, name)
            local stores = ngx._stores or {}
            local expires = ngx._expires or {}
            if not stores[name] then stores[name] = {} end
            if not expires[name] then expires[name] = {} end
            local st = stores[name]
            local ex = expires[name]
            return {
                get = function(_, key)
                    if ex[key] and ngx.time() > ex[key] then
                        st[key] = nil; ex[key] = nil
                    end
                    return st[key]
                end,
                set = function(_, key, val, ttl)
                    st[key] = val
                    if ttl then ex[key] = ngx.time() + ttl end
                    return true
                end,
                add = function(_, key, val, ttl)
                    if ex[key] and ngx.time() > ex[key] then
                        st[key] = nil; ex[key] = nil
                    end
                    if st[key] then return false end
                    st[key] = val
                    if ttl then ex[key] = ngx.time() + ttl end
                    return true
                end,
                delete = function(_, key) st[key] = nil; ex[key] = nil end,
                incr = function(_, key, delta, init, ttl)
                    local n = (st[key] or init or 0) + delta
                    st[key] = n
                    return n
                end,
                expire = function(_, key, ttl) if ttl then ex[key] = ngx.time() + ttl end end,
            }
        end,
    })
end
ensure_ngx()

local config = require "core.config"

describe("base_uri is not changeable through the config API", function()

    before_each(function()
        ensure_ngx()
    end)

    it("refuses a change of base_uri", function()
        -- Install a config with the default base_uri first.
        local ok, err = config.save({
            version = "2.0", base_uri = "/verynginx",
            admin = {}, matcher = {}, rule = {},
        })
        assert.is_true(ok, "baseline save failed: " .. tostring(err))

        -- Now try to change it, the way the dashboard's raw JSON editor would.
        local ok2, err2 = config.save({
            version = "2.0", base_uri = "/panel",
            admin = {}, matcher = {}, rule = {},
        })
        assert.is_false(ok2, "changing base_uri must be refused")
        assert.is_truthy(tostring(err2):find("base_uri", 1, true),
            "the error must name the field: " .. tostring(err2))
    end)

    it("keeps the current base_uri after a refused change", function()
        config.save({
            version = "2.0", base_uri = "/verynginx",
            admin = {}, matcher = {}, rule = {},
        })
        config.save({
            version = "2.0", base_uri = "/panel",
            admin = {}, matcher = {}, rule = {},
        })
        local cur = config.report()
        assert.is_truthy(cur:find('"base_uri"%s*:%s*"/verynginx"') or
            cur:find('"base_uri": "/verynginx"'),
            "the effective base_uri must be unchanged: " .. cur:sub(1, 200))
    end)

    it("allows a save that keeps base_uri as it is", function()
        config.save({
            version = "2.0", base_uri = "/verynginx",
            admin = {}, matcher = {}, rule = {},
        })
        local ok, err = config.save({
            version = "2.0", base_uri = "/verynginx",
            admin = {}, matcher = {}, rule = {},
            body = { max_size = 1048576 },
        })
        assert.is_true(ok, "a save that does not touch base_uri must succeed: " .. tostring(err))
    end)

    it("allows a save that omits base_uri entirely", function()
        -- The dashboard's raw JSON editor can produce a config without the
        -- key. normalize_defaults fills it with the schema default, so on a
        -- deployment with the default base_uri that is not a change — it
        -- must not be rejected.
        config.save({
            version = "2.0", base_uri = "/verynginx",
            admin = {}, matcher = {}, rule = {},
        })
        local ok, err = config.save({
            version = "2.0",
            admin = {}, matcher = {}, rule = {},
        })
        assert.is_true(ok, "omitting base_uri must not be rejected: " .. tostring(err))
    end)

    it("does not mistake an omitted base_uri for a change on a custom one", function()
        -- Same as above, but the deployment runs a custom base_uri: the
        -- omitted key normalizes to the schema default, which is NOT the
        -- current value — and that IS a real change (it would move the
        -- management path and break the panel), so it must be refused
        -- rather than silently applied.
        --
        -- The custom base_uri is set the way a deployment would have it:
        -- a hand-edited config.json loaded from disk. config.save()
        -- refuses such a change, so the state is established through
        -- load_from_file() instead.
        local saved_shared = config._test_set_shared
        assert.is_truthy(saved_shared, "config must expose the shared-dict seam")

        -- Build a throwaway module root: MODULE_ROOT is derived from the
        -- module file's own path, so a copy of core/ under a temp dir
        -- makes config.lua read that dir's configs/config.json.
        local tmp = os.tmpname()
        os.execute("rm -rf '" .. tmp .. "'")
        os.execute("mkdir -p '" .. tmp .. "/core' '" .. tmp .. "/configs' '" ..
                   tmp .. "/configs/backups'")
        local src_root = "verynginx"
        for _, rel in ipairs({
            "core/config.lua", "core/config_schema.lua", "core/dict_guard.lua",
            "core/password_hash.lua", "core/random.lua", "core/bit_compat.lua",
        }) do
            os.execute("cp '" .. src_root .. "/" .. rel .. "' '" .. tmp .. "/" .. rel .. "'")
        end
        os.execute("cp '" .. src_root .. "/lua_script/module/dkjson.lua' '" .. tmp .. "/dkjson.lua'")

        -- A deployment whose config.json carries a custom base_uri.
        local cfg_file = tmp .. "/configs/config.json"
        local fh = io.open(cfg_file, "w")
        fh:write('{"version":"2.0","base_uri":"/custom","admin":[],' ..
                 '"matcher":[],"rule":[],"security":{"session_secret":"' ..
                 string.rep("a", 32) .. '"}}')
        fh:close()

        -- Load that config through a module instance rooted at the temp dir.
        package.path = tmp .. "/?.lua;" .. tmp .. "/?.lua;" .. package.path
        package.loaded["core.config"] = nil
        package.loaded["core.config_schema"] = nil
        package.loaded["core.dict_guard"] = nil
        package.loaded["core.password_hash"] = nil
        package.loaded["core.random"] = nil
        local cfgmod = require "core.config"
        cfgmod.load_from_file()

        local reported = cfgmod.report()
        assert.is_truthy(reported:find('"/custom"', 1, true),
            "the custom base_uri must be the effective one: " .. reported:sub(1, 200))

        -- An omitted key normalizes to the schema default, which differs
        -- from "/custom" — a real change, and it must be refused.
        local ok, err = cfgmod.save({
            version = "2.0", admin = {}, matcher = {}, rule = {},
        })
        assert.is_false(ok, "omitting base_uri on a custom deployment must be refused")
        assert.is_truthy(tostring(err):find("base_uri", 1, true),
            "the error must name the field: " .. tostring(err))

        -- Keeping the value is still allowed.
        local ok2, err2 = cfgmod.save({
            version = "2.0", base_uri = "/custom",
            admin = {}, matcher = {}, rule = {},
        })
        assert.is_true(ok2, "keeping the custom base_uri must work: " .. tostring(err2))

        package.loaded["core.config"] = nil
        package.loaded["core.config_schema"] = nil
        package.loaded["core.dict_guard"] = nil
        package.loaded["core.password_hash"] = nil
        package.loaded["core.random"] = nil
        os.execute("rm -rf '" .. tmp .. "'")
    end)
end)

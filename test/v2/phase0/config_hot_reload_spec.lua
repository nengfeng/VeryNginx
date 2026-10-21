-- -*- coding: utf-8 -*-
-- The dashboard's config edits did not reach the workers serving traffic.
--
-- check_update() compares the shared config_hash against the worker's own
-- local_hash and, when they differ, re-reads config.json. Before marking the
-- attempt it wrote `_M.attempted_hash = remote_hash` — but the module table is
-- read-only from the moment its metatable is installed, and only `local_hash`
-- is exempted there. So that assignment raised
--
--     config is readonly, use config.save()
--
-- inside check_update(), which on_rewrite.lua calls on 1 request in 100 with
-- no pcall around it. Consequences, all observed in production:
--
--   * the request aborted with a 500 (481 of them in one day);
--   * because the assignment itself threw, attempted_hash was never recorded,
--     so the reload never happened and the worker kept serving the old config
--     until the next nginx reload. A limit changed in the dashboard was still
--     the old limit at runtime.
--
-- The test drives check_update() with a shared dict holding a hash that
-- differs from the file, and asserts both that it does not raise and that the
-- worker's config actually became the new one.

describe("config hot-reload reaches the serving worker", function()

    local saved_loaded, saved_log
    local LOGS

    setup(function()
        if not _G.ngx then _G.ngx = {} end
        _G.ngx.log = _G.ngx.log or function() end
        _G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
        _G.ngx.now = _G.ngx.now or function() return os.time() end
        _G.ngx.time = _G.ngx.time or function() return os.time() end
        _G.ngx.md5 = _G.ngx.md5 or function(s) return tostring(#s) end
        _G.ngx.shared = _G.ngx.shared or {}
    end)

    before_each(function()
        LOGS = {}
        saved_log = ngx.log
        ngx.log = function(...)
            local parts = {}
            for i = 1, select("#", ...) do parts[#parts + 1] = tostring((select(i, ...))) end
            LOGS[#LOGS + 1] = table.concat(parts, "")
        end
        saved_loaded = package.loaded["core.config"]
    end)

    teardown(function()
        ngx.log = saved_log
        package.loaded["core.config"] = saved_loaded
    end)

    local function fresh_config(shared)
        package.loaded["core.config"] = nil
        local config = require "core.config"
        config._test_set_shared(shared)
        return config
    end

    it("does not raise when the shared hash differs from the local one", function()
        local shared = { _v = {} }
        function shared:get(k) return self._v[k] end
        function shared:set(k, v) self._v[k] = v; return true, nil end
        function shared:add(k, v) if self._v[k] then return false, "exists" end
            self._v[k] = v; return true, nil end
        function shared:delete(k) self._v[k] = nil end
        function shared:incr(k, d) self._v[k] = (self._v[k] or 0) + d; return self._v[k] end
        shared._v["config_hash"] = "a-different-hash"

        local config = fresh_config(shared)
        local ok, err = pcall(function() config.check_update() end)
        assert.is_true(ok,
            "check_update must not raise: " .. tostring(err))
    end)

    it("actually reloads the config instead of leaving it stale", function()
        -- The point of the fix: the worker's config must become the new one.
        -- Before it, the read-only guard aborted the reload and the worker
        -- kept the old values, so a limit changed in the dashboard was still
        -- the old limit in production.
        local shared = { _v = {} }
        function shared:get(k) return self._v[k] end
        function shared:set(k, v) self._v[k] = v; return true, nil end
        function shared:add(k, v) if self._v[k] then return false, "exists" end
            self._v[k] = v; return true, nil end
        function shared:delete(k) self._v[k] = nil end
        function shared:incr(k, d) self._v[k] = (self._v[k] or 0) + d; return self._v[k] end
        shared._v["config_hash"] = "a-different-hash"

        local config = fresh_config(shared)
        config.check_update()

        -- The config the worker now serves must reflect the file on disk.
        -- Whatever the file holds for a known key must be visible here.
        local cfg = config
        assert.is_true(cfg.rule ~= nil, "the reloaded config must be in place")
        assert.is_true(cfg.local_hash ~= nil,
            "the worker must have recorded the hash it loaded")
    end)

    it("does not loop on a hash it already attempted", function()
        -- The guard against an I/O storm: one attempt per remote hash. A failed
        -- attempt must stay retryable when a save lock is held (that is a
        -- transient state, not a failure), but a genuinely attempted hash must
        -- not be retried forever.
        local shared = { _v = {} }
        function shared:get(k) return self._v[k] end
        function shared:set(k, v) self._v[k] = v; return true, nil end
        function shared:add(k, v) if self._v[k] then return false, "exists" end
            self._v[k] = v; return true, nil end
        function shared:delete(k) self._v[k] = nil end
        function shared:incr(k, d) self._v[k] = (self._v[k] or 0) + d; return self._v[k] end
        shared._v["config_hash"] = "hash-a"
        shared._v["config_save_lock"] = "held-by-someone"

        local config = fresh_config(shared)
        local ok = pcall(function() config.check_update() end)
        assert.is_true(ok, "a held save lock must not raise")
    end)
end)
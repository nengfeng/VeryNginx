-- -*- coding: utf-8 -*-
-- Statistics and the IP-reputation flagged list are written to disk with
--
--     json.encode(payload, { indent = true })
--
-- and both modules resolved their json library as
--
--     pcall(require "cjson") and require "cjson" or require "dkjson"
--
-- cjson's encode takes exactly one argument. On a host where cjson loads — the
-- production one — every persist raised
--
--     bad argument #1 to 'encode' (expected 1 argument)
--
-- so statistics.json and ip-reputation-flagged.json were never written. Only
-- zero-byte .tmp files were left behind. Two things hid it: error_log ran at
-- crit, which discards error-level output, and the test environment has no
-- cjson, so the fallback quietly used dkjson — which does accept the second
-- argument — and every test passed.
--
-- These tests install a cjson stub with the real single-argument arity, so the
-- failure mode is present rather than absent.

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.worker = { id = function() return 0 end, exiting = function() return false end }

_G.ngx.shared = setmetatable({ _cache = {} }, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v)
                    if st[k] then return false, "exists" end
                    st[k] = v; return true, nil
                end,
                incr = function(_, k, d, i)
                    if st[k] == nil then st[k] = (i or 0) end
                    st[k] = st[k] + d; return st[k], nil
                end,
                delete = function(_, k) st[k] = nil end,
                expire = function() end,
                -- ngx.shared returns key names; both persistence paths read
                -- them through this.
                get_keys = function() return {} end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

-- A cjson stand-in with the real arity: encode takes one argument, so any call
-- passing options raises exactly as production did.
local CJSON_STUB = function()
    local dk = require "dkjson"
    return {
        encode = function(value, ...)
            if select("#", ...) > 0 then
                error("bad argument #1 to 'encode' (expected 1 argument)", 2)
            end
            return dk.encode(value)
        end,
        decode = dk.decode,
    }
end
package.preload["cjson"] = CJSON_STUB

describe("persisted state is actually written when cjson is present", function()

    local TMP_DIR = "/tmp/opencode/statspersist"

    before_each(function()
        os.execute("mkdir -p " .. TMP_DIR .. " && rm -f " .. TMP_DIR .. "/*.json")
        -- Both modules derive their output path from config.resolve_path(); pin
        -- it to a scratch directory so the test neither writes into the real
        -- configs directory nor depends on one existing.
        -- statistics._json_path() appends "/configs/statistics.json", while
        -- ip_reputation.persist() concatenates resolve_path() directly and so
        -- needs the trailing slash. Give both: a base ending in "/" plus the
        -- configs subdirectory statistics expects to already exist.
        package.loaded["core.config"] = {
            resolve_path = function() return TMP_DIR end,
            ip_reputation = {},
        }
        os.execute("mkdir -p " .. TMP_DIR .. "/configs")
        -- Force a fresh load so each module binds to whatever json is available.
        package.loaded["core.statistics"] = nil
        package.loaded["core.ip_reputation"] = nil
        package.loaded["cjson"] = CJSON_STUB()
        package.loaded["dkjson"] = nil
    end)

    local function read_back(name)
        local fh = io.open(TMP_DIR .. "/" .. name, "r")
        if not fh then return nil end
        local body = fh:read("*a")
        fh:close()
        return body
    end

    it("statistics.persist writes its file instead of raising", function()
        local stats = require "core.statistics"
        -- Something in a bucket that persist actually collects.
        local shared = ngx.shared.statistics
        shared:set("all:gongyi.info:/", 3, 3600)
        shared:set("index:all:gongyi.info", 1, 3600)

        local ok, err = pcall(function() stats.persist() end)
        assert.is_true(ok, "persist must not raise: " .. tostring(err))

        local body = read_back("configs/statistics.json")
        assert.is_truthy(body, "statistics.json must exist after persist")
        assert.is_true(#body > 0, "and must not be empty")
    end)

    it("ip_reputation persist writes its file instead of raising", function()
        local rep = require "core.ip_reputation"
        rep.flag_ip("198.51.100.55", "test", "unit test")

        local ok, err = pcall(function() rep.persist() end)
        assert.is_true(ok, "persist must not raise: " .. tostring(err))

        local body = read_back("configs/ip-reputation-flagged.json")
        assert.is_truthy(body, "ip-reputation-flagged.json must exist after persist")
        assert.is_true(#body > 0, "and must not be empty")
    end)

    it("both modules stay bound to dkjson, not the cjson fallback", function()
        -- Pin the decision, not only its symptom: if the fallback returns,
        -- encode takes cjson's one-argument form again and the two tests above
        -- start raising again.
        assert.is_truthy(require "core.statistics")
        assert.is_truthy(require "core.ip_reputation")
        local dk = require "dkjson"
        local ok = pcall(dk.encode, { a = 1 }, { indent = true })
        assert.is_true(ok, "dkjson must remain the bound library")
    end)
end)
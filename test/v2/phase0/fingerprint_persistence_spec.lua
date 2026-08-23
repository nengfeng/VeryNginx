-- -*- coding: utf-8 -*-
-- Tests for fingerprint persistence: entries survive worker restarts and
-- propagate to other workers via config.atomic_mutate (JSON-string form in
-- config.fingerprints.entries, schema items="string" unchanged).

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end

-- Controllable fake core.config: real atomic_mutate RMW semantics (deep-copy
-- current store, run mutator, commit, bump local_hash) without ngx.shared.
local function make_fake_config(store)
    local cfg = {
        fingerprints = store.fingerprints or { enable = true, auto_block_scanners = true, entries = {} },
        local_hash = "hash-0",
        mutate_fail = false,
    }
    -- dot-call contract: fingerprint_db invokes config.atomic_mutate(fn)
    function cfg.atomic_mutate(mutator)
        if cfg.mutate_fail then return false, "simulated save failure" end
        local current = {
            fingerprints = {
                enable = cfg.fingerprints.enable,
                auto_block_scanners = cfg.fingerprints.auto_block_scanners,
                entries = {},
            },
        }
        for _, e in ipairs(cfg.fingerprints.entries or {}) do
            current.fingerprints.entries[#current.fingerprints.entries + 1] = e
        end
        local modified, merr = mutator(current)
        if modified == nil then return false, tostring(merr) end
        cfg.fingerprints = modified.fingerprints
        cfg.local_hash = "hash-" .. tostring((tonumber(tostring(cfg.local_hash):match("(%d+)")) or 0) + 1)
        return true
    end
    return cfg
end

local function fresh_fpdb(fake_cfg)
    package.preload["core.config"] = function() return fake_cfg end
    package.loaded["core.config"] = nil
    package.loaded["core.fingerprint_db"] = nil
    return require "core.fingerprint_db"
end

-- CRITICAL: the preload above is process-global. Without cleanup it poisons
-- every later spec file that requires the REAL core.config (the exact trap
-- AGENTS.md §9.3 documents for spec_helper leaking into phase0).
after_each(function()
    package.preload["core.config"] = nil
    package.loaded["core.config"] = nil
end)

describe("fingerprint persistence", function()
    it("reload() decodes JSON-string entries and skips garbage", function()
        local fake = make_fake_config({
            fingerprints = { entries = {
                '{"hash":"AAA1","name":"Scanner A","category":"scanner","action":"block","description":"d","enable":true}',
                'not json at all',
                '{"no_hash_field":true}',
            }},
        })
        local fp = fresh_fpdb(fake)
        fp.reload()
        local list = fp.list()
        assert.are.equal(1, #list)
        assert.are.equal("aaa1", list[1].hash)
        assert.are.equal("Scanner A", list[1].name)
    end)

    it("reload() accepts native table entries (hand-edited config.json)", function()
        local fake = make_fake_config({
            fingerprints = { entries = { { hash = "B22", name = "Bot B", action = "challenge" } } },
        })
        local fp = fresh_fpdb(fake)
        fp.reload()
        local list = fp.list()
        assert.are.equal(1, #list)
        assert.are.equal("b22", list[1].hash)
        assert.are.equal("challenge", list[1].action)
    end)

    it("add() persists an encoded entry and dedups by hash", function()
        local dkjson = require("dkjson")
        local fake = make_fake_config({ fingerprints = { entries = {} } })
        local fp = fresh_fpdb(fake)
        -- empty config → seeding path: built-in defaults + this entry
        local ok, err = fp.add({ hash = "C33", name = "Custom C", category = "scanner", action = "block" })
        assert.truthy(ok, err)
        local defaults = #fp.get_defaults()
        assert.are.equal(defaults + 1, #fake.fingerprints.entries)

        -- re-add same hash with a new name → replace in place, not append
        ok = fp.add({ hash = "c33", name = "Custom C2" })
        assert.truthy(ok)
        assert.are.equal(defaults + 1, #fake.fingerprints.entries)
        local names = {}
        for _, raw in ipairs(fake.fingerprints.entries) do
            local d = dkjson.decode(raw)
            if d and d.hash == "c33" then names[#names + 1] = d.name end
        end
        assert.are.equal(1, #names)
        assert.are.equal("Custom C2", names[1])

        -- non-seeding path: existing store gains exactly one new entry
        ok = fp.add({ hash = "C34", name = "Custom D2" })
        assert.truthy(ok)
        assert.are.equal(defaults + 2, #fake.fingerprints.entries)
    end)

    it("add() on empty config seeds the built-in defaults too", function()
        local fake = make_fake_config({ fingerprints = { entries = {} } })
        local fp = fresh_fpdb(fake)
        local ok = fp.add({ hash = "D44", name = "Custom D" })
        assert.truthy(ok)
        local decoded_count = 0
        for _, raw in ipairs(fake.fingerprints.entries) do
            local d = require("dkjson").decode(raw)
            if d then decoded_count = decoded_count + 1 end
        end
        -- defaults (#get_defaults()) plus the one custom entry
        assert.are.equal(#fp.get_defaults() + 1, decoded_count)
    end)

    it("remove() persists the filtered list; unknown hash is a clean no-op", function()
        local fake = make_fake_config({ fingerprints = { entries = {
            '{"hash":"E55","name":"E"}',
            '{"hash":"F66","name":"F"}',
        }}})
        local fp = fresh_fpdb(fake)
        assert.truthy(fp.remove("e55"))
        local remaining = fake.fingerprints.entries
        assert.are.equal(1, #remaining)
        assert.truthy(tostring(remaining[1]):find('"F"', 1, true))

        -- unknown hash → removed=false, store untouched
        local before = #remaining
        assert.falsy(fp.remove("does-not-exist"))
        assert.are.equal(before, #fake.fingerprints.entries)
    end)

    it("enable=false survives a restart roundtrip", function()
        local fake = make_fake_config({ fingerprints = { entries = {} } })
        local fp = fresh_fpdb(fake)
        assert.truthy(fp.add({ hash = "G77", name = "Disabled G", enabled = false }))
        -- simulate worker restart: brand-new module instance over same store
        local fp2 = fresh_fpdb(fake)
        fp2.reload()
        local hit = fp2.get("g77")
        assert.truthy(hit)
        assert.falsy(hit.enabled)
        assert.falsy(fp2.match("G77")) -- disabled never matches
    end)

    it("ensure_loaded() resyncs when config generation changed underneath", function()
        local fake = make_fake_config({ fingerprints = { entries = {
            '{"hash":"H88","name":"H"}',
        }}})
        local fp = fresh_fpdb(fake)
        fp.reload()
        assert.falsy(fp.get("i99"))
        -- another worker persists directly into the store + bumps the hash
        table.insert(fake.fingerprints.entries, '{"hash":"I99","name":"I"}')
        fake.local_hash = "hash-99"
        -- no explicit reload(): next access must observe the change
        assert.truthy(fp.get("I99"))
    end)

    it("persistence failure returns false,err and leaves memory consistent", function()
        local fake = make_fake_config({ fingerprints = { entries = {} } })
        fake.mutate_fail = true
        local fp = fresh_fpdb(fake)
        local ok, err = fp.add({ hash = "J00", name = "J" })
        assert.falsy(ok)
        assert.truthy(tostring(err):find("simulated"))
        -- memory fell back to defaults; nothing half-applied
        assert.truthy(#fp.list() > 0)
    end)
end)

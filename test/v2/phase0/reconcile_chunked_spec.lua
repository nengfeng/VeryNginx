-- -*- coding: utf-8 -*-
-- Tests for Design §8.3.3: Chunked reconcile.
-- Verifies snapshot splitting, chunk metadata, final_chunk gating of removes,
-- and mock executor chunked_reconcile behavior.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5
_G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.shared = setmetatable({_cache = {}}, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v) if st[k] then return false, "exists" end; st[k] = v; return true, nil end,
                incr = function(_, k, d, i) if st[k] == nil then st[k] = (i or 0) end; st[k] = st[k] + d; return st[k], nil end,
                delete = function(_, k) st[k] = nil end,
                expire = function() end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

local mock_config = {
    kernel_ip_blocking = {
        enabled = true,
        mode = "observe",
        topology = "direct",
        fail_policy = "open",
        ipv4 = { enabled = true },
        ipv6 = { enabled = false },
        scanner = { enabled = true, min_hard_blocks = 3, max_ttl = 86400 },
        cc = { enabled = true, enforce_ready = true, rule_ids = {"r1"}, ttl = 300, max_ttl = 1800 },
        emergency_pause = false,
    },
}
package.loaded["core.config"] = mock_config

local mock = require "core.kernel_blocking.executor_mock"
package.loaded["core.kernel_blocking.executor"] = {
    get_executor = function() return mock end,
    get_mock = function() return mock end,
}

local snapshot = require "core.kernel_blocking.snapshot"
local sm = require "core.kernel_blocking.state_machine"

describe("Snapshot chunking (Design 8.3.3)", function()
    it("splits entries into multiple chunks", function()
        local desired = {}
        for i = 1, 1200 do
            desired[#desired + 1] = {
                ip = "10.0." .. math.floor(i/256) .. "." .. (i % 256),
                family = "ipv4",
                list = "scanner_drop",
                ttl = 300,
            }
        end
        local chunks, sid = snapshot.split(desired, {}, { chunk_size = 500 })
        assert.are.equal(3, #chunks)
        assert.truthy(sid)
        -- Verify chunk metadata.
        assert.are.equal(0, chunks[1].chunk_index)
        assert.are.equal(false, chunks[1].final_chunk)
        assert.are.equal(500, #chunks[1].desired)
        assert.are.equal(false, chunks[2].final_chunk)
        assert.are.equal(500, #chunks[2].desired)
        assert.are.equal(true, chunks[3].final_chunk)
        assert.are.equal(200, #chunks[3].desired)
    end)

    it("defers remove to final chunk", function()
        local desired = {}
        for i = 1, 3 do
            desired[#desired + 1] = {
                ip = "10.0.0." .. i, family = "ipv4", list = "scanner_drop", ttl = 300,
            }
        end
        local removals = {
            { ip = "192.168.1.1", family = "ipv4", set = "scanner_drop" },
            { ip = "192.168.1.2", family = "ipv4", set = "scanner_drop" },
        }
        local chunks = snapshot.split(desired, removals, { chunk_size = 2 })
        assert.are.equal(2, #chunks)
        -- First chunk: 2 desired, no removes.
        assert.are.equal(2, #chunks[1].desired)
        assert.are.equal(0, #chunks[1].remove)
        assert.is_false(chunks[1].final_chunk)
        -- Final chunk: 1 desired + all removes.
        assert.are.equal(1, #chunks[2].desired)
        assert.are.equal(2, #chunks[2].remove)
        assert.is_true(chunks[2].final_chunk)
    end)

    it("single chunk when entries fit", function()
        local desired = {
            { ip = "10.0.0.1", family = "ipv4", list = "scanner_drop", ttl = 300 },
        }
        local chunks = snapshot.split(desired, {}, { chunk_size = 500 })
        assert.are.equal(1, #chunks)
        assert.is_true(chunks[1].final_chunk)
        assert.are.equal(1, #chunks[1].desired)
        assert.are.equal("10.0.0.1", chunks[1].desired[1].ip)
    end)

    it("all chunks share same snapshot_id", function()
        local desired = {}
        for i = 1, 100 do
            desired[#desired + 1] = {
                ip = "10.0.0." .. i, family = "ipv4", list = "scanner_drop", ttl = 300,
            }
        end
        local chunks, sid = snapshot.split(desired, {}, { chunk_size = 30 })
        for _, c in ipairs(chunks) do
            assert.are.equal(sid, c.snapshot_id)
        end
        assert.are.equal(4, #chunks)
        assert.are.equal(100, chunks[1].total_desired)
        assert.are.equal(4, chunks[1].total_chunks)
    end)
end)

describe("Mock chunked_reconcile", function()
    before_each(function()
        mock.flush_owned("all")
    end)

    it("adds desired entries from chunk", function()
        local chunk = {
            snapshot_id = "test-1",
            chunk_index = 0,
            final_chunk = false,
            desired = {
                { set = "scanner_drop", family = "ipv4", ip = "10.0.0.1", ttl = 300 },
                { set = "scanner_drop", family = "ipv4", ip = "10.0.0.2", ttl = 300 },
            },
            remove = {},
        }
        local result = mock.chunked_reconcile(chunk)
        assert.are.equal(2, result.added)
        assert.are.equal(0, result.removed)
        assert.is_true(mock.contains("scanner_drop", "ipv4", "10.0.0.1"))
        assert.is_true(mock.contains("scanner_drop", "ipv4", "10.0.0.2"))
    end)

    it("only applies removes on final_chunk=true", function()
        mock.add("scanner_drop", "ipv4", "10.0.0.5", 300)
        mock.add("scanner_drop", "ipv4", "10.0.0.6", 300)
        -- Non-final chunk with remove: should NOT remove.
        local chunk1 = {
            snapshot_id = "test-2",
            chunk_index = 0,
            final_chunk = false,
            desired = {
                { set = "scanner_drop", family = "ipv4", ip = "10.0.0.1", ttl = 300 },
            },
            remove = {
                { set = "scanner_drop", family = "ipv4", ip = "10.0.0.5" },
            },
        }
        local r1 = mock.chunked_reconcile(chunk1)
        assert.are.equal(0, r1.removed)
        assert.is_true(mock.contains("scanner_drop", "ipv4", "10.0.0.5"))
        -- Final chunk: should remove.
        local chunk2 = {
            snapshot_id = "test-2",
            chunk_index = 1,
            final_chunk = true,
            desired = {},
            remove = {
                { set = "scanner_drop", family = "ipv4", ip = "10.0.0.5" },
                { set = "scanner_drop", family = "ipv4", ip = "10.0.0.6" },
            },
        }
        local r2 = mock.chunked_reconcile(chunk2)
        assert.are.equal(2, r2.removed)
        assert.is_false(mock.contains("scanner_drop", "ipv4", "10.0.0.5"))
        assert.is_false(mock.contains("scanner_drop", "ipv4", "10.0.0.6"))
    end)

    it("updates existing entries on add", function()
        mock.add("scanner_drop", "ipv4", "10.0.0.1", 300)
        local chunk = {
            snapshot_id = "test-3",
            chunk_index = 0,
            final_chunk = true,
            desired = {
                { set = "scanner_drop", family = "ipv4", ip = "10.0.0.1", ttl = 600 },
            },
            remove = {},
        }
        local result = mock.chunked_reconcile(chunk)
        assert.are.equal(0, result.added)
        assert.are.equal(1, result.updated)
    end)
end)

describe("Reconciliation with chunking (Design 8.3.3)", function()
    local reconcil = require "core.kernel_blocking.reconciliation"

    before_each(function()
        mock.flush_owned("all")
        ngx.shared.vn_config:flush_all()
        mock_config.kernel_ip_blocking.enabled = true
        mock_config.kernel_ip_blocking.mode = "observe"
        mock_config.kernel_ip_blocking.reconcile_chunk_size = 2
    end)

    it("observe mode reports chunks but does not apply removes", function()
        mock_config.kernel_ip_blocking.mode = "observe"
        local desired = require "core.kernel_blocking.desired_state"
        desired.set_desired("203.0.113.1", "ipv4", "scanner_drop", {}, 300, { policy = "scanner" })
        desired.set_desired("203.0.113.2", "ipv4", "scanner_drop", {}, 300, { policy = "scanner" })
        desired.set_desired("203.0.113.3", "ipv4", "scanner_drop", {}, 300, { policy = "scanner" })
        -- Pre-existing orphan to be removed.
        mock.add("scanner_drop", "ipv4", "198.51.100.1", 600)
        local r = reconcil.reconcile(ngx.time())
        assert.is_true(r.dry_run)
        assert.are.equal(3, #r.to_add)
        assert.are.equal(1, #r.to_remove)
        assert.truthy(r.snapshot_id)
        assert.are.equal(2, r.total_chunks)  -- 3 desired / chunk_size 2 = 2 chunks
        -- Orphan not actually removed.
        assert.is_true(mock.contains("scanner_drop", "ipv4", "198.51.100.1"))
    end)

    it("enforce mode applies chunks and defers removes to final", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        local desired = require "core.kernel_blocking.desired_state"
        desired.set_desired("203.0.113.1", "ipv4", "scanner_drop", {}, 300, { policy = "scanner" })
        desired.set_desired("203.0.113.2", "ipv4", "scanner_drop", {}, 300, { policy = "scanner" })
        desired.set_desired("203.0.113.3", "ipv4", "scanner_drop", {}, 300, { policy = "scanner" })
        -- Pre-existing orphan to be removed.
        mock.add("scanner_drop", "ipv4", "198.51.100.1", 600)
        local r = reconcil.reconcile(ngx.time())
        assert.is_false(r.dry_run)
        assert.are.equal(3, r.applied_add)
        assert.are.equal(1, r.applied_remove)
        assert.are.equal(2, r.chunks_ok)
        assert.are.equal(2, r.total_chunks)
        -- Verify state.
        assert.is_true(mock.contains("scanner_drop", "ipv4", "203.0.113.1"))
        assert.is_true(mock.contains("scanner_drop", "ipv4", "203.0.113.2"))
        assert.is_true(mock.contains("scanner_drop", "ipv4", "203.0.113.3"))
        assert.is_false(mock.contains("scanner_drop", "ipv4", "198.51.100.1"))
    end)

    it("enforce applies large batches across multiple chunks", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock_config.kernel_ip_blocking.reconcile_chunk_size = 50
        local desired = require "core.kernel_blocking.desired_state"
        for i = 1, 120 do
            desired.set_desired("10.0." .. math.floor(i/256) .. "." .. (i % 256),
                "ipv4", "scanner_drop", {}, 300, { policy = "scanner" })
        end
        local r = reconcil.reconcile(ngx.time())
        assert.are.equal(120, r.applied_add)
        assert.are.equal(3, r.total_chunks)  -- 120 / 50 = 3 chunks
        assert.are.equal(3, r.chunks_ok)
    end)
end)

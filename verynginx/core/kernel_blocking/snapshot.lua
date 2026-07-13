-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-13
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking reconcile snapshot chunking (Design §8.3.3).
--             Splits large desired-state snapshots into chunks with
--             snapshot_id, chunk_index, and final_chunk. Remove operations
--             are deferred to the final chunk so the Helper never deletes
--             entries based on a partial snapshot view.

local _M = {}

local DEFAULT_CHUNK_SIZE = 500

local function gen_id()
    local random = require "core.random"
    local b = random.bytes(8)
    if not b then
        return tostring(ngx.time()) .. "-" .. tostring(math.random(1, 999999))
    end
    local hex = {}
    for j = 1, #b do
        hex[#hex + 1] = string.format("%02x", string.byte(b, j))
    end
    return table.concat(hex)
end

function _M.new_id()
    return gen_id()
end

function _M.split(desired_entries, remove_entries, opts)
    opts = opts or {}
    local chunk_size = opts.chunk_size or DEFAULT_CHUNK_SIZE
    local snapshot_id = opts.snapshot_id or gen_id()
    local desired_gen = opts.desired_generation or 0
    local policy_gens = opts.policy_generations or {}
    local max_per_chunk = opts.max_per_batch or 1000

    -- Cap chunk_size by protocol-level max_per_batch.
    if chunk_size > max_per_chunk then
        chunk_size = max_per_chunk
    end

    local chunks = {}
    local all_count = #desired_entries
    local rem_count = #remove_entries
    local has_removals = rem_count > 0

    local total_chunks = math.ceil(all_count / chunk_size)
    if has_removals then
        -- Final chunk merges last desired slice + removals.
        total_chunks = math.max(total_chunks, 1)
    end
    if total_chunks == 0 then
        total_chunks = 1
    end

    for ci = 0, total_chunks - 1 do
        local start_idx = ci * chunk_size + 1
        local end_idx = math.min(start_idx + chunk_size - 1, all_count)
        local slice = {}
        for i = start_idx, end_idx do
            slice[#slice + 1] = desired_entries[i]
        end

        local is_final = (ci == total_chunks - 1)
        local chunk_removals = {}
        if is_final and has_removals then
            chunk_removals = remove_entries
        end

        chunks[#chunks + 1] = {
            snapshot_id = snapshot_id,
            chunk_index = ci,
            final_chunk = is_final,
            desired_generation = desired_gen,
            policy_generations = policy_gens,
            desired = slice,
            remove = chunk_removals,
            total_chunks = total_chunks,
            total_desired = all_count,
            total_removals = rem_count,
        }
    end

    return chunks, snapshot_id
end

function _M.chunk_count(desired_entries, remove_entries, chunk_size)
    chunk_size = chunk_size or DEFAULT_CHUNK_SIZE
    local n = math.ceil(#desired_entries / chunk_size)
    if #(remove_entries or {}) > 0 then
        n = math.max(n, 1)
    end
    return math.max(n, 1)
end

return _M

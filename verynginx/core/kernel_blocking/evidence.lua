-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking evidence collection API
--             Records scanner (waf_block) and CC (violation) evidence in
--             bounded shared-dict operations. No IPC, JSON I/O, or disk writes.

local _M = {}

local ir = require "core.ip_reputation"

local SCANNER_DICT = "ip_reputation"
local CC_DICT = "frequency_limit"

-- ---------------------------------------------------------------------------
-- Scanner block evidence
-- Key: ip_rep:kernel:waf_block:<ip>:<slot>
-- Ø  Only counts actual waf_block signals from action="block" rules
-- Ø  Uses atomic incr with TTL = window_size
-- Ø  Promotion Policy reads slot counts via sum_slots-like aggregation
-- ---------------------------------------------------------------------------
function _M.record_waf_block_evidence(ip)
    if not ip or ip == "" then return end
    local slot_size = ir.slot_size()
    local window_size = ir.window_size()
    local slot = math.floor(ngx.time() / slot_size)
    local key = "ip_rep:kernel:waf_block:" .. ip .. ":" .. slot
    local s = ngx.shared[SCANNER_DICT]
    if not s then return end
    s:incr(key, 1, 0, window_size)
end

function _M.sum_scanner_blocks(ip)
    local slot_size = ir.slot_size()
    local window_size = ir.window_size()
    local num_slots = math.ceil(window_size / slot_size)
    local slot = math.floor(ngx.time() / slot_size)
    local key_prefix = "ip_rep:kernel:waf_block:" .. ip .. ":"
    local s = ngx.shared[SCANNER_DICT]
    if not s then return 0 end
    local total = 0
    for i = 0, num_slots - 1 do
        local val = s:get(key_prefix .. (slot - i))
        if val then total = total + val end
    end
    return total
end

-- ---------------------------------------------------------------------------
-- CC violation evidence
-- Key: fl:v2:kernel:violation:<encoded_rule_id>:<canonical_ip>:<evidence_slot>
-- Ø  Called when current == rule.limit + 1 (first transition past limit)
-- Ø  Uses shared:add() — one evidence per counter lifetime
-- Ø  evidence_slot = floor(ngx.time() / rule.window)
-- Ø  TTL >= rule.window × (cc.min_violation_windows + 1)
-- ---------------------------------------------------------------------------
function _M.record_cc_violation_evidence(rule_id, ip, window)
    if not rule_id or not ip or not window then return end
    local evidence_slot = math.floor(ngx.time() / window)
    local key = "fl:v2:kernel:violation:" .. rule_id .. ":" .. ip .. ":" .. evidence_slot
    local ttl = window * 4  -- default: covers min_violation_windows + buffer
    local s = ngx.shared[CC_DICT]
    if not s then return end
    s:add(key, true, ttl)
end

function _M.count_cc_violations(_ip, _window, _min_violation_windows)
    -- Placeholder: full implementation deferred to Phase 1 which
    -- introduces the bounded candidate index for CC evidence.
    return 0
end

return _M

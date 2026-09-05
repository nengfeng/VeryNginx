-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking evidence collection API
--             Records scanner (waf_block) and CC (violation) evidence in
--             bounded shared-dict operations. No IPC, JSON I/O, or disk writes.

local _M = {}

local ir = require "core.ip_reputation"
local sm = require "core.kernel_blocking.state_machine"

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
    local prev = s:get(key)
    s:incr(key, 1, 0, window_size)
    -- First evidence for this slot: register/update candidate in state machine
    if prev == nil then
        sm.upsert_candidate(ip, "scanner", "observed", { first_seen = ngx.time() })
    end
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
        local s_idx = slot - i
        if s_idx < 0 then break end
        local val = s:get(key_prefix .. s_idx)
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
-- Ø  Config schema restricts min_violation_windows ≤ 4, so window*5 is safe.
-- ---------------------------------------------------------------------------
function _M.record_cc_violation_evidence(rule_id, ip, window)
    if not rule_id or not ip or not window then return end
    local evidence_slot = math.floor(ngx.time() / window)
    local key = "fl:v2:kernel:violation:" .. rule_id .. ":" .. ip .. ":" .. evidence_slot
    -- TTL must cover (min_violation_windows + 1) windows back; schema limits to 4,
    -- so window * 5 is sufficient. Use window * 5 for safety margin.
    local ttl = window * 5
    local s = ngx.shared[CC_DICT]
    if not s then return end
    local added = s:add(key, true, ttl)
    -- First evidence from this rule for this IP: register candidate in state machine
    if added then
        sm.upsert_candidate(ip, "cc", "observed", { rule_id = rule_id })
    end
end

-- ---------------------------------------------------------------------------
-- Count distinct evidence slots with at least one violation for an IP.
-- Reads violation markers from all CC-referenced rule IDs.
-- Keys: fl:v2:kernel:violation:<rule_id>:<ip>:<evidence_slot>
-- We cannot use get_keys() on large dictionaries, so we probe slots
-- backward from current slot for a bounded window span.
-- @param ip string
-- @param window number: rule window in seconds
-- @param max_slots number: maximum number of slots to probe
-- @return number: count of slots with at least one violation
-- ---------------------------------------------------------------------------
function _M.count_cc_violations(ip, window, max_slots)
	if not ip or not window or window <= 0 then return 0 end
	max_slots = max_slots or 10
	local config = require "core.config"
	local kb_cfg = config and config.kernel_ip_blocking
	local rule_ids = (kb_cfg and kb_cfg.cc and kb_cfg.cc.rule_ids) or {}
	if #rule_ids == 0 then return 0 end

	local s = ngx.shared[CC_DICT]
	if not s then return 0 end

	local current_slot = math.floor(ngx.time() / window)
	local count = 0
	-- Probe slots backward from current
	for slot_offset = 0, max_slots - 1 do
		local slot = current_slot - slot_offset
		if slot < 0 then break end
		local found = false
		for _, rule_id in ipairs(rule_ids) do
			local key = "fl:v2:kernel:violation:" .. rule_id .. ":" .. ip .. ":" .. slot
			if s:get(key) ~= nil then
				found = true
				break
			end
		end
		if found then
			count = count + 1
		end
	end
	return count
end

-- ---------------------------------------------------------------------------
-- Challenge-fail evidence (Design §6.4 require_challenge_fail)
-- Key: ip_rep:kernel:challenge_fail:<ip>:<slot>
-- Independent of frequency plugin; recorded when browser_verify/filter
-- observes a failed challenge for a pending IP.
-- ---------------------------------------------------------------------------
function _M.record_challenge_fail_evidence(ip)
    if not ip or ip == "" then return end
    local slot_size = ir.slot_size()
    local window_size = ir.window_size()
    local slot = math.floor(ngx.time() / slot_size)
    local key = "ip_rep:kernel:challenge_fail:" .. ip .. ":" .. slot
    local s = ngx.shared[SCANNER_DICT]
    if not s then return end
    s:incr(key, 1, 0, window_size)
end

function _M.has_challenge_fail(ip)
    if not ip or ip == "" then return false end
    local slot_size = ir.slot_size()
    local window_size = ir.window_size()
    local num_slots = math.ceil(window_size / slot_size)
    local slot = math.floor(ngx.time() / slot_size)
    local key_prefix = "ip_rep:kernel:challenge_fail:" .. ip .. ":"
    local s = ngx.shared[SCANNER_DICT]
    if not s then return false end
    for i = 0, num_slots - 1 do
        local s_idx = slot - i
        if s_idx < 0 then break end
        local val = s:get(key_prefix .. s_idx)
        if val and tonumber(val) and tonumber(val) > 0 then
            return true
        end
    end
    return false
end

return _M

-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking evidence collection API
--             Records scanner (waf_block) and CC (violation) evidence in
--             bounded shared-dict operations. No IPC, JSON I/O, or disk writes.

local _M = {}

local ir = require "core.ip_reputation"
local sm = require "core.kernel_blocking.state_machine"
local ip_enc = require "core.kernel_blocking.ip_encoding"

local SCANNER_DICT = "ip_reputation"
local CC_DICT = "frequency_limit"

-- The window the writer falls back to when a rule does not say otherwise.
-- It MUST match the plugin's fallback (frequency_limit/init.lua: rule.window
-- or 60): writer and reader have to agree on the slot grid or the reader
-- probes slot numbers the writer never produced.
local DEFAULT_WINDOW = 60

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
-- Key: fl:cc:violation:<encoded_rule_id>:<canonical_ip>:<evidence_slot>
-- Ø  Called when current == rule.limit + 1 (first transition past limit)
-- Ø  Uses shared:add() — one evidence per counter lifetime
-- Ø  evidence_slot = floor(ngx.time() / rule.window)
-- Ø  TTL >= rule.window × (cc.min_violation_windows + 1)
-- Ø  Config schema restricts min_violation_windows ≤ 4, so window*5 is safe.
-- ---------------------------------------------------------------------------
function _M.record_cc_violation_evidence(rule_id, ip, window)
    if not rule_id or rule_id == "" or not ip or not window then return end
    local evidence_slot = math.floor(ngx.time() / window)
    local key = ip_enc.violation_key(ip_enc.encode_rule_id(rule_id), ip, evidence_slot)
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
-- Keys: fl:cc:violation:<encoded_rule_id>:<ip>:<evidence_slot>
-- We cannot use get_keys() on large dictionaries, so we probe slots
-- backward from current slot for a bounded window span.
--
-- The slot width is the RULE's window, because that is what the writer uses:
-- evidence_slot = floor(ngx.time() / rule.window). Reading with a different
-- width probes a different grid entirely — 300s slots and 60s slots are
-- different numbers, so the probe never meets the evidence it is looking for
-- and the count stays 0 no matter how much abuse there is. The reader used to
-- be handed cc.ttl (300) while the writer used rule.window (60): that made
-- CC promotion unreachable, silently.
--
-- Each referenced rule is counted on its own grid; the result is the maximum
-- across rules. Summing instead would let one violation of three different
-- rules inside a single window count as three "violation windows", which is
-- not what min_violation_windows means.
--
-- @param ip string
-- @param max_slots number: maximum number of slots to probe per rule
-- @return number: count of slots with at least one violation
-- ---------------------------------------------------------------------------
local function rule_windows(rule_ids)
    local out = {}
    local config = require "core.config"
    local rules = config and config.rule and config.rule.frequency_limit
    if type(rules) ~= "table" then return out end
    for _, rule in ipairs(rules) do
        if rule and rule.id and rule.id ~= "" then
            for _, rid in ipairs(rule_ids) do
                if rid == rule.id then
                    out[rid] = tonumber(rule.window) or DEFAULT_WINDOW
                end
            end
        end
    end
    return out
end

function _M.count_cc_violations(ip, max_slots)
	if not ip or not max_slots or max_slots <= 0 then return 0 end
	local config = require "core.config"
	local kb_cfg = config and config.kernel_ip_blocking
	local rule_ids = (kb_cfg and kb_cfg.cc and kb_cfg.cc.rule_ids) or {}
	if #rule_ids == 0 then return 0 end

	local s = ngx.shared[CC_DICT]
	if not s then return 0 end

	local windows = rule_windows(rule_ids)
	local now = ngx.time()
	local best = 0
	for _, rule_id in ipairs(rule_ids) do
		local w = windows[rule_id] or DEFAULT_WINDOW
		local current_slot = math.floor(now / w)
		local enc_id = ip_enc.encode_rule_id(rule_id)
		local count = 0
		-- Probe slots backward from current
		for slot_offset = 0, max_slots - 1 do
			local slot = current_slot - slot_offset
			if slot < 0 then break end
			local key = ip_enc.violation_key(enc_id, ip, slot)
			if s:get(key) ~= nil then
				count = count + 1
			end
		end
		if count > best then best = count end
	end
	return best
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

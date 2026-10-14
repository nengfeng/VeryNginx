local _M = {}

local config = require "core.config"
local bit = require "core.bit_compat"
local json = pcall(require, "cjson") and require("cjson") or require("dkjson")
local wlg = require "core.kernel_blocking.whitelist_generation"
local cidr = require "core.cidr"
local random = require "core.random"
local dict_guard = require "core.dict_guard"
local DEFAULTS = {
    slot_size = 60,
    window_size = 300,
    threshold = 25,
    flag_duration = 600,
    pending_ttl = 600,
    min_requests = 3,
    signals = {
        waf_challenge = 3,
        waf_block = 5,
        not_found = 1,
        challenge_fail = 5,
    },
    whitelist = {},
    auto_whitelist = {
        enabled = true,
        threshold = 3,        -- 连续通过 challenge 次数
        ttl = 3600,            -- 自动白名单有效期（秒）
        max_entries = 1000,    -- 最大并发自动白名单数
    },
}

local SHARED_DICT_NAME = "ip_reputation"
local CACHE_TTL = 10
local SCORE_CACHE_TTL = 2
local MAX_UA_DISTINCT = 20
local AWL_INDEX_KEY = "ip_rep:awl_index"
local INDEX_COMPACT_THRESHOLD = 32

-- Durable per-day flag log (ip_rep:flaglog:<YYYYMMDD>[:ip]). Flag keys and
-- the evidence snapshot both live only flag_duration (default 600s); once
-- they expire the daily counter was the sole survivor and "今日标记 N" could
-- never answer WHICH IPs were flagged. These records deliberately outlive
-- the flags (48h TTL, UTC-day keys) so the panel can list expired flags.
-- FLAG_LOG_MAX bounds BOTH paths: the day index is capped at write time
-- (flaglog_index_add_unlocked — flag_ip runs on the request hot path via
-- is_flagged, so an unbounded index would be a full decode/encode of a
-- growing list inside the global index lock, worst exactly when attack
-- traffic peaks) and the read surfaces at most FLAG_LOG_MAX newest rows.
local FLAG_LOG_TTL = 172800
local FLAG_LOG_MAX = 100

local function shared()
    return ngx.shared[SHARED_DICT_NAME]
end

-- ---------------------------------------------------------------------------
-- JSON index mutex: serializes read-modify-write on shared list keys across
-- workers (avoid lost updates / TOCTOU). Uses vn_locks shared dict.
-- Falls back to a best-effort un-locked RMW if the lock cannot be acquired.
-- ---------------------------------------------------------------------------
local INDEX_LOCK_DICT = "vn_locks"
local INDEX_LOCK_KEY = "ip_rep:index_lock"
local INDEX_LOCK_TTL = 5
local INDEX_LOCK_SLEEP = 0.001
local INDEX_LOCK_MAX_RETRIES = 100

local function index_lock_acquire(s)
    local token = random.bytes(8)
    local attempts = 0
    while attempts < INDEX_LOCK_MAX_RETRIES do
        if s:add(INDEX_LOCK_KEY, token, INDEX_LOCK_TTL) then
            return token
        end
        attempts = attempts + 1
        if ngx.sleep then
            ngx.sleep(INDEX_LOCK_SLEEP)
        end
    end
    return nil
end

local function index_lock_release(s, token)
    if s:get(INDEX_LOCK_KEY) == token then
        s:delete(INDEX_LOCK_KEY)
    end
end

local function with_index_lock(fn)
    local s = ngx.shared[INDEX_LOCK_DICT]
    if not s then
        return fn()
    end
    local token = index_lock_acquire(s)
    if not token then
        -- Best-effort fallback: without the lock a concurrent RMW could be
        -- lost. Log so sustained contention is visible, but still attempt the
        -- operation rather than dropping the entry outright.
        ngx.log(ngx.WARN, "ip_reputation: index lock not acquired after ",
                INDEX_LOCK_MAX_RETRIES, " retries; proceeding without lock")
        return fn()
    end
    local ok, result = pcall(fn)
    index_lock_release(s, token)
    if ok then
        return result
    end
    return nil, result
end

local cfg_val -- forward declare (defined below add_to_pending_index)

--- Keep only live entries of a JSON list.
-- @param list array of IP strings
-- @param is_live function(eip) -> truthy when the entry still has live state
-- @return compacted list
local function filter_live(list, is_live)
    local compacted = {}
    for _, eip in ipairs(list) do
        if is_live(eip) then
            compacted[#compacted + 1] = eip
        end
    end
    return compacted
end

-- Core JSON-index add (RMW). Callers must hold the index lock (with_index_lock).
-- @param force_renew: treat a pre-existing entry for `ip` as stale and replace
-- it (used when the caller knows the previous flag/pending expired), so a dead
-- entry lingering in a sub-threshold list cannot suppress a fresh re-add.
local function json_index_add_unlocked(s, index_key, ip, ttl, is_live, force_renew)
    local raw = s:get(index_key)
    local list = {}
    if raw then
        local ok, decoded = pcall(json.decode, raw)
        if ok and type(decoded) == "table" then list = decoded end
    end
    -- Opportunistically drop dead entries once the list grows past the
    -- threshold (bounds index growth; live entries are never lost).
    if is_live and #list >= INDEX_COMPACT_THRESHOLD then
        list = filter_live(list, is_live)
    end
    -- Dedup: a live entry for this IP short-circuits. A dead entry may be
    -- dropped and re-added fresh (count/refresh consistency).
    for i, v in ipairs(list) do
        if v == ip then
            if not force_renew and (not is_live or is_live(v)) then
                return false
            end
            table.remove(list, i)
            break
        end
    end
    table.insert(list, ip)
    dict_guard.set(s, "ip_rep.index", index_key, json.encode(list), ttl)
    return true
end

-- Core JSON-index remove (RMW). Callers must hold the index lock.
local function json_index_remove_unlocked(s, index_key, ip, ttl)
    local raw = s:get(index_key)
    if not raw then return end
    local ok, list = pcall(json.decode, raw)
    if not ok or type(list) ~= "table" then return end
    local filtered = {}
    for _, v in ipairs(list) do
        if v ~= ip then table.insert(filtered, v) end
    end
    if #filtered > 0 then
        -- Write back with the class TTL so the index keeps auto-expiring
        -- (a nil TTL here would make the key immortal until next add).
        dict_guard.set(s, "ip_rep.index", index_key, json.encode(filtered), ttl)
    else
        s:delete(index_key)
    end
end

local function pending_index_key(ip)
    return "ip_rep:pi:" .. ip
end

-- Update pending_index after add/remove
local function add_to_pending_index(ip)
    local s = shared()
    if not s then return end
    local ttl = cfg_val("pending_ttl")
    -- Fast path: an already-live per-IP key means the IP is already indexed.
    -- Refresh the per-IP key TTL with a lock-free set (idempotent) and ALSO
    -- refresh the index TTL via json_index_add_unlocked(force_renew=true).
    -- Without this the index TTL can lapse (see _collect_pending: index TTL
    -- is math.max(pending_max_rem, 1) which drops to 1s as entries expire),
    -- leaving the index absent while per-IP keys live — forcing the
    -- get_keys(0) 1024-key fallback in pending_count / _collect_pending.
    local fresh = s:get(pending_index_key(ip)) == nil
    dict_guard.set(s, "ip_rep.pending_index", pending_index_key(ip), "1", ttl)
    if fresh then
        with_index_lock(function()
            -- Serialized: re-set_pending after expiry must refresh the index even
            -- when a dead entry for this IP lingers in a sub-threshold list.
            json_index_add_unlocked(s, "ip_rep:pending_index", ip, ttl,
                function(eip) return s:get(pending_index_key(eip)) ~= nil end,
                true)
        end)
        s:incr("ip_rep:pi_version", 1, 0, 0)
    else
        -- Index already has this IP; refresh its TTL without the global lock.
        -- json_index_add_unlocked with force_renew=true re-encodes and re-TTLs
        -- the index, keeping it alive alongside the per-IP key.
        json_index_add_unlocked(s, "ip_rep:pending_index", ip, ttl,
            function(eip) return s:get(pending_index_key(eip)) ~= nil end,
            true)
    end
end

local function remove_from_pending_index(ip)
    local s = shared()
    if not s then return end
    -- Fast path: no live per-IP key, nothing pending to remove.
    -- (A stale list entry may linger until compaction — harmless, it reads as
    -- dead during scans.)
    if s:get(pending_index_key(ip)) == nil then return end
    -- Delete the per-IP key and the index entry in one lock-held critical
    -- section (mirrors add_to_pending_index), so a concurrent add/remove of the
    -- same IP cannot leave a transient window where the two disagree.
    with_index_lock(function()
        s:delete(pending_index_key(ip))
        json_index_remove_unlocked(s, "ip_rep:pending_index", ip, cfg_val("pending_ttl"))
    end)
    s:incr("ip_rep:pi_version", 1, 0, 0)
end

local function raw_cfg()
    return config.ip_reputation or {}
end

function cfg_val(key)
    local v = raw_cfg()[key]
    if v ~= nil then return v end
    return DEFAULTS[key]
end

--- Is the reputation subsystem switched on?
--
-- Until now nothing read this key: `ip_reputation.enable: false` sat in the
-- shipped defaults while record_signal / flag_ip / is_flagged all ran anyway,
-- so an operator who believed they had turned scoring off had not. It is a
-- real switch now. An ABSENT key means enabled — a config written before the
-- switch existed describes an install that was running, and failing closed
-- here would silently unflag every IP on upgrade.
function _M.is_enabled()
    local v = raw_cfg().enable
    if v == nil then return true end
    return v == true
end

--- Signal weight to charge for a rule hit.
--
-- All block rules used to cost the flat `signals.waf_block` (5), which made
-- vn_bot_0017 — a UserAgent match on ccbot / claudebot / dataforseo, i.e. the
-- ordinary AI and search crawlers — as expensive as an XSS attempt. Five
-- crawler requests inside the window flagged a verified search engine and
-- held it at a flat 403 for the whole flag duration, with no challenge step
-- in between to prove otherwise.
--
-- rule_signal_weights maps a rule *category* to its own weight; categories
-- absent from the map keep the flat signal weight. Keying on category (a
-- field the factory rules already carry) rather than rule id means an
-- operator who adds their own bot rule gets the soft weight automatically.
--
-- @param rule table|nil: a WAF rule (nil-safe, e.g. for signals with no rule)
-- @return number: points to charge (>= 1)
function _M.signal_weight_for_rule(rule)
    local base = cfg_val("signals").waf_block or DEFAULTS.signals.waf_block
    if not rule then return base end
    local by_cat = raw_cfg().rule_signal_weights
    if type(by_cat) ~= "table" then return base end
    local cat = rule.category
    local w = cat and by_cat[cat]
    if type(w) == "number" and w >= 1 then return w end
    return base
end

--- Is this rule one that a verified crawler should be exempt from?
--
-- Only rules whose category carries an entry in rule_signal_weights — i.e.
-- the soft categories. An attack rule is never skipped: a crawler fetching a
-- URL whose query string carries SQL injection is still an injection worth
-- blocking, and "it is Googlebot" is not a defence against that.
--
-- @param rule table
-- @param ip string
-- @return boolean
function _M.is_crawler_exempt(rule, ip)
    local by_cat = raw_cfg().rule_signal_weights
    if type(by_cat) ~= "table" or not rule or not rule.category then return false end
    if by_cat[rule.category] == nil then return false end
    return cidr.match_any(ip, raw_cfg().crawler_ip_whitelist)
end

local function slot_size()
    return cfg_val("slot_size")
end

local function window_size()
    return cfg_val("window_size")
end

-- Public read-only accessors for Promotion Policy (Phase 1+)
function _M.slot_size()
    return slot_size()
end

function _M.window_size()
    return window_size()
end

function _M.flag_duration()
    return cfg_val("flag_duration")
end

local function num_slots()
    return math.ceil(window_size() / slot_size())
end

local function current_slot()
    return math.floor(ngx.time() / slot_size())
end

local _slot_cache_slot = nil
local _slot_cache_keys = nil

local function slot_keys()
    local slot = current_slot()
    if slot == _slot_cache_slot and _slot_cache_keys then
        return _slot_cache_keys
    end
    local n = num_slots()
    local keys = {}
    for i = 0, n - 1 do
        keys[i + 1] = slot - i
    end
    _slot_cache_slot = slot
    _slot_cache_keys = keys
    return keys
end

local function sum_slots(key_prefix)
    local s = shared()
    if not s then return 0 end
    local total = 0
    for _, slot in ipairs(slot_keys()) do
        local val = s:get(key_prefix .. slot) or 0
        total = total + val
    end
    return total
end

local function resolve_path()
    return require("core.config").resolve_path() .. "/configs/"
end

local function get_signals()
    local raw = raw_cfg()
    if raw.signals then return raw.signals end
    return DEFAULTS.signals
end

local function get_whitelist()
    local raw = raw_cfg()
    if raw.whitelist then return raw.whitelist end
    return DEFAULTS.whitelist
end

--- Charge `signal_type` against an IP's score.
--
-- `rule` is optional: when given, its category may lower the weight (see
-- signal_weight_for_rule). Signals with no rule behind them — geoip_block,
-- fingerprint_block, not_found — keep the flat configured weight.
--
-- @param ip string
-- @param signal_type string
-- @param rule table|nil: the WAF rule that produced the signal
function _M.record_signal(ip, signal_type, rule)
    if not _M.is_enabled() then return end
    local signals = get_signals()
    local weight = signals[signal_type]
    if not weight or weight <= 0 then
        return
    end
    if rule then
        weight = _M.signal_weight_for_rule(rule)
    end
    local s = shared()
    if not s then return end
    local slot = current_slot()
    local key = "ip_rep:waf:" .. ip .. ":" .. slot
    s:incr(key, weight, 0, window_size())
    -- Per-signal event counter. The waf slot above only stores the summed
    -- points, which loses the signal *type* — this companion counter is what
    -- lets the panel answer "why was this IP flagged". Same window/TTL, so
    -- both expire together.
    s:incr("ip_rep:sig:" .. ip .. ":" .. signal_type .. ":" .. slot, 1, 0, window_size())
    -- Invalidate score cache since weights changed
    s:delete("ip_rep:score_cache:" .. ip)
end

function _M.increment_req(ip)
    local s = shared()
    if not s then return end
    local slot = current_slot()
    local key = "ip_rep:req:" .. ip .. ":" .. slot
    s:incr(key, 1, 0, window_size())
end

function _M.record_ua(ip, ua_string)
    local s = shared()
    if not s then return end
    local slot = current_slot()
    local hash = ngx.crc32_short(ua_string or "")
    local seen_key = "ip_rep:ua_seen:" .. ip .. ":" .. slot .. ":" .. hash
    local is_new = s:add(seen_key, 1, window_size())
    if is_new then
        local count_key = "ip_rep:ua_count:" .. ip .. ":" .. slot
        s:incr(count_key, 1, 0, window_size())
        -- Invalidate score cache: the UA diversity factor has changed
        s:delete("ip_rep:score_cache:" .. ip)
    end
end

local function distinct_ua_count(ip)
    local s = shared()
    if not s then return 0 end
    local total = 0
    for _, slot in ipairs(slot_keys()) do
        local val = s:get("ip_rep:ua_count:" .. ip .. ":" .. slot) or 0
        total = total + val
    end
    return total
end

--- Raw score computation shared by get_score() and score_explain().
-- @return result, raw, df, ua_distinct
local function compute_score(ip)
    local raw = sum_slots("ip_rep:waf:" .. ip .. ":")
    local duc = distinct_ua_count(ip)
    local df = 1.0
    if duc > 1 then
        df = math.max(0.5, 1.0 - (math.min(duc, MAX_UA_DISTINCT) - 1) * 0.1)
    end
    return math.floor(raw * df + 0.5), raw, df, duc
end

function _M.get_score(ip)
    if not _M.is_enabled() then return 0 end
    local s = shared()
    if s then
        local cached = s:get("ip_rep:score_cache:" .. ip)
        if cached ~= nil then
            return cached
        end
    end
    local result = compute_score(ip)
    if s then
        -- Adaptive TTL: clean IPs (well below threshold) cache longer
        local threshold = cfg_val("threshold")
        local ttl = (result < threshold * 0.5) and 10 or SCORE_CACHE_TTL
        dict_guard.set(s, "ip_rep.score_cache", "ip_rep:score_cache:" .. ip, result, ttl)
    end
    return result
end

--- Full score explanation for diagnostics: the score plus the inputs behind
-- it (raw signal points, UA-diversity factor, distinct-UA count). Always
-- recomputed fresh — the caller wants the truth, not a 2-second cache.
function _M.score_explain(ip)
    local result, raw, df, duc = compute_score(ip)
    return {
        score = result,
        raw = raw,
        diversity = df,
        ua_distinct = duc,
        threshold = cfg_val("threshold"),
        window = window_size(),
    }
end

--- Per-signal event/point breakdown for an IP over the live window.
-- Enumerates the *configured* signal types (a type removed from config drops
-- out of the breakdown; its counters simply age out with the window). Points
-- are recomputed as events x current weight, so a mid-window weight edit can
-- differ from the summed waf slot total.
-- @return array of { signal, events, weight, points },
--         sorted points desc then name asc — deterministic, never pairs()-order
function _M.get_signal_breakdown(ip)
    local out = {}
    local s = shared()
    if not s then return out end
    local signals = get_signals()
    -- Stable iteration order: collect then sort the type names.
    local types = {}
    for stype, w in pairs(signals) do
        if type(w) == "number" and w > 0 then
            types[#types + 1] = stype
        end
    end
    table.sort(types)
    local slots = slot_keys()
    for _, stype in ipairs(types) do
        local events = 0
        for _, slot in ipairs(slots) do
            events = events + (s:get("ip_rep:sig:" .. ip .. ":" .. stype .. ":" .. slot) or 0)
        end
        if events > 0 then
            local weight = signals[stype]
            out[#out + 1] = {
                signal = stype,
                events = events,
                weight = weight,
                points = events * weight,
            }
        end
    end
    table.sort(out, function(a, b)
        if a.points ~= b.points then return a.points > b.points end
        return a.signal < b.signal
    end)
    return out
end

--- Snapshot of the evidence taken when the IP was flagged (written by
-- flag_ip). The live slots only cover the rolling window (default 5 min)
-- while a flag outlives it (default 10 min), so without this snapshot the
-- panel would lose the reason halfway through the flag's lifetime.
-- @return table|nil { at, score, threshold, signals = {...} }
function _M.get_flag_reason(ip)
    local s = shared()
    if not s then return nil end
    local raw = s:get("ip_rep:flag_reason:" .. ip)
    if not raw then return nil end
    local ok, snap = pcall(json.decode, raw)
    -- Guard the dkjson path: json.decode("null") yields json.null, a TABLE
    -- with a metatable, which would otherwise masquerade as a snapshot.
    if not ok or snap == json.null or type(snap) ~= "table" then return nil end
    return snap
end

function _M.set_pending(ip)
    local s = shared()
    if not s then return end
    local ttl = cfg_val("pending_ttl")
    dict_guard.set(s, "ip_rep.pending", "ip_rep:pending:" .. ip, ngx.time(), ttl)
    add_to_pending_index(ip)
end

function _M.has_pending(ip)
    local s = shared()
    if not s then return false end
    return s:get("ip_rep:pending:" .. ip) ~= nil
end

function _M.clear_pending(ip)
    local s = shared()
    if not s then return end
    if s:get("ip_rep:pending:" .. ip) then
        s:delete("ip_rep:pending:" .. ip)
        remove_from_pending_index(ip)
    end
end

--- Track consecutive challenge pass (for auto-whitelist).
-- Increments a counter; when it reaches threshold, adds IP to auto-whitelist.
-- The live entry list is kept in a JSON index (ip_rep:awl_index) maintained
-- under the index lock, so the max_entries cap is enforced on *live* entries
-- and self-heals as entries expire (no unbounded counter leak).
function _M.record_challenge_pass(ip)
    local awl = raw_cfg().auto_whitelist or DEFAULTS.auto_whitelist
    if not awl.enabled then return end
    local s = shared()
    if not s then return end
    local key = "ip_rep:awl_count:" .. ip
    local count = s:incr(key, 1, 0, awl.ttl)
    if count < awl.threshold then
        return
    end
    s:delete(key)

    local added = with_index_lock(function()
        local raw = s:get(AWL_INDEX_KEY)
        local list = {}
        if raw then
            local ok, decoded = pcall(json.decode, raw)
            if ok and type(decoded) == "table" then list = decoded end
        end
        local compacted = filter_live(list, function(eip)
            return s:get("ip_rep:awl:" .. eip) ~= nil
        end)
        local existing = false
        for _, eip in ipairs(compacted) do
            if eip == ip then existing = true break end
        end
        if existing then
            -- Already whitelisted: refresh index TTL only, keep live key as-is.
            dict_guard.set(s, "ip_rep.awl_index", AWL_INDEX_KEY, json.encode(compacted), awl.ttl)
            return false
        end
        if #compacted >= awl.max_entries then
            -- Cap reached: never publish the live key for an IP that is not in
            -- the index, or the app layer (is_whitelisted) and the kernel allow
            -- snapshot (index-driven) would diverge.
            dict_guard.set(s, "ip_rep.awl_index", AWL_INDEX_KEY, json.encode(compacted), awl.ttl)
            return false
        end
        -- Publish live key + index in the same critical section so no window
        -- exists where is_whitelisted (reads the live key) disagrees with the
        -- allow snapshot (reads the index).
        compacted[#compacted + 1] = ip
        dict_guard.set(s, "ip_rep.awl", "ip_rep:awl:" .. ip, ngx.time(), awl.ttl)
        dict_guard.set(s, "ip_rep.awl", "ip_rep:awl_ttl:" .. ip, awl.ttl, awl.ttl)
        dict_guard.set(s, "ip_rep.awl_index", AWL_INDEX_KEY, json.encode(compacted), awl.ttl)
        return true
    end)

    if added then
        wlg.bump_sequence()
    end
end

local function flagged_idx_key(ip)
    return "ip_rep:flagged_idx:" .. ip
end

local function add_to_flagged_index(ip, ttl, now)
    local s = shared()
    if not s then return false end
    -- Serialized decision: the liveness of a re-flag must be evaluated against
    -- the flag state *before* this call, otherwise a dead index entry lingering
    -- in a sub-threshold list would suppress counting a fresh flag. Only the
    -- first concurrent caller after expiry observes already == nil.
    return with_index_lock(function()
        local already = s:get("ip_rep:flagged:" .. ip) ~= nil
        dict_guard.set(s, "ip_rep.flagged", "ip_rep:flagged:" .. ip, now, ttl)
        dict_guard.set(s, "ip_rep.flagged_index", flagged_idx_key(ip), tostring(now + ttl), ttl)
        local added = json_index_add_unlocked(s, "ip_rep:flagged_index", ip, ttl,
            function(eip) return s:get(flagged_idx_key(eip)) ~= nil end,
            not already)
        -- Count when this IP was not already flagged, or its stale index entry
        -- was replaced as a fresh one.
        return (not already) or added
    end)
end

local function remove_from_flagged_index(ip)
    local s = shared()
    if not s then return end
    -- Per-IP delete + index remove in one lock-held section (mirrors
    -- add_to_flagged_index) to avoid a transient index/per-IP disagreement
    -- under concurrent flag/clear of the same IP.
    with_index_lock(function()
        s:delete(flagged_idx_key(ip))
        json_index_remove_unlocked(s, "ip_rep:flagged_index", ip, cfg_val("flag_duration"))
    end)
end

--- Flag timestamps for a single IP (nil when not currently flagged).
function _M.get_flag_meta(ip)
    local s = shared()
    if not s then return nil end
    local expires_at = tonumber(s:get(flagged_idx_key(ip)))
    if not expires_at or expires_at <= ngx.time() then return nil end
    local flagged_at = tonumber(s:get("ip_rep:flagged:" .. ip))
    if not flagged_at then
        flagged_at = expires_at - cfg_val("flag_duration")
    end
    return { flagged_at = flagged_at, expires_at = expires_at }
end

-- The day bucket for the durable flag log AND for the flagged_today counter,
-- which is why both live here: the panel shows them side by side under the
-- same "today" label, so they must roll over at the same instant.
--
-- Local server date, deliberately NOT os.date("!%Y%m%d"). The UTC day rolls
-- over at 08:00 on a CST box, so every day between local midnight and 08:00
-- the counter (a 24h TTL that ignores day boundaries) counted events whose
-- records went to the previous day's list — the panel read "今日标记 14" above
-- a five-row "今日被标记 IP" table, with the missing nine sitting in a bucket
-- nobody displays. Keying the counter by day removes the second mismatch too:
-- same day function, same rollover, no rolling window to disagree with.
local function flag_log_day()
    return os.date("%Y%m%d")
end

local function flagged_today_key()
    return "ip_rep:flagged_today:" .. flag_log_day()
end

-- Day-index add with a HARD write-path bound. The generic
-- json_index_add_unlocked cannot serve the flag log: with is_live=nil its
-- only growth control (filter_live compaction) is disabled, so the index
-- would grow without bound — one full decode/encode per newly flagged IP,
-- O(n) inside the global index lock — until the shared dict refuses the
-- oversized value and the index freezes while ip_rep:flagged_today keeps
-- counting (the §3.4 silent divergence, reintroduced by the very feature
-- built to fight it). Evicting the oldest-first-SEEN entries keeps the
-- newest FLAG_LOG_MAX; per-IP data keys are untouched, so an evicted IP's
-- count still merges when it is flagged again (its list slot re-enters at
-- the tail). Bounded work: decode/encode of <= FLAG_LOG_MAX short strings.
local function flaglog_index_add_unlocked(s, day, ip, ttl)
    local key = "ip_rep:flaglog:" .. day
    local raw = s:get(key)
    local list = {}
    if raw then
        local ok, decoded = pcall(json.decode, raw)
        if ok and type(decoded) == "table" then list = decoded end
    end
    for _, v in ipairs(list) do
        if v == ip then return false end -- already listed; data key merged by caller
    end
    -- Single-pass tail-keep (O(n), not repeated remove(1)): also self-heals
    -- any oversized list written before this bound existed.
    local drop = #list - FLAG_LOG_MAX + 1
    if drop > 0 then
        local trimmed = {}
        for i = drop + 1, #list do trimmed[#trimmed + 1] = list[i] end
        list = trimmed
    end
    list[#list + 1] = ip
    dict_guard.set(s, "ip_rep.index", key, json.encode(list), ttl)
    return true
end

-- Append one durable per-day flag record for `ip` (see FLAG_LOG_TTL).
-- Called only for NEW flags (add_to_flagged_index serialized the decision),
-- so the per-IP data key has a single writer; the day index RMW runs under
-- the index lock like every other ip_rep JSON index.
local function record_flag_log(ip, snap)
    local s = shared()
    if not s then return end
    local day = flag_log_day()
    local now = (snap and snap.at) or ngx.time()
    local entry = { first_at = now, last_at = now, count = 1 }
    local prev = s:get("ip_rep:flaglog:" .. day .. ":" .. ip)
    if prev then
        local ok, p = pcall(json.decode, prev)
        if ok and type(p) == "table" then
            entry.first_at = p.first_at or now
            entry.last_at = now
            entry.count = (tonumber(p.count) or 0) + 1
        end
    end
    if snap then
        entry.score = snap.score
        entry.threshold = snap.threshold
        entry.signals = snap.signals
    end
    dict_guard.set(s, "ip_rep.flaglog", "ip_rep:flaglog:" .. day .. ":" .. ip,
        json.encode(entry), FLAG_LOG_TTL)
    with_index_lock(function()
        -- Not json_index_add_unlocked: entries are records, not live state,
        -- so is_live=nil would disable the ONLY growth bound — this capped
        -- variant is the flag-log's own write path (see above).
        flaglog_index_add_unlocked(s, day, ip, FLAG_LOG_TTL)
    end)
end

-- Today's durable flag records, newest first (by last_at), capped. The day
-- index is already bounded to FLAG_LOG_MAX entries at write time, so the
-- loop below performs at most FLAG_LOG_MAX gets — the final trim is a
-- belt-and-braces guard, not the primary bound.
local function flagged_log_today(s)
    local day = flag_log_day()
    local raw = s:get("ip_rep:flaglog:" .. day)
    if not raw then return {} end
    local ok, list = pcall(json.decode, raw)
    if not ok or type(list) ~= "table" then return {} end
    local out = {}
    for _, ip in ipairs(list) do
        local ejson = s:get("ip_rep:flaglog:" .. day .. ":" .. ip)
        if ejson then
            local ok2, e = pcall(json.decode, ejson)
            if ok2 and type(e) == "table" then
                e.ip = ip
                out[#out + 1] = e
            end
        end
    end
    table.sort(out, function(a, b) return (a.last_at or 0) > (b.last_at or 0) end)
    if #out > FLAG_LOG_MAX then
        local trimmed = {}
        for i = 1, FLAG_LOG_MAX do trimmed[i] = out[i] end
        return trimmed
    end
    return out
end

function _M.flag_ip(ip, duration)
    if not _M.is_enabled() then return end
    local s = shared()
    if not s then return end
    local ttl = duration or cfg_val("flag_duration")
    local now = ngx.time()
    -- add_to_flagged_index sets the flag keys + index in one lock-held critical
    -- section and reports whether this is a *new* flag (based on the pre-call
    -- state), so a dead index entry from an expired flag cannot suppress the
    -- count, while concurrent re-flags after expiry cannot double-count.
    if add_to_flagged_index(ip, ttl, now) then
        s:incr(flagged_today_key(), 1, 0, 86400)
        -- Snapshot the evidence while the signal slots are still live: the
        -- flag outlives the scoring window, so this is the only record of
        -- "why" that survives until expires_at. TTL matches the flag's.
        local snap = {
            at = now,
            score = _M.get_score(ip),
            threshold = cfg_val("threshold"),
            signals = _M.get_signal_breakdown(ip),
        }
        dict_guard.set(s, "ip_rep.flag_reason", "ip_rep:flag_reason:" .. ip,
            json.encode(snap), ttl)
        record_flag_log(ip, snap)
    end
end

function _M.is_flagged(ip, opts)
    -- Disabled means disabled: the filter plugin's 【前置-3】 shortcut keys off
    -- this, so returning true would keep serving the 403 that the switch is
    -- supposed to stop. Existing flags stay in the shared dict (harmless,
    -- expires on its own TTL) and reappear if the subsystem is switched back
    -- on inside their flag_duration.
    if not _M.is_enabled() then return false end
    local s = shared()
    if not s then return false end
    local no_cache = opts and opts.no_cache

    if not no_cache then
        local cached = s:get("ip_rep:cache:" .. ip)
        if cached ~= nil then
            return cached == 1
        end
    end

    local flagged = s:get("ip_rep:flagged:" .. ip)
    if flagged ~= nil then
        if not no_cache then
            dict_guard.set(s, "ip_rep.cache", "ip_rep:cache:" .. ip, 1, CACHE_TTL)
        end
        return true
    end

    local min_req = cfg_val("min_requests")
    if min_req > 0 then
        local req_total = sum_slots("ip_rep:req:" .. ip .. ":")
        if req_total < min_req then
            if not no_cache then
                s:set("ip_rep:cache:" .. ip, 0, CACHE_TTL)
            end
            return false
        end
    end

    local score = _M.get_score(ip)
    local threshold = cfg_val("threshold")
    if score >= threshold then
        local ttl = cfg_val("flag_duration")
        _M.flag_ip(ip, ttl)
        if not no_cache then
            s:set("ip_rep:cache:" .. ip, 1, CACHE_TTL)
        end
        ngx.log(ngx.WARN, "ip_reputation: IP ", ip, " flagged as scanner, score=", score)
        return true
    end

    if not no_cache then
        s:set("ip_rep:cache:" .. ip, 0, CACHE_TTL)
    end
    return false
end

function _M.clear_ip(ip)
    local s = shared()
    if not s then return end
    s:delete("ip_rep:flagged:" .. ip)
    s:delete("ip_rep:cache:" .. ip)
    s:delete("ip_rep:flag_reason:" .. ip)
    remove_from_flagged_index(ip)
    _M.clear_score(ip)
    -- A full reputation reset must also drop pending challenge state — a
    -- surviving ip_rep:pending:<ip> entry keeps the IP in the challenge
    -- pipeline (and the pending index) after the admin asked to clear it.
    _M.clear_pending(ip)
end

function _M.clear_score(ip)
    local s = shared()
    if not s then return end
    local slots = slot_keys()
    local signals = get_signals()
    for _, slot in ipairs(slots) do
        s:delete("ip_rep:waf:" .. ip .. ":" .. slot)
        s:delete("ip_rep:req:" .. ip .. ":" .. slot)
        s:delete("ip_rep:ua_count:" .. ip .. ":" .. slot)
        -- Per-signal counters too: a surviving breakdown would contradict
        -- the freshly-cleared score until the window aged it out.
        for stype, w in pairs(signals) do
            if type(w) == "number" and w > 0 then
                s:delete("ip_rep:sig:" .. ip .. ":" .. stype .. ":" .. slot)
            end
        end
    end
    -- Invalidate score cache so get_score() reflects the cleared score
    s:delete("ip_rep:score_cache:" .. ip)
end

function _M.add_whitelist(entry)
    local cfg_mod = require("core.config")
    local ok, err = cfg_mod.atomic_mutate(function(cfg)
        local ip_rep = cfg.ip_reputation or {}
        local list = ip_rep.whitelist or {}
        for _, e in ipairs(list) do
            if e == entry then return nil, "already exists" end
        end
        table.insert(list, entry)
        ip_rep.whitelist = list
        cfg.ip_reputation = ip_rep
        return cfg
    end)
    if not ok then
        if tostring(err):find("already exists") then return end
        ngx.log(ngx.WARN, "add_whitelist: save failed: ", err)
        return
    end
    -- Phase 1: bump generation sequence to invalidate old caches
    wlg.bump_sequence()
end

function _M.remove_whitelist(entry)
    local cfg_mod = require("core.config")
    local ok, err = cfg_mod.atomic_mutate(function(cfg)
        local ip_rep = cfg.ip_reputation or {}
        local list = ip_rep.whitelist or {}
        local filtered = {}
        for _, e in ipairs(list) do
            if e ~= entry then
                table.insert(filtered, e)
            end
        end
        ip_rep.whitelist = filtered
        cfg.ip_reputation = ip_rep
        return cfg
    end)
    if not ok then
        ngx.log(ngx.WARN, "remove_whitelist: save failed: ", err)
        return
    end
    -- Phase 1: bump generation sequence to invalidate old caches
    wlg.bump_sequence()
end

-- Dotted-quad parsing and CIDR matching live in core/cidr.lua (shared with the
-- verified-crawler range list so there is only one implementation).
local parse_ipv4 = cidr.parse_ipv4

-- Strict IPv6 format check: 8 groups (or fewer with a single `::`),
-- each group 1-4 lowercase/uppercase hex digits, no embedded whitespace.
-- Also accepts IPv4-mapped IPv6 (::ffff:x.x.x.x) and IPv4-compat IPv6 (::x.x.x.x).
local function is_valid_ipv6(ip)
    if type(ip) ~= "string" or ip == "" then return false end
    if ip:find("%s") then return false end
    if ip:find("%z") then return false end
    -- reject three or more consecutive colons (e.g. ":::")
    if ip:find(":::", 1, true) then return false end
    -- reject a leading/trailing single colon that is not part of `::`
    if ip:sub(1, 1) == ":" and ip:sub(1, 2) ~= "::" then return false end
    if ip:sub(-1) == ":" and ip:sub(-2) ~= "::" then return false end
    local dbl = 0
    for _ in ip:gmatch("::") do dbl = dbl + 1 end
    if dbl > 1 then return false end
    if not ip:match("%x") and ip ~= "::" then return false end

    -- Handle IPv4-mapped/compat IPv6: last part may be dotted-quad
    local has_dotted = ip:match("%.%d+$")
    local parts = {}
    for part in ip:gmatch("[^:]+") do
        parts[#parts + 1] = part
    end
    if has_dotted then
        -- Last part should be IPv4
        local last = parts[#parts]
        local a, b, c, d = last:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        if not a then return false end
        if tonumber(a) > 255 or tonumber(b) > 255
            or tonumber(c) > 255 or tonumber(d) > 255 then return false end
        -- Check the IPv6 prefix parts (excluding the last IPv4 part)
        for i = 1, #parts - 1 do
            if not parts[i]:match("^%x+$") or #parts[i] > 4 then return false end
        end
        local ngroups = #parts - 1
        if dbl == 1 then
            return ngroups <= 6  -- IPv4 mapped takes 2 groups
        end
        return ngroups == 6  -- IPv4 mapped takes 2 groups, total 8
    else
        -- Regular IPv6
        for _, part in ipairs(parts) do
            if not part:match("^%x+$") or #part > 4 then return false end
        end
        local ngroups = #parts
        if dbl == 1 then
            return ngroups <= 7
        end
        return ngroups == 8
    end
end

--- Validate a whitelist entry (bare IPv4/IPv6 or IPv4/IPv6 CIDR).
-- @param entry string: candidate whitelist entry
-- @return boolean: true when the entry is a well-formed IPv4/IPv6 or IPv4/IPv6 CIDR
function _M.validate_whitelist_entry(entry)
    if type(entry) ~= "string" or entry == "" then return false end

    -- IPv6 CIDR (e.g., 2001:db8::/32) or IPv6 bare address
    if entry:find(":", 1, true) then
        -- IPv6 CIDR matching is NOT implemented (is_whitelisted does numeric
        -- v4 math + exact string equality only). Accepting a v6 CIDR would
        -- create a silent dead whitelist entry — reject until supported.
        if entry:find("/") then return false end
        return is_valid_ipv6(entry)
    end

    -- IPv4 CIDR or bare IPv4
    local function ok_octets(s)
        local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        if not a then return false end
        if tonumber(a) > 255 or tonumber(b) > 255
            or tonumber(c) > 255 or tonumber(d) > 255 then return false end
        return true
    end
    local pos = entry:find("/")
    if pos then
        local subnet = entry:sub(1, pos - 1)
        local bits = tonumber(entry:sub(pos + 1))
        if not subnet or not bits or bits < 1 or bits > 32 then return false end
        -- Mirror the Go helper's allow-prefix floor (§11.8b, inclusive): a
        -- /8-and-broader whitelist is evaluated before kernel drops and would
        -- neutralize the blocking surface for the whole range. Rejecting here
        -- (config/import/save time) instead of at snapshot sync time also
        -- keeps replace_allow_snapshot batches from failing wholesale.
        if bits <= 8 then return false end
        local num = parse_ipv4(subnet)
        if not num or not ok_octets(subnet) then return false end
        -- Reject host-bits-set CIDR (e.g. 1.2.3.4/24 is ambiguous)
        local mask = (2 ^ (32 - bits)) - 1
        return bit.band(num, mask) == 0
    end
    return ok_octets(entry)
end

local ip_in_cidr = cidr.ip_in_cidr

function _M.is_whitelisted(ip)
    local s = shared()
    if not s then return false end

    -- Read generation once for this request (epoch may be nil if not initialized)
    local epoch, seq = wlg._get_generation()

    -- Phase 1: use generation-qualified cache
    local cached = wlg._cache_get_with_gen(s, ip, epoch, seq)
    if cached ~= nil then
        return cached
    end
    -- Check static whitelist (from config)
    local wl = get_whitelist()
    for _, entry in ipairs(wl) do
        if ip_in_cidr(ip, entry) then
            wlg._cache_set_with_gen(s, ip, true, epoch, seq)
            return true
        end
    end
    -- Check auto-whitelist (ephemeral, for repeatedly verified IPs)
    local created = s:get("ip_rep:awl:" .. ip)
    if created then
        local awl_ttl = s:get("ip_rep:awl_ttl:" .. ip) or DEFAULTS.auto_whitelist.ttl
        local remaining = awl_ttl - (ngx.time() - created)
        if remaining > 0 then
            -- Limit positive cache TTL to the auto-whitelist *remaining* TTL,
            -- not the full awl.ttl: awl entry expiry does not bump the
            -- generation sequence, so a full-TTL cache here would let the IP
            -- stay allow-listed up to a second full awl.ttl after it expired.
            wlg._cache_set_with_gen(s, ip, true, epoch, seq, remaining)
            return true
        end
    end
    wlg._cache_set_with_gen(s, ip, false, epoch, seq)
    return false
end

function _M.list_flagged()
    local s = shared()
    if not s then return {} end
    local now = ngx.time()
    local valid = {}

    -- Read from JSON index (avoids get_keys(0) 1024-key ceiling)
    local flagged = {}
    local raw = s:get("ip_rep:flagged_index")
    if raw then
        local ok, list = pcall(json.decode, raw)
        if ok and type(list) == "table" then
            for _, ip in ipairs(list) do flagged[ip] = true end
        end
    end

    -- Fallback to get_keys(0) during migration (index may not exist yet)
    if not next(flagged) then
        local keys = s:get_keys(0)
        for _, key in ipairs(keys) do
            local ip = key:match("^ip_rep:flagged_idx:(.+)$")
            if ip then flagged[ip] = true end
        end
    end

    for ip, _ in pairs(flagged) do
        local expires_at = tonumber(s:get(flagged_idx_key(ip)))
        if expires_at and expires_at > now then
            valid[#valid + 1] = {
                ip = ip,
                expires_at = expires_at,
                flagged_at = expires_at - cfg_val("flag_duration"),
                -- Enrichment for the panel: current score plus the flag-time
                -- reason snapshot. Also flows through persist()/restore() so
                -- reasons survive a restart alongside their flags. May be nil
                -- (no snapshot) — the API layer normalizes to JSON null, since
                -- this module's json may differ from the controller's.
                score = _M.get_score(ip),
                reason = _M.get_flag_reason(ip),
            }
        end
    end
    -- Newest first, IP as tiebreak — a stable list for the dashboard table
    -- (raw pairs() order would reshuffle on every render).
    table.sort(valid, function(a, b)
        if a.flagged_at ~= b.flagged_at then return a.flagged_at > b.flagged_at end
        return a.ip < b.ip
    end)
    return valid
end

function _M.list_whitelist()
    return get_whitelist()
end

--- Count current live pending entries.
-- Derived from the JSON index (not a monotonic counter), so TTL expiry or a
-- challenge pass that leaves the pending key in place until TTL never inflates
-- the count.
function _M.pending_count()
    local s = shared()
    if not s then return 0 end
    local now = ngx.time()
    local ttl = cfg_val("pending_ttl") or 0
    local ips = {}
    local raw = s:get("ip_rep:pending_index")
    if raw then
        local ok, list = pcall(json.decode, raw)
        if ok and type(list) == "table" then
            for _, ip in ipairs(list) do ips[ip] = true end
        end
    end
    if not next(ips) then
        for _, key in ipairs(s:get_keys(0)) do
            local ip = key:match("^ip_rep:pi:(.+)$")
            if ip then ips[ip] = true end
        end
    end
    local count = 0
    for ip, _ in pairs(ips) do
        local created = s:get("ip_rep:pending:" .. ip)
        if created and (ttl == 0 or (now - created) < ttl) then
            count = count + 1
        end
    end
    return count
end

function _M.get_stats()
    local enabled = _M.is_enabled()
    if not shared() then
        return { flagged = 0, pending = 0, flagged_today = 0,
                 threshold = cfg_val("threshold"), enabled = enabled }
    end
    local s = shared()
    local flagged_count = #_M.list_flagged()
    local pending_count = _M.pending_count()
    local flagged_today = s:get(flagged_today_key()) or 0
    return {
        flagged = flagged_count,
        pending = pending_count,
        flagged_today = flagged_today,
        -- Exposed so the panel can highlight scores at/over the flag line.
        threshold = cfg_val("threshold"),
        -- Whether scoring/flagging is actually running. The panel shows this
        -- because the switch used to be inert: an operator who had set
        -- enable=false still saw IPs being flagged and had no way to tell
        -- the config was not being read.
        enabled = enabled,
        -- Size of the verified-crawler range list, so an empty list (the
        -- shipped default) is visible rather than silently inert.
        crawler_ip_count = #(raw_cfg().crawler_ip_whitelist or {}),
        -- Durable per-day records: which IPs were flagged today (incl.
        -- already-expired flags), newest first.
        flagged_log = flagged_log_today(s),
    }
end

function _M.persist()
    local wid = (ngx.worker and ngx.worker.id and ngx.worker.id()) or 0
    if wid ~= 0 then
        return
    end
    local flagged = _M.list_flagged()
    -- Collect pending entries from shared dict
    local pending = _M._collect_pending()
    local payload = {
        version = 2,
        saved_at = ngx.time(),
        flagged = flagged,
        pending = pending,
    }
    local dir = resolve_path()
    -- The configs dir may not exist in the test host / minimal install;
    -- create it (lfs preferred, shell fallback) before writing so persist
    -- does not silently no-op and the round-trip data is actually lost.
    do
        local ok_lfs, lfs = pcall(require, "lfs")
        if ok_lfs then
            pcall(lfs.mkdir, dir)
        else
            os.execute("mkdir -p '" .. dir .. "' 2>/dev/null")
        end
    end
    local path = dir .. "ip-reputation-flagged.json"
    local tmp = path .. ".tmp"
    local f = io.open(tmp, "w")
    if not f then
        ngx.log(ngx.WARN, "ip_reputation: cannot open temp file for persist: ", tmp)
        return
    end
    f:write(json.encode(payload, { indent = true }))
    f:close()
    os.rename(tmp, path)
end

-- Collect pending challenge state from shared dict (no-lru scan)
-- Uses version counter to avoid repeated get_keys(0) scans when nothing changed.
local _last_pi_version = nil
local _cached_pending = nil
function _M._collect_pending()
    local s = shared()
    if not s then return {} end
    local ttl = cfg_val("pending_ttl")
    local version = s:get("ip_rep:pi_version")
    if version and version == _last_pi_version and _cached_pending then
        -- Pending entries expire passively and never bump pi_version, so the
        -- cached list may hold entries that have since expired. Refresh the
        -- remaining TTLs from cached created_at and drop what expired.
        local now = ngx.time()
        local fresh = {}
        for _, e in ipairs(_cached_pending) do
            local remaining = ttl - (now - e.created_at)
            if remaining > 0 then
                e.remaining = remaining
                fresh[#fresh + 1] = e
            end
        end
        _cached_pending = fresh
        return fresh
    end
    _last_pi_version = version
    local pending = {}

    -- Read from JSON index (avoids get_keys(0) 1024-key ceiling)
    local pending_ips = {}
    local pidx_raw = s:get("ip_rep:pending_index")
    if pidx_raw then
        local ok, list = pcall(json.decode, pidx_raw)
        if ok and type(list) == "table" then
            for _, ip in ipairs(list) do pending_ips[ip] = true end
        end
    end

    -- Fallback to get_keys(0) during migration
    if not next(pending_ips) then
        local all_keys = s:get_keys(0)
        for _, key in ipairs(all_keys) do
            local ip = key:match("^ip_rep:pi:(.+)$")
            if ip then pending_ips[ip] = true end
        end
    end

    for ip, _ in pairs(pending_ips) do
        local created = s:get("ip_rep:pending:" .. ip)
        if created then
            local remaining = ttl - (ngx.time() - created)
            if remaining > 0 then
                pending[#pending + 1] = { ip = ip, created_at = created, remaining = remaining }
            end
        end
    end
    _cached_pending = pending
    return pending
end

function _M.restore()
    local wid = (ngx.worker and ngx.worker.id and ngx.worker.id()) or 0
    if wid ~= 0 then return end
    local path = resolve_path() .. "ip-reputation-flagged.json"
    local f = io.open(path, "r")
    if not f then
        ngx.log(ngx.WARN, "ip_reputation: no persist file found at ", path)
        return
    end
    local data = f:read("*all")
    f:close()
    if not data or data == "" or data == "[]" then return end
    local ok, payload = pcall(json.decode, data)
    if not ok or type(payload) ~= "table" then
        ngx.log(ngx.ERR, "ip_reputation: persist file decode error")
        return
    end
    local s = shared()
    if not s then return end
    local now = ngx.time()

    -- Restore flagged IPs and rebuild the JSON index, so list_flagged()
    -- still enumerates them after new flags later populate that index.
    -- Without this, restored entries are only reachable via the get_keys(0)
    -- fallback while the index is empty, then vanish from list_flagged() and
    -- the next persist() once a new flag makes the index non-empty.
    local flagged = payload.flagged or {}
    local flagged_list = {}
    local flagged_max_rem = 0
    for _, entry in ipairs(flagged) do
        if entry.expires_at and entry.expires_at > now then
            local remaining = entry.expires_at - now
            s:set("ip_rep:flagged:" .. entry.ip, entry.flagged_at, remaining)
            s:set(flagged_idx_key(entry.ip), tostring(entry.expires_at), remaining)
            s:delete("ip_rep:cache:" .. entry.ip)
            -- Re-materialize the flag-time reason snapshot (persist carries it
            -- inside the entry); same TTL as the flag so they expire together.
            if entry.reason ~= nil and entry.reason ~= json.null
                and type(entry.reason) == "table" then
                local okr, encoded = pcall(json.encode, entry.reason)
                if okr then
                    s:set("ip_rep:flag_reason:" .. entry.ip, encoded, remaining)
                end
            end
            table.insert(flagged_list, entry.ip)
            flagged_max_rem = math.max(flagged_max_rem, remaining)
            ngx.log(ngx.WARN, "ip_reputation: restored flagged IP ", entry.ip, " (", remaining, "s remaining)")
        end
    end
    if #flagged_list > 0 then
        s:set("ip_rep:flagged_index", json.encode(flagged_list), math.max(flagged_max_rem, 1))
    end

    -- Restore pending challenge state (v2 only) and rebuild the pending index
    if payload.pending and type(payload.pending) == "table" then
        local pending_list = {}
        local pending_max_rem = 0
        for _, p in ipairs(payload.pending) do
            if p.ip and p.remaining and p.remaining > 0 then
                s:set("ip_rep:pending:" .. p.ip, p.created_at or (now - 1), p.remaining)
                s:set(pending_index_key(p.ip), "1", p.remaining)
                table.insert(pending_list, p.ip)
                pending_max_rem = math.max(pending_max_rem, p.remaining)
                ngx.log(ngx.WARN, "ip_reputation: restored pending IP ", p.ip, " (", p.remaining, "s remaining)")
            end
        end
        if #pending_list > 0 then
            -- Index TTL must be at least pending_ttl so it outlives the last
            -- pending entry; otherwise a 1-second TTL (from pending_max_rem=1)
            -- expires the index before the next per-IP-key refresh revives it.
            local idx_ttl = math.max(pending_max_rem, cfg_val("pending_ttl") or 0)
            s:set("ip_rep:pending_index", json.encode(pending_list), idx_ttl)
            s:incr("ip_rep:pi_version", 1, 0, 0)
        end
    end
end

return _M

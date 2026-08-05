local _M = {}

local config = require "core.config"
local bit = require "bit"
local json = pcall(require, "cjson") and require("cjson") or require("dkjson")
local wlg = require "core.kernel_blocking.whitelist_generation"
local random = require "core.random"
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

local function json_index_add(index_key, ip, ttl)
    local s = shared()
    if not s then return end
    return with_index_lock(function()
        local raw = s:get(index_key)
        local list = {}
        if raw then
            local ok, decoded = pcall(json.decode, raw)
            if ok and type(decoded) == "table" then list = decoded end
        end
        for _, v in ipairs(list) do
            if v == ip then return end
        end
        table.insert(list, ip)
        s:set(index_key, json.encode(list), ttl)
    end)
end

local function json_index_remove(index_key, ip)
    local s = shared()
    if not s then return end
    return with_index_lock(function()
        local raw = s:get(index_key)
        if not raw then return end
        local ok, list = pcall(json.decode, raw)
        if not ok or type(list) ~= "table" then return end
        local filtered = {}
        for _, v in ipairs(list) do
            if v ~= ip then table.insert(filtered, v) end
        end
        if #filtered > 0 then
            s:set(index_key, json.encode(filtered))
        else
            s:delete(index_key)
        end
    end)
end

local function pending_index_key(ip)
    return "ip_rep:pi:" .. ip
end

-- Update pending_index after add/remove
local function add_to_pending_index(ip)
    local s = shared()
    if not s then return end
    local ttl = cfg_val("pending_ttl")
    s:set(pending_index_key(ip), "1", ttl)
    json_index_add("ip_rep:pending_index", ip, ttl)
    s:incr("ip_rep:pi_version", 1, 0, 0)
end

local function remove_from_pending_index(ip)
    local s = shared()
    if not s then return end
    s:delete(pending_index_key(ip))
    json_index_remove("ip_rep:pending_index", ip)
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

local function slot_keys()
    local slot = current_slot()
    local n = num_slots()
    local keys = {}
    for i = 0, n - 1 do
        keys[i + 1] = slot - i
    end
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

function _M.record_signal(ip, signal_type)
    local signals = get_signals()
    local weight = signals[signal_type]
    if not weight or weight <= 0 then
        return
    end
    local s = shared()
    if not s then return end
    local slot = current_slot()
    local key = "ip_rep:waf:" .. ip .. ":" .. slot
    s:incr(key, weight, 0, window_size())
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

function _M.get_score(ip)
    local s = shared()
    if s then
        local cached = s:get("ip_rep:score_cache:" .. ip)
        if cached ~= nil then
            return cached
        end
    end
    local score = sum_slots("ip_rep:waf:" .. ip .. ":")
    local duc = distinct_ua_count(ip)
    local df = 1.0
    if duc > 1 then
        df = math.max(0.5, 1.0 - (math.min(duc, MAX_UA_DISTINCT) - 1) * 0.1)
    end
    local result = math.floor(score * df + 0.5)
    if s then
        -- Adaptive TTL: clean IPs (well below threshold) cache longer
        local threshold = cfg_val("threshold")
        local ttl = (result < threshold * 0.5) and 10 or SCORE_CACHE_TTL
        s:set("ip_rep:score_cache:" .. ip, result, ttl)
    end
    return result
end

function _M.set_pending(ip)
    local s = shared()
    if not s then return end
    local ttl = cfg_val("pending_ttl")
    s:set("ip_rep:pending:" .. ip, ngx.time(), ttl)
    s:incr("ip_rep:pending_count", 1, 0, 0)
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
        s:incr("ip_rep:pending_count", -1, 0, 0)
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
        local compacted = {}
        local existing = false
        for _, eip in ipairs(list) do
            if s:get("ip_rep:awl:" .. eip) then
                if eip == ip then existing = true end
                compacted[#compacted + 1] = eip
            end
        end
        if not existing and #compacted < awl.max_entries then
            compacted[#compacted + 1] = ip
            s:set(AWL_INDEX_KEY, json.encode(compacted), awl.ttl)
            return true
        end
        s:set(AWL_INDEX_KEY, json.encode(compacted), awl.ttl)
        return false
    end)

    if added then
        s:set("ip_rep:awl:" .. ip, ngx.time(), awl.ttl)
        s:set("ip_rep:awl_ttl:" .. ip, awl.ttl, awl.ttl)
        wlg.bump_sequence()
    end
end

local function flagged_idx_key(ip)
    return "ip_rep:flagged_idx:" .. ip
end

local function add_to_flagged_index(ip, duration, now)
    local s = shared()
    if not s then return end
    local expires_at = (now or ngx.time()) + duration
    s:set(flagged_idx_key(ip), tostring(expires_at), duration)
    json_index_add("ip_rep:flagged_index", ip, duration)
end

local function remove_from_flagged_index(ip)
    local s = shared()
    if not s then return end
    s:delete(flagged_idx_key(ip))
    json_index_remove("ip_rep:flagged_index", ip)
end

function _M.flag_ip(ip, duration)
    local s = shared()
    if not s then return end
    local ttl = duration or cfg_val("flag_duration")
    local now = ngx.time()
    s:set("ip_rep:flagged:" .. ip, now, ttl)
    s:incr("ip_rep:flagged_today", 1, 0, 86400)
    add_to_flagged_index(ip, ttl, now)
end

function _M.is_flagged(ip, opts)
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
            s:set("ip_rep:cache:" .. ip, 1, CACHE_TTL)
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
    remove_from_flagged_index(ip)
end

function _M.clear_score(ip)
    local s = shared()
    if not s then return end
    local slots = slot_keys()
    for _, slot in ipairs(slots) do
        s:delete("ip_rep:waf:" .. ip .. ":" .. slot)
        s:delete("ip_rep:req:" .. ip .. ":" .. slot)
        s:delete("ip_rep:ua_count:" .. ip .. ":" .. slot)
    end
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

local function ip_in_cidr(ip, cidr)
    if ip == cidr then
        return true
    end
    local pos = cidr:find("/")
    if not pos then
        return false
    end
    local subnet_str = cidr:sub(1, pos - 1)
    local bits = tonumber(cidr:sub(pos + 1))
    if not bits then return false end
    local function ip_to_num(s)
        local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        if not a then return nil end
        return (tonumber(a) * 16777216) + (tonumber(b) * 65536) + (tonumber(c) * 256) + tonumber(d)
    end
    local ip_num = ip_to_num(ip)
    local subnet_num = ip_to_num(subnet_str)
    if not ip_num or not subnet_num then return false end
    local mask = 0
    for _ = 1, bits do
        mask = (mask * 2) + 1
    end
    mask = mask * (2 ^ (32 - bits))
    return bit.band(ip_num, mask) == bit.band(subnet_num, mask)
end

function _M.is_whitelisted(ip)
    -- Phase 1: use generation-qualified cache
    local cached = wlg.cache_get(ip)
    if cached ~= nil then
        return cached
    end
    -- Check static whitelist (from config)
    local wl = get_whitelist()
    for _, entry in ipairs(wl) do
        if ip_in_cidr(ip, entry) then
            wlg.cache_set(ip, true)
            return true
        end
    end
    -- Check auto-whitelist (ephemeral, for repeatedly verified IPs)
    local s = shared()
    if s and s:get("ip_rep:awl:" .. ip) then
        -- Limit positive cache TTL to auto-whitelist remaining TTL
        local awl_ttl = s:get("ip_rep:awl_ttl:" .. ip)
        wlg.cache_set(ip, true, awl_ttl or 60)
        return true
    end
    wlg.cache_set(ip, false)
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
            }
        end
    end
    return valid
end

function _M.list_whitelist()
    return get_whitelist()
end

function _M.get_stats()
    local s = shared()
    if not s then return { flagged = 0, pending = 0, flagged_today = 0 } end
    local flagged_count = #_M.list_flagged()
    local pending_count = tonumber(s:get("ip_rep:pending_count") or 0)
    local flagged_today = s:get("ip_rep:flagged_today") or 0
    return {
        flagged = flagged_count,
        pending = pending_count,
        flagged_today = flagged_today,
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
    local path = resolve_path() .. "ip-reputation-flagged.json"
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
    local version = s:get("ip_rep:pi_version")
    if version and version == _last_pi_version and _cached_pending then
        return _cached_pending
    end
    _last_pi_version = version
    local pending = {}
    local ttl = cfg_val("pending_ttl")

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

    -- Restore flagged IPs
    local flagged = payload.flagged or {}
    for _, entry in ipairs(flagged) do
        if entry.expires_at and entry.expires_at > now then
            local remaining = entry.expires_at - now
            s:set("ip_rep:flagged:" .. entry.ip, entry.flagged_at, remaining)
            s:set(flagged_idx_key(entry.ip), tostring(entry.expires_at), remaining)
            s:delete("ip_rep:cache:" .. entry.ip)
            ngx.log(ngx.WARN, "ip_reputation: restored flagged IP ", entry.ip, " (", remaining, "s remaining)")
        end
    end

    -- Restore pending challenge state (v2 only)
    if payload.pending and type(payload.pending) == "table" then
        for _, p in ipairs(payload.pending) do
            if p.ip and p.remaining and p.remaining > 0 then
                s:set("ip_rep:pending:" .. p.ip, p.created_at or (now - 1), p.remaining)
                s:set(pending_index_key(p.ip), "1", p.remaining)
                ngx.log(ngx.WARN, "ip_reputation: restored pending IP ", p.ip, " (", p.remaining, "s remaining)")
            end
        end
    end
end

return _M

-- -*- coding: utf-8 -*-
-- What is actually inside the shared dicts.
--
-- Why this exists
-- ---------------
-- The panel showed `ip_reputation` at 100% of its 16 MB and
-- `frequency_limit` at 94.8%, and there was no way to find out what was in
-- them. Watermarks say "full", never "full of what". Three candidates were
-- ruled out by reading logs rather than the dict: ua_seen looked like an
-- amplifier (it is, see the cap in ip_reputation.record_ua) but no IP
-- presented more than 4 distinct User-Agents a minute; the 48-hour flag log
-- held five records; and pi_version is a single key. Meanwhile the metric
-- itself produced two contradictory readings eleven minutes apart — one
-- claiming every dict was full, the next claiming vn_config was empty, which
-- cannot be true while the rules are running.
--
-- So the missing instrument is exactly this: read capacity and free space
-- directly, and sample the key space per namespace so an operator can see
-- which family of keys is holding the memory.
--
-- The sampling is honest about being a sample
-- -------------------------------------------
-- ngx.shared.DICT has no full key enumeration; get_keys() returns at most
-- 1024 keys and costs a scan proportional to what it returns. So the
-- namespace breakdown is derived from up to KEYS_SAMPLE keys and is reported
-- as `sampled_keys / sample_truncated`. It is enough to answer "which family
-- dominates" and useless for exact per-namespace totals — it does not pretend
-- to be a census.
--
-- Bytes per key are approximate by nature (slab nodes carry fixed overhead
-- and fragment), so the per-namespace byte figures are an estimate derived
-- from free space and the sample's proportions, not a measurement.

local _M = {}

local KEYS_SAMPLE = 1024

-- Dict name -> list of namespace prefixes worth reporting separately. The
-- prefix is the key up to and including the first component that varies per
-- subject (an IP, a rule id, a day), so the grouping is stable across
-- subjects rather than producing one group per IP.
local GROUPS = {
    ip_reputation = {
        { p = "ip_rep:waf", label = "信号槽 waf" },
        { p = "ip_rep:sig", label = "信号明细 sig" },
        { p = "ip_rep:req", label = "请求计数 req" },
        { p = "ip_rep:ua_seen", label = "UA 去重标记" },
        { p = "ip_rep:ua_count", label = "UA 多样性计数" },
        { p = "ip_rep:cache", label = "标记判定缓存" },
        { p = "ip_rep:score_cache", label = "分数缓存" },
        { p = "ip_rep:flagged", label = "标记中" },
        { p = "ip_rep:flagged_index", label = "标记索引" },
        { p = "ip_rep:flag_reason", label = "标记原因快照" },
        { p = "ip_rep:flaglog", label = "每日标记日志" },
        { p = "ip_rep:flagged_today", label = "今日标记计数" },
        { p = "ip_rep:crawler_verify", label = "爬虫 DNS 判定" },
        { p = "ip_rep:awl", label = "自动白名单" },
        { p = "ip_rep:pending", label = "挑战 pending" },
        { p = "ip_rep:pi_version", label = "pending 版本号" },
        { p = "fl:", label = "限流计数器(误入)" },
    },
    frequency_limit = {
        { p = "fl:count", label = "限流计数" },
        { p = "fl:cc:violation", label = "CC 违规证据" },
        { p = "fl:v1", label = "限流计数 v1(遗留)" },
        { p = "fl:", label = "限流计数(遗留/无版本前缀)" },
    },
}

--- Make a key safe to put in a JSON response.
--
-- Keys in the statistics dict are built from request URIs, so they carry
-- whatever bytes the internet sent. Returning one raw breaks the response —
-- the first version of this endpoint emitted a lone 0xc0 byte from a URI and
-- the whole document stopped parsing. Anything outside printable ASCII
-- becomes \xNN, and long keys are truncated so a long URI cannot bloat it.
local function safe_label(k)
    if type(k) ~= "string" then return tostring(k) end
    local esc = k:gsub("[^\32-\126]", function(c)
        return string.format("\\x%02X", c:byte())
    end)
    if #esc > 96 then esc = esc:sub(1, 93) .. "..." end
    return esc
end

local function group_of(name, key)
    local groups = GROUPS[name]
    if not groups then return safe_label(key) end
    -- Longest prefix first, so "ip_rep:ua_seen" is not swallowed by a shorter
    -- prefix that happens to match.
    local best, best_label
    for _, g in ipairs(groups) do
        if #g.p > #(best or "") and key:sub(1, #g.p) == g.p then
            best, best_label = g.p, g.label
        end
    end
    return best_label or safe_label(key)
end

--- Snapshot one dict: exact byte figures, sampled namespace breakdown.
function _M.snapshot(name)
    local d = ngx.shared[name]
    if not d then return { name = name, present = false } end
    local capacity = d:capacity() or 0
    local free = d:free_space() or 0
    local used = capacity - free

    local out = {
        name = name,
        present = true,
        capacity_bytes = capacity,
        free_bytes = free,
        used_bytes = used,
        used_pct = capacity > 0 and math.floor(used / capacity * 1000) / 10 or 0,
    }

    local ok, keys = pcall(function() return d:get_keys(0) end)
    if not ok or type(keys) ~= "table" then
        out.key_scan = "unavailable"
        return out
    end

    local counts, other, total = {}, 0, 0
    for _, k in ipairs(keys) do
        total = total + 1
        local g = group_of(name, k)
        if g == k and GROUPS[name] then
            other = other + 1
        else
            counts[g] = (counts[g] or 0) + 1
        end
    end
    if other > 0 then counts["（未归类）"] = (counts["（未归类）"] or 0) + other end

    local list = {}
    for label, c in pairs(counts) do
        list[#list + 1] = { label = label, keys = c }
    end
    table.sort(list, function(a, b) return a.keys > b.keys end)

    out.sampled_keys = total
    out.sample_truncated = total >= KEYS_SAMPLE
    out.namespaces = list
    -- Bytes per namespace are inferred from the sample's share of the space.
    -- Explicitly an estimate: slab overhead and fragmentation make any
    -- per-key figure approximate, and pretending otherwise would be worse than
    -- saying so.
    if total > 0 and used > 0 then
        for _, e in ipairs(list) do
            e.est_bytes = math.floor(used * e.keys / total)
        end
    end
    return out
end

function _M.snapshot_all()
    local names = {}
    for _, n in ipairs({ "ip_reputation", "frequency_limit", "vn_config", "vn_locks",
                         "vn_rate_limit", "vn_session", "statistics", "metrics",
                         "metrics_labeled", "healthcheck", "dns_cache" }) do
        names[#names + 1] = n
    end
    local out = {}
    for i, n in ipairs(names) do out[i] = _M.snapshot(n) end
    return out
end

--- Can this dict still take a write?
--
-- Occupancy and key count disagree badly here: frequency_limit reports 9.48 MB
-- used across NINE keys, and ip_reputation reports 16 MB across 103. Those are
-- impossible amounts, so capacity()-free_space() is describing allocator state
-- rather than stored data — most likely a slab pool that grew during an earlier
-- traffic spike and never shrank back. That makes the watermark the panel draws
-- untrustworthy as a measure of "how much data are we holding".
--
-- The question that actually matters operationally is whether writes still
-- succeed, and that is answerable directly instead of by inference: under the
-- default eviction policy a full dict silently drops old keys and still reports
-- success, so nothing in any log would ever say so. This probe performs one
-- 1-second-TTL set and one incr and reports what came back.
--
-- It writes two tiny throwaway keys and removes them at once. Deliberately the
-- cheapest test that separates "full and quietly evicting" from "full and
-- refusing".
function _M.write_probe(name)
    local d = ngx.shared[name]
    if not d then return { name = name, present = false } end
    local probe = "vn_diagprobe:" .. tostring(ngx.worker.pid()) .. ":" ..
                  tostring(ngx.now())
    local out = { name = name, present = true }

    local ok, err = d:set(probe, "probe", 1)
    out.set_ok = ok and true or false
    out.set_err = ok and nil or tostring(err)
    if out.set_ok then out.readback = d:get(probe) end
    d:delete(probe)

    -- A SEPARATE key for incr. Incrementing the one just written to "probe"
    -- asks the dict to add 1 to a string, which fails on every dict at every
    -- occupancy level — including a 0.8%-full one. That is how the first
    -- version of this probe reported "incr fails everywhere" and nearly had
    -- everyone believe the shared dicts were refusing writes.
    local ikey = probe .. ":i"
    local v, ierr = d:incr(ikey, 1, 0, 1)
    out.incr_ok = v ~= nil
    out.incr_err = v ~= nil and nil or tostring(ierr)
    if out.incr_ok then out.incr_value = v end
    d:delete(ikey)

    return out
end

function _M.probe_all()
    local out = {}
    for _, n in ipairs({ "ip_reputation", "frequency_limit", "vn_config", "statistics",
                         "metrics", "metrics_labeled" }) do
        out[#out + 1] = _M.write_probe(n)
    end
    return out
end

return _M

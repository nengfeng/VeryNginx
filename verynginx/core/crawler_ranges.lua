-- -*- coding: utf-8 -*-
-- Fetch published crawler IP ranges into ip_reputation.crawler_ip_whitelist.
--
-- The panel's "list is empty" notice has always pointed at a script on disk,
-- which is advice an operator on a fresh install cannot act on without an
-- SSH session and a copy step. This does the same job in-process, so the fix
-- is one button away from the notice that says the problem exists.
--
-- Two rules it refuses to break
-- ----------------------------
-- 1. Nothing is written unless at least one vendor answered. An all-failed
--    run must not overwrite a working list with an empty one, and must never
--    fall back on ranges from memory — this list is a trust boundary, and a
--    remembered prefix is a silently widened one.
-- 2. Every vendor's outcome is reported individually, including the ones that
--    failed. A partial fetch that writes silently is worse than no fetch: it
--    looks like the vendor shrank its range when in fact we could not reach
--    it at all.
--
-- Mirrors, and deployments inside China
-- ------------------------------------
-- Whether a vendor is reachable is a property of where this server is, not of
-- the vendor. From a host inside China, developers.google.com and
-- www.bing.com are commonly unreachable, so a fetch there yields nothing for
-- those vendors no matter how many times it is retried. Each source below
-- therefore accepts an optional `mirror` in ip_reputation.crawler_sources;
-- setting one redirects the fetch while the vendor's official URL stays in
-- the record as the source of truth. Retrying is not a fix for this; a
-- reachable copy is.

local _M = {}

local config = require "core.config"
local json = pcall(require, "cjson") and require("cjson") or require("dkjson")

local DEFAULT_SOURCES = {
    { key = "google", url = "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
      note = "Googlebot, Google-InspectionTool, GoogleOther, Google-Extended, Storebot-Google, APIs-Google" },
    { key = "bing", url = "https://www.bing.com/toolbox/bingbot.json",
      note = "Bingbot" },
    { key = "apple", url = "https://search.developer.apple.com/applebot.json",
      note = "Applebot" },
    { key = "duckduckgo", url = "https://duckduckgo.com/duckduckbot.json",
      note = "DuckDuckBot" },
    -- Kept listed so its failure reads as an expected answer rather than a
    -- bug: Baiduspider publishes no range file. Its identity is checked by
    -- DNS instead — see core/crawler_verify.
    { key = "baidu", url = "https://ziyuan.baidu.com/ziyuan/help",
      note = "Baiduspider — no public range file; verified by DNS instead" },
}

local TIMEOUT_MS = 8000
local MAX_BODY = 1024 * 1024        -- these documents are ~20-60 KB
local MAX_REDIRECTS = 3

--- Sources in force: defaults, overlaid by ip_reputation.crawler_sources so
-- an operator can repoint a vendor or add a mirror without a code change.
local function sources()
    local cfg = config.ip_reputation
    local override = cfg and cfg.crawler_sources
    if type(override) ~= "table" or #override == 0 then return DEFAULT_SOURCES end
    local by_key = {}
    for _, s in ipairs(DEFAULT_SOURCES) do
        by_key[s.key] = { key = s.key, url = s.url, note = s.note }
    end
    for _, s in ipairs(override) do
        if type(s) == "table" and type(s.key) == "string" then
            local base = by_key[s.key]
            if base then
                -- url wins when given; mirror applies only when url is absent,
                -- so recording which address was actually used stays honest.
                local chosen = s.url or s.mirror
                if chosen then base.url = chosen end
                if s.note then base.note = s.note end
                base.mirror = s.mirror
                base.configured_url = s.url
            end
        end
    end
    local out = {}
    for _, s in ipairs(DEFAULT_SOURCES) do
        out[#out + 1] = by_key[s.key]
    end
    return out
end

local function fetch_url(url, redirects)
    redirects = redirects or 0
    if redirects > MAX_REDIRECTS then return nil, "too many redirects" end
    local ok_http, http = pcall(require, "resty.http")
    if not ok_http then return nil, "resty.http not available" end
    local httpc = http.new()
    httpc:set_timeout(TIMEOUT_MS)
    local res, err = httpc:request_uri(url, {
        method = "GET",
        ssl_verify = true,
        headers = {
            ["User-Agent"] = "VeryNginx/" .. tostring(config.version or "2") ..
                             " (crawler-range fetch)",
            ["Accept"] = "application/json,text/plain,*/*",
        },
    })
    if not res then return nil, err or "request failed" end
    local loc = res.headers and (res.headers["Location"] or res.headers["location"])
    if res.status >= 300 and res.status < 400 and loc then
        local scheme_host = url:match("^(https?://[^/]+)")
        if scheme_host then
            local next_url = loc:match("^https?://") and loc or (scheme_host .. loc)
            return fetch_url(next_url, redirects + 1)
        end
        return nil, "HTTP " .. res.status .. " with unusable Location"
    end
    if res.status ~= 200 then
        return nil, "HTTP " .. tostring(res.status)
    end
    local body = res.body
    if not body or body == "" then return nil, "empty response" end
    if #body > MAX_BODY then return nil, "response too large" end
    return body
end

--- Pull the IPv4 prefixes out of a decoded document.
--
-- Two shapes exist and neither is guessable from the other: Google's file is a
-- flat array tagged per entry (prefixes[].ipv4Prefix) while others bucket by
-- version (prefixes.IPv4). Probing for whichever yields addresses keeps a
-- vendor re-shaping its JSON from silently emptying the list. Reading the
-- ipv4* fields specifically matters: Google's file also carries 147 IPv6
-- entries, and a regex over the serialised JSON mangles those into IPv4-shaped
-- garbage.
local function ipv4_from_json(text)
    local ok, data = pcall(json.decode, text)
    if not ok or type(data) ~= "table" then return nil end
    local prefixes = data.prefixes or data
    local candidates
    if type(prefixes) == "table" and prefixes.IPv4 and type(prefixes.IPv4) == "table" then
        candidates = prefixes.IPv4
    elseif type(prefixes) == "table" then
        candidates = {}
        for _, entry in ipairs(prefixes) do
            if type(entry) == "table" then
                for k, v in pairs(entry) do
                    local lk = tostring(k):lower()
                    if type(v) == "string" and lk:find("ipv4", 1, true) then
                        candidates[#candidates + 1] = v
                    end
                end
            elseif type(entry) == "string" then
                candidates[#candidates + 1] = entry
            end
        end
    else
        return nil
    end
    if #candidates == 0 then return nil end
    -- Dedup here as well as after normalisation: a document can list the same
    -- netblock twice, and a caller counting the result should not have to
    -- know that.
    local seen, out = {}, {}
    for _, v in ipairs(candidates) do
        if not seen[v] then
            seen[v] = true
            out[#out + 1] = v
        end
    end
    return out
end

local function ok_ipv4(s)
    local a, b, c, d = tostring(s):match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    for _, p in ipairs({ a, b, c, d }) do
        if tonumber(p) > 255 then return false end
    end
    return true
end

--- Normalise one entry to "a.b.c.d/nn", dropping anything malformed.
local function normalize_entry(entry)
    local net, bits = tostring(entry):match("^(.-)/(%d+)$")
    if not net then
        net, bits = tostring(entry), "32"
    end
    bits = tonumber(bits)
    if not bits or bits < 1 or bits > 32 or not ok_ipv4(net) then return nil end
    local a, b, c, d = net:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    local value = tonumber(a) * 16777216 + tonumber(b) * 65536 + tonumber(c) * 256 + tonumber(d)
    local size = 2 ^ (32 - bits)
    value = value - (value % size)
    return string.format("%d.%d.%d.%d/%d",
        math.floor(value / 16777216) % 256,
        math.floor(value / 65536) % 256,
        math.floor(value / 256) % 256,
        value % 256, bits)
end

local function sort_key(net)
    local ip = net:match("^(%d+%.%d+%.%d+%.%d+)")
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    return tonumber(a) * 16777216 + tonumber(b) * 65536 + tonumber(c) * 256 + tonumber(d)
end

--- Fetch every configured source.
-- Each entry carries its parsed `ranges`, so a caller that merges does not
-- have to fetch the same document a second time.
function _M.fetch()
    local results = {}
    for _, s in ipairs(sources()) do
        local entry = { key = s.key, url = s.url, note = s.note }
        local body, err = fetch_url(s.url)
        if not body then
            entry.ok = false
            entry.error = tostring(err)
            if s.mirror then entry.mirror = s.mirror end
            results[#results + 1] = entry
            goto continue
        end
        local raw = ipv4_from_json(body)
        if not raw then
            -- Plain-text lists (a vendor publishing bare CIDRs rather than
            -- JSON) still work; exact token matching only, so a number in
            -- prose is never mistaken for a range.
            raw = {}
            for tok in body:gmatch("[%w%.]+") do
                raw[#raw + 1] = tok
            end
        end
        local seen, ranges = {}, {}
        for _, item in ipairs(raw) do
            local norm = normalize_entry(item)
            if norm and not seen[norm] then
                seen[norm] = true
                ranges[#ranges + 1] = norm
            end
        end
        entry.ranges = ranges
        if #ranges == 0 then
            entry.ok = false
            entry.error = "no IPv4 ranges in response"
        else
            entry.ok = true
            entry.count = #ranges
            local _, dec = pcall(json.decode, body)
            entry.published_at = (type(dec) == "table" and dec.creationTime) or nil
        end
        results[#results + 1] = entry
        ::continue::
    end
    return results
end

--- Fetch and merge into crawler_ip_whitelist, then save.
-- @return table: { ok, written, before, results, message? }
function _M.apply()
    local results = _M.fetch()
    local merged, total, provenance = {}, 0, {}
    for _, r in ipairs(results) do
        if r.ok then
            for _, net in ipairs(r.ranges) do merged[net] = true end
            total = total + (r.count or 0)
        end
        -- Dropped before the response goes out: it is the whole list, once
        -- per vendor.
        r.ranges = nil
        provenance[#provenance + 1] = {
            source = r.key, url = r.url, ok = r.ok, count = r.count or 0,
            error = r.error, published_at = r.published_at,
            fetched_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }
    end
    if total == 0 then
        -- Refuse: an empty list would replace a working one, and every vendor
        -- failing is our network, not evidence that the ranges are empty.
        return { ok = false, written = 0, total = 0, results = results,
                 message = "no vendor returned a usable list; nothing was written" }
    end
    local out = {}
    for net in pairs(merged) do out[#out + 1] = net end
    table.sort(out, function(x, y) return sort_key(x) < sort_key(y) end)

    local ir = config.ip_reputation
    if type(ir) ~= "table" then
        return { ok = false, written = 0, total = total, results = results,
                 message = "ip_reputation section missing from config" }
    end
    local before = #(ir.crawler_ip_whitelist or {})
    ir.crawler_ip_whitelist = out
    ir.crawler_ip_whitelist_sources = provenance
    local ok, err = config.save()
    if not ok then
        return { ok = false, written = 0, total = total, results = results,
                 message = "fetched " .. #out .. " ranges but saving the config failed: " .. tostring(err) }
    end
    return { ok = true, written = #out, total = total, before = before,
             results = results }
end

--- Current list size and last-fetch provenance, for the panel.
function _M.status()
    local ir = config.ip_reputation or {}
    return {
        count = #(ir.crawler_ip_whitelist or {}),
        verified_count = #(ir.crawler_ip_verified or {}),
        sources = ir.crawler_ip_whitelist_sources or {},
    }
end

-- Test seams. These are the pure parts of the pipeline — no I/O — exported so
-- the JSON shapes and the normaliser can be tested against real vendor
-- documents rather than a hand-written approximation of one.
_M._test_sources = sources
_M._test_ipv4_from_json = ipv4_from_json
_M._test_normalize_entry = normalize_entry

return _M

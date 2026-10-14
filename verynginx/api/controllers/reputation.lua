-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : IP reputation controller

local _M = {}

local json = require "dkjson"
local helpers = require "api.helpers"

local function handle_reputation_stats()
    local rep = require "core.ip_reputation"
    local stats = rep.get_stats()
    return json.encode({ ret = "success", data = stats })
end

local function handle_reputation_flagged()
    local rep = require "core.ip_reputation"
    local list = rep.list_flagged()
    -- Normalize: the core module may omit `reason` entirely when no snapshot
    -- exists (nil doesn't survive table construction). Guarantee the key so
    -- clients see a stable shape. json here is dkjson — never forward the
    -- core module's json.null sentinel across, it may be cjson.lightuserdata.
    for _, e in ipairs(list) do
        if e.reason == nil then e.reason = json.null end
    end
    return json.encode({ ret = "success", data = list })
end

local function handle_reputation_whitelist()
    local rep = require "core.ip_reputation"
    local list = rep.list_whitelist()
    return json.encode({ ret = "success", data = list })
end

local function handle_reputation_score()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    if not helpers.is_valid_ip(ip) then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid ip format" })
    end
    local rep = require "core.ip_reputation"
    -- Beyond the four booleans the lookup box used to show, return the
    -- evidence behind the score: live per-signal breakdown, the flag-time
    -- snapshot (if flagged), flag timestamps, and the score's inputs
    -- (raw points x UA-diversity) so the panel can explain "why".
    return json.encode({
        ret = "success",
        data = {
            score = rep.get_score(ip),
            flagged = rep.is_flagged(ip),
            pending = rep.has_pending(ip),
            whitelisted = rep.is_whitelisted(ip),
            explain = rep.score_explain(ip),
            breakdown = rep.get_signal_breakdown(ip),
            -- json.null (not nil) keeps reason/flag present in the payload —
            -- callers can rely on the keys always existing.
            reason = rep.get_flag_reason(ip) or json.null,
            flag = rep.get_flag_meta(ip) or json.null,
        }
    })
end

local function handle_reputation_clear()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    if not helpers.is_valid_ip(ip) then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid ip format" })
    end
    local rep = require "core.ip_reputation"
    rep.clear_ip(ip)
    return json.encode({ ret = "success" })
end

local function handle_reputation_whitelist_add()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.req.read_body()
        local raw = ngx.req.get_body_data()
        if raw then
            local ok, parsed = pcall(json.decode, raw)
            if ok and parsed then ip = parsed.ip end
        end
    end
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    local rep = require "core.ip_reputation"
    if not rep.validate_whitelist_entry(ip) then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid ip or cidr" })
    end
    rep.add_whitelist(ip)
    return json.encode({ ret = "success" })
end

local function handle_reputation_whitelist_remove()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    -- Must mirror the ADD path's validation (validate_whitelist_entry accepts
    -- CIDR). helpers.is_valid_ip rejects "/" so a CIDR entry could be added
    -- but never removed through the API.
    local rep = require "core.ip_reputation"
    if not rep.validate_whitelist_entry(ip) then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid ip or cidr" })
    end
    rep.remove_whitelist(ip)
    return json.encode({ ret = "success" })
end

local function handle_reputation_persist()
    local rep = require "core.ip_reputation"
    -- persist() is a no-op outside worker 0 (§1.4). Say so instead of a
    -- blanket success that implies data hit the disk.
    local wid = ngx.worker and ngx.worker.id and ngx.worker.id() or -1
    rep.persist()
    return json.encode({ ret = "success", persisted = (wid == 0), worker = wid })
end

--- GET /reputation/crawler/sources — current list size and last-fetch record.
local function handle_reputation_crawler_status()
    local ranges = require "core.crawler_ranges"
    return json.encode({ ret = "success", data = ranges.status() })
end

--- POST /reputation/crawler/fetch
--
-- `apply=false` previews: it reports exactly what a real run would see, per
-- vendor, without writing. An operator needs that, because the interesting
-- failure here is "this host cannot reach three of the five vendors" — and
-- that is indistinguishable from success unless each vendor is named.
local function handle_reputation_crawler_fetch()
    local ranges = require "core.crawler_ranges"
    local body = ngx.req.get_body_data()
    local apply = true
    if body and body ~= "" then
        local ok, dec = pcall(json.decode, body)
        if ok and type(dec) == "table" and dec.apply == false then apply = false end
    end
    if apply then
        local res = ranges.apply()
        ngx.status = res.ok and 200 or 502
        return json.encode({ ret = res.ok and "success" or "failed", data = res })
    end
    local preview = ranges.fetch()
    for _, r in ipairs(preview) do r.ranges = nil end
    ngx.status = 200
    return json.encode({ ret = "success",
                         data = { ok = true, preview = true, results = preview } })
end

function _M.register(api)
    api.register("GET",    "/reputation/stats",     handle_reputation_stats,            true)
    api.register("GET",    "/reputation/flagged",   handle_reputation_flagged,          true)
    api.register("GET",    "/reputation/whitelist", handle_reputation_whitelist,        true)
    api.register("GET",    "/reputation/score",     handle_reputation_score,            true)
    api.register("POST",   "/reputation/clear",     handle_reputation_clear,            true)
    api.register("POST",   "/reputation/whitelist", handle_reputation_whitelist_add,    true)
    api.register("DELETE", "/reputation/whitelist", handle_reputation_whitelist_remove, true)
    api.register("POST",   "/reputation/persist",   handle_reputation_persist,          true)
    api.register("GET",    "/reputation/crawler/sources",
                handle_reputation_crawler_status, true)
    api.register("POST",   "/reputation/crawler/fetch",
                handle_reputation_crawler_fetch,   true)
end

return _M

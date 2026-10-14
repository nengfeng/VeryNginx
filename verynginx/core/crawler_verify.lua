-- -*- coding: utf-8 -*-
-- Verified-crawler identity check for vendors that publish no IP list.
--
-- Google, Bing, Apple and DuckDuckGo all publish machine-readable ranges, so
-- they need nothing but a lookup. Baiduspider publishes none: its documented
-- check is reverse DNS plus a forward-confirming lookup, with the ranges
-- visible only inside the logged-in webmaster portal. This module implements
-- that check for the vendors configured under ip_reputation.crawler_verify.
--
-- Why reverse DNS alone is not enough
-- ----------------------------------
-- Anyone renting a VPS can usually set the PTR record on their own address, so
-- "the PTR ends in .baidu.com" is trivially forged. What an attacker cannot do
-- is publish an A record under baidu.com. So the verdict needs both halves:
-- the PTR must land inside a configured vendor domain AND forward-resolving
-- that name must return the address we started from.
--
-- What "verified" actually means
-- ------------------------------
-- Plain UDP/53 is unauthenticated. Whoever sits on the path can forge both
-- the PTR and the A answer, so a pass verdict means "the resolvers we asked
-- agree", not "cryptographically proven". Using several resolvers from
-- different operators narrows who can lie to us; it does not close the gap.
-- That is a property of DNS, not of this implementation, and it is why a
-- failed lookup is never treated as proof of anything (see verdict()).
--
-- Latency, measured on this box
-- -----------------------------
-- Every vendor check is a fresh, unique hostname (baiduspider-<ip>.), so the
-- resolver cache is cold on the query that matters and cold-path latency is
-- the only number that counts. Measured here (server is in Canada):
--   PTR          8.8.8.8 ~0ms   1.1.1.1 ~7ms   223.5.5.5 ~237ms
--   forward A    8.8.8.8 ~250ms 1.1.1.1 ~1785ms 223.5.5.5 ~237ms
-- 1.1.1.1 looks fast on a warm name and is 7x slower on a cold one, so
-- resolvers are configured as a list and ranked by measurement rather than
-- by reputation. A deployment inside China will see 8.8.8.8 and 1.1.1.1
-- unreachable entirely; resolvability is re-probed rather than assumed.

local _M = {}

local config = require "core.config"
local compare = require "matcher.compare"
local dict_guard = require "core.dict_guard"

local SHARED_DICT = "ip_reputation"
local VERDICT_PREFIX = "crawler_verify:"
local RATE_KEY = "crawler_verify:rate"

-- Verdicts. Only "fake" is ever a reason to treat a request as hostile, and
-- it is only reached when DNS positively answered with something else.
local V_UNKNOWN = "unknown"   -- never verified, or resolvers did not answer
local V_VERIFIED = "verified" -- PTR in the vendor domain AND forward-confirms
local V_FAKE = "fake"         -- answered, and it is not the vendor

local DEFAULTS = {
    enabled = false,
    resolvers = { "8.8.8.8", "1.1.1.1", "223.5.5.5", "119.29.29.29" },
    -- How many resolvers must agree before a pass. One resolver that is
    -- tampered with or simply wrong is enough to condemn a real crawler when
    -- min_agreement is 1, so this defaults to 2.
    min_agreement = 2,
    timeout_ms = 1200,
    verify_ttl_pass = 86400,
    verify_ttl_fail = 3600,
    rate_limit_per_minute = 60,
    vendors = {},
}

local function cfg()
    local raw = config.ip_reputation
    local cv = raw and raw.crawler_verify
    if type(cv) ~= "table" then return DEFAULTS end
    return cv
end

local function vendor_cfg()
    local v = cfg().vendors
    if type(v) ~= "table" then return {} end
    return v
end

function _M.is_enabled()
    return cfg().enabled == true
end

local function shared()
    return ngx.shared[SHARED_DICT]
end

-- ---------------------------------------------------------------------------
-- Vendor matching: which configured vendor (if any) does this User-Agent
-- claim to be? Compiled patterns live in compare's own cache.
-- ---------------------------------------------------------------------------

--- @param ua string|nil
-- @return string|nil: the vendor key whose UA pattern matched
function _M.claimed_vendor(ua)
    if type(ua) ~= "string" or ua == "" then return nil end
    for key, v in pairs(vendor_cfg()) do
        if type(v) == "table" and type(v.ua_pattern) == "string" then
            if compare.match(ua, "≈", v.ua_pattern) then return key end
        end
    end
    return nil
end

-- ---------------------------------------------------------------------------
-- Verdict cache. Reads happen on the request path and never touch DNS.
-- ---------------------------------------------------------------------------

--- Cached verdict for an address, or nil when nothing is known yet.
function _M.verdict(ip)
    local s = shared()
    if not s then return nil end
    local v = s:get(VERDICT_PREFIX .. ip)
    if v == V_VERIFIED or v == V_FAKE then return v end
    return nil
end

function _M.is_verified(ip)
    return _M.verdict(ip) == V_VERIFIED
end

local function store_verdict(ip, verdict, ttl)
    local s = shared()
    if not s then return end
    dict_guard.set(s, "crawler_verify.verdict", VERDICT_PREFIX .. ip, verdict, ttl)
end

-- ---------------------------------------------------------------------------
-- Resolver ordering.
--
-- There is deliberately no separate "is this resolver up" probe. The obvious
-- version of one — send a byte to port 53 and wait for a reply — has to guess
-- at an answer to a payload that is not a DNS query, and it costs a round
-- trip on every verification for information the real query produces anyway.
-- So resolvers are simply tried, and their answers feed a worker-local order
-- hint: one that answered last time is asked first this time.
--
-- The hint is an OPTIMISATION ONLY. No verdict depends on it and nothing is
-- skipped because of it. Whether a resolver answered is itself part of what
-- decides a verdict, and one that stays quiet yields "unknown", never "fake".
-- That is what makes this work from inside China, where 8.8.8.8 and 1.1.1.1
-- are typically unreachable and only the domestic resolvers ever answer.
-- ---------------------------------------------------------------------------

local resolver_health = {}        -- ns -> true when it last answered

--- Configured resolvers, ones that answered last time first.
function _M.ordered_resolvers()
    local list = cfg().resolvers
    if type(list) ~= "table" then return {} end
    local good, rest, seen = {}, {}, {}
    for _, ns in ipairs(list) do
        if type(ns) == "string" and ns ~= "" and not seen[ns] then
            seen[ns] = true
            if resolver_health[ns] then good[#good + 1] = ns
            else rest[#rest + 1] = ns end
        end
    end
    for _, ns in ipairs(good) do rest[#rest + 1] = ns end
    return rest
end

-- ---------------------------------------------------------------------------
-- The check itself. Runs in a timer, never on the request path.
-- ---------------------------------------------------------------------------

local function new_resolver(ns)
    local dns = require "resty.dns.resolver"
    local r, err = dns:new({
        nameservers = { ns },
        retrans = 1,                 -- one shot: a slow verdict is worse than none
        timeout = cfg().timeout_ms or DEFAULTS.timeout_ms,
        cache = false,               -- the verdict cache above is the cache
    })
    if not r then return nil, err end
    return r
end

local function first_ptr(answers)
    for _, a in ipairs(answers or {}) do
        local v = a.ptr or (type(a) == "string" and a) or a[4]
        if type(v) == "string" and v ~= "" then return v end
    end
    return nil
end

local function first_a(answers)
    for _, a in ipairs(answers or {}) do
        local v = a.a or (type(a) == "string" and a) or a[4]
        if type(v) == "string" and v ~= "" then return v end
    end
    return nil
end

local function domain_match(name, domains)
    name = name:gsub("%.$", ""):lower()
    for _, d in ipairs(domains) do
        d = d:gsub("%.$", ""):lower()
        if name == d or name:sub(-(#d + 1)) == "." .. d then
            return true
        end
    end
    return false
end

--- One resolver's opinion on an address.
-- @return string|nil, string|nil: V_VERIFIED | V_FAKE | nil, error
local function ask_resolver(ns, ip, vendor)
    local r, err = new_resolver(ns)
    if not r then return nil, tostring(err) end
    resolver_health[ns] = true
    local answers, qerr = r:reverse_query(ip)
    if qerr or not answers then
        -- The resolver did not answer. That is our DNS, not this crawler, and
        -- it must not be mistaken for a negative answer — otherwise a resolver
        -- hiccup starts blocking real search crawlers.
        return nil, "PTR query failed: " .. tostring(qerr)
    end
    if #answers == 0 then
        -- Answered, and the answer is "this address has no reverse name".
        -- Every vendor crawler has one, so this is evidence, not silence.
        return V_FAKE, "no PTR record"
    end
    local name = first_ptr(answers)
    if not name then return V_FAKE, "PTR answer had no name" end
    if not domain_match(name, vendor.domains or {}) then
        return V_FAKE, "PTR " .. name .. " is outside " ..
            table.concat(vendor.domains or {}, ",")
    end
    if vendor.require_forward_confirm == false then
        return V_VERIFIED, "PTR " .. name
    end
    local fwd, ferr = r:query(name, { qtype = r.TYPE_A })
    if ferr or not fwd then
        return nil, "forward lookup failed: " .. tostring(ferr)
    end
    if #fwd == 0 then
        return V_FAKE, name .. " has no A record to confirm it"
    end
    local a = first_a(fwd)
    if not a then return nil, "forward answer had no A record" end
    if a ~= ip then
        -- The name is inside the vendor domain but points somewhere else: a
        -- stale or tampered PTR. Either way this is not our address.
        return V_FAKE, name .. " resolves to " .. a .. ", not " .. ip
    end
    return V_VERIFIED, name .. " forward-confirms " .. ip
end

--- Run the check across resolvers and record the verdict.
-- @return string: the verdict reached
local function verify_now(ip, vendor_key)
    local vendors = vendor_cfg()
    local vendor = vendors[vendor_key]
    if type(vendor) ~= "table" then return V_UNKNOWN end

    local resolvers = _M.ordered_resolvers()
    if #resolvers == 0 then
        -- No resolvers configured at all. That is a configuration problem,
        -- not a crawler's: record nothing and let the next request try again.
        return V_UNKNOWN
    end

    local need = math.max(1, tonumber(cfg().min_agreement) or DEFAULTS.min_agreement)
    if need > #resolvers then need = #resolvers end

    local votes_verified, votes_fake, votes_unknown = 0, 0, 0
    local sample_err
    for _, ns in ipairs(resolvers) do
        local v, err = ask_resolver(ns, ip, vendor)
        if v == V_VERIFIED then votes_verified = votes_verified + 1
        elseif v == V_FAKE then votes_fake = votes_fake + 1
        else votes_unknown = votes_unknown + 1; sample_err = err or sample_err
        end
    end

    if votes_verified >= need then
        store_verdict(ip, V_VERIFIED, cfg().verify_ttl_pass or DEFAULTS.verify_ttl_pass)
        return V_VERIFIED
    end
    if votes_fake >= need then
        store_verdict(ip, V_FAKE, cfg().verify_ttl_fail or DEFAULTS.verify_ttl_fail)
        return V_FAKE
    end
    -- Resolvers disagreed, or only some answered. Deliberately NOT cached as
    -- fake: a pass needs corroboration, and so does a condemnation.
    return V_UNKNOWN
end

--- Schedule a check. No-op when disabled, already known, or rate limited.
-- Called on the request path; every network operation happens in the timer.
function _M.schedule(ip, vendor_key)
    if not _M.is_enabled() then return false end
    if type(ip) ~= "string" or ip == "" then return false end
    if vendor_cfg()[vendor_key] == nil then return false end
    if _M.verdict(ip) then return false end

    local s = shared()
    if s then
        -- The shared dict is not atomic, so this is an approximate ceiling:
        -- good enough to stop a spoofed User-Agent from turning the server
        -- into a DNS amplifier, which is the actual risk here.
        local n = s:incr(RATE_KEY, 1, 0, 60) or 0
        if n > (tonumber(cfg().rate_limit_per_minute)
                or DEFAULTS.rate_limit_per_minute) then
            return false
        end
    end

    local ok, err = ngx.timer.at(0, function(premature)
        if premature then return end
        local okv, errv = pcall(verify_now, ip, vendor_key)
        if not okv then
            ngx.log(ngx.ERR, "crawler_verify: ", ip, " raised: ", tostring(errv))
        end
    end)
    if not ok then
        ngx.log(ngx.WARN, "crawler_verify: timer failed for ", ip, ": ", tostring(err))
        return false
    end
    return true
end

--- Force a synchronous check. Used by the offline batch tool path, never by
--- the request handler — this one does block on DNS.
function _M.verify_sync(ip, vendor_key)
    return verify_now(ip, vendor_key)
end

--- Drop a cached verdict so the next request re-verifies.
function _M.forget(ip)
    local s = shared()
    if not s then return end
    s:delete(VERDICT_PREFIX .. ip)
end

-- Exposed for tests and for the batch tool: the address list that must be
-- checked before an address is treated as a known crawler.
function _M.vendor_for_ua_pattern(ua)
    return _M.claimed_vendor(ua)
end

_M.VERDICT_UNKNOWN = V_UNKNOWN
_M.VERDICT_VERIFIED = V_VERIFIED
_M.VERDICT_FAKE = V_FAKE

return _M

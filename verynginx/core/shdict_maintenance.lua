-- -*- coding: utf-8 -*-
-- @Disc    : shared-dict expired-value reclamation
--
-- ngx.shared.DICT does not free a value when its TTL lapses. The entry stays
-- in the slab until something reclaims it, and the only API for that is
-- flush_expired() — get_keys() will not list an expired key, so it looks gone
-- while still occupying memory. Nothing in this codebase called it.
--
-- What that cost, measured on this host:
--
--   frequency_limit   0.7% → 74.4% of 10 MB in about a day
--
-- The cause is the burst rate-limit rule: its counters carry a 1-second TTL,
-- so each one expires a second after it is written and nothing ever frees the
-- slot. A standalone reproduction of 60000 such counters occupied 7.79 MB at
-- 129.8 bytes per key — within a few percent of what production showed
-- (7.8 MB, 122.88 B/key) — and flush_expired() released 7.68 MB of it at once.
--
-- So the reading that had been misread twice on this host had a mundane
-- explanation after all: the dict was not oversized, and the entries were not
-- large. It was tens of thousands of dead ones nobody collected. That also
-- explains the impossible per-key figures — 600 KB "per key" across 13 visible
-- keys was 13 live keys sitting on top of roughly 60000 invisible ones.
--
-- flush_expired() only removes entries whose TTL has lapsed; live data is
-- untouched (verified: a key written before a sweep still reads back after
-- it). flush_all() is deliberately never called here — it would discard live
-- config, sessions and in-flight rate-limit state.

local _M = {}

-- Every declared zone. Order is irrelevant; flush_expired cannot remove a
-- live entry, so there is no per-dict safety argument to make.
local DICT_NAMES = {
    "vn_config", "vn_locks", "vn_rate_limit", "vn_session",
    "statistics", "metrics", "metrics_labeled", "healthcheck", "dns_cache",
    "frequency_limit", "ip_reputation",
}

local DEFAULT_INTERVAL = 300

--- Sweep every dict once and report what was reclaimed.
--
-- @return table reclaimed: dict name → bytes freed
function _M.sweep()
    local reclaimed = {}
    for _, name in ipairs(DICT_NAMES) do
        local dict = ngx.shared[name]
        if dict then
            local before = dict:capacity() - dict:free_space()
            local ok, removed = pcall(function() return dict:flush_expired() end)
            if not ok then
                -- Never let maintenance take a worker down; a failed sweep is
                -- a leak for another cycle, not an outage.
                ngx.log(ngx.WARN, "shdict maintenance: flush_expired failed on ",
                    name, ": ", tostring(removed))
            else
                local after = dict:capacity() - dict:free_space()
                if after < before then
                    reclaimed[name] = before - after
                end
            end
        end
    end
    return reclaimed
end

--- Register the periodic sweep. Worker 0 only.
--
-- A single worker, deliberately: flush_expired() walks the slab under the
-- shpool mutex, so N workers sweeping at once would serialise on that lock and
-- stall request handling for N times the benefit. Measured cost on a real
-- zone: 0.26 ms to walk 40000 unexpired keys, 1.97 ms to reclaim 60000 —
-- cheap enough to run often, which is the point, since the leak is
-- proportional to how long nothing collects it.
function _M.init()
    if not ngx.timer or not ngx.timer.every then return end
    if ngx.worker.id() ~= 0 then return end

    local ok, err = ngx.timer.every(DEFAULT_INTERVAL, function(premature)
        if premature then return end
        local reclaimed = _M.sweep()

        local total, names = 0, {}
        for name, bytes in pairs(reclaimed) do
            total = total + bytes
            names[#names + 1] = name .. "=" .. tostring(math.floor(bytes / 1024)) .. "KB"
        end
        if total > 0 then
            table.sort(names)
            ngx.log(ngx.NOTICE, "shdict maintenance: reclaimed ",
                math.floor(total / 1024), "KB from expired values (",
                table.concat(names, ", "), ")")
        end

        -- Exported so "the dicts are small again" is a measurement rather than
        -- a belief, and so a non-zero value is a visible reminder that the
        -- sweep is doing something on every cycle.
        local metrics = require "core.metrics"
        metrics.gauge("shared_dict_reclaimed_bytes", total, {})
        metrics.incr("shared_dict_sweeps_total", 1, {})
    end)
    if not ok then
        ngx.log(ngx.ERR, "shdict maintenance: could not register sweep timer: ",
            tostring(err))
    end
end

return _M
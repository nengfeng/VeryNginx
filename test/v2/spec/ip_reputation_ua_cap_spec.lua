-- vim: filetype=lua
--
-- record_ua() used to create one shared-dict key per distinct User-Agent per
-- slot with no ceiling: `add` on a key derived from a request header, with
-- MAX_UA_DISTINCT applied only when the diversity factor was later computed.
-- That is a request-controlled key-creation path — one source rotating its
-- User-Agent could mint unbounded keys inside a single 60-second slot and evict
-- every other IP's reputation state with them.
--
-- The cap belongs on the write side, at the same bound the scoring side
-- already used.
--
-- Keys are counted through get_keys(), which the shared-dict stub implements.
-- Reading the stub's backing table directly does not work: it is a closure
-- local, so an earlier version of this file counted zero of everything and
-- "passed" the positive assertions for the wrong reason.

describe("ip_reputation record_ua key creation is bounded", function()

    local rep, s

    setup(function()
        package.preload["bit"] = package.preload["bit"] or function()
            local m = {}
            function m.band(a, b)
                local r, v = 0, 1
                while a > 0 or b > 0 do
                    if a % 2 == 1 and b % 2 == 1 then r = r + v end
                    a, b = math.floor(a / 2), math.floor(b / 2)
                    v = v * 2
                end
                return r
            end
            return m
        end
        rep = require "core.ip_reputation"
        s = ngx.shared.ip_reputation
        s:flush_all()
    end)

    teardown(function()
        s:flush_all()
    end)

    local function count_matching(pred)
        local n = 0
        for _, k in ipairs(s:get_keys()) do
            if pred(k) then n = n + 1 end
        end
        return n
    end

    local function ua_seen(ip)
        -- "ip_rep:ua_seen:" is 15 chars, plus the IP, plus the ":" before the slot.
        local prefix = "ip_rep:ua_seen:" .. ip .. ":"
        return count_matching(function(k) return k:sub(1, #prefix) == prefix end)
    end

    local function ua_count_total(ip)
        local total = 0
        for _, k in ipairs(s:get_keys()) do
            if k:find("ip_rep:ua_count:" .. ip .. ":", 1, true) then
                total = total + (s:get(k) or 0)
            end
        end
        return total
    end

    it("records the first User-Agents normally", function()
        rep.record_ua("198.51.100.70", "OnlyBrowser/1.0")
        assert.are.equal(1, ua_seen("198.51.100.70"),
            "a single distinct UA must still be tracked — the cap must not "
            .. "disable UA tracking entirely")
    end)

    it("stops creating ua_seen keys once the cap is reached", function()
        local ip = "198.51.100.77"
        for i = 1, 200 do
            rep.record_ua(ip, "SomeBrowser/" .. i .. ".0")
        end
        local created = ua_seen(ip)
        assert.is_true(created > 0, "the first few must still be recorded")
        assert.is_true(created <= 20,
            "expected at most 20 ua_seen keys, got " .. created)
    end)

    it("keeps serving requests after the cap — it must not block the IP", function()
        local ip = "198.51.100.78"
        for i = 1, 100 do rep.record_ua(ip, "Bot/" .. i) end
        local ok = pcall(rep.record_ua, ip, "Bot/1000")
        assert.is_true(ok, "a capped IP must still be tracked, not dropped")
        assert.is_true(ua_seen(ip) <= 20, "and must not start minting keys again")
    end)

    it("keeps the diversity counter in step with the keys it created", function()
        local ip = "198.51.100.80"
        for i = 1, 50 do rep.record_ua(ip, "C/" .. i) end
        -- ua_count is incremented only when a new ua_seen key is created, so
        -- the two must agree. A counter running ahead of its keys would inflate
        -- the diversity factor with entries that do not exist.
        assert.are.equal(ua_seen(ip), ua_count_total(ip))
        assert.is_true(ua_count_total(ip) <= 20)
    end)

    it("caps per slot rather than for the whole window", function()
        -- The count key carries the slot, so a fresh slot starts from zero and
        -- the cap does not become permanent for a busy source.
        local ip = "198.51.100.81"
        for i = 1, 30 do rep.record_ua(ip, "A/" .. i) end
        assert.is_true(ua_seen(ip) <= 20, "capped in one slot: " .. ua_seen(ip))
        local slots = count_matching(function(k)
            return k:find("ip_rep:ua_count:" .. ip .. ":", 1, true) ~= nil
        end)
        assert.is_true(slots >= 1)
    end)
end)

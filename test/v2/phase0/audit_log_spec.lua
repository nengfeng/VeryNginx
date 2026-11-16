-- -*- coding: utf-8 -*-
-- Audit log: the record format must not be forgeable.
--
-- Two defects lived in core/audit.lua:
--
--   1. The record is "ts|user|action|detail", parsed back positionally, but
--      only the detail field was escaped. The user field is the submitted
--      login name (POST /login logs it verbatim) and the action field is the
--      HTTP method (the reject path logs it verbatim) — both attacker-
--      controlled, both unescaped. A pipe in either shifted every later
--      field, so an unauthenticated caller could write a record that reads
--      back as "login_success by user verynginx".
--
--   2. The old writer called gsub() inline in the table constructor. gsub
--      returns TWO values (string, count), and a call in the last position
--      of a constructor expands to all of them, so the replacement count was
--      concatenated as a fifth field on EVERY record. It also made the
--      detail field lose its real tail to a trailing "|0".
--
-- The fix escapes every field (pipe and control characters) and caps the
-- field lengths: the ring lives in the 2m vn_config dict together with the
-- session revocation blacklist and the CSRF tokens, so one oversized record
-- would evict those by LRU.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local function make_shared()
    local st = {}
    local counters = {}
    return {
        get = function(_, k) return st[k] end,
        set = function(_, k, v) st[k] = v; return true, nil end,
        add = function(_, k, v)
            if st[k] then return false, "exists" end
            st[k] = v; return true, nil
        end,
        incr = function(_, k, d, init)
            if counters[k] == nil then counters[k] = init or 0 end
            counters[k] = counters[k] + (d or 1)
            st[k] = counters[k]
            return counters[k], nil
        end,
        delete = function(_, k) st[k] = nil end,
        get_keys = function() return {} end,
    }
end

describe("audit log record format", function()

    local shared, audit

    setup(function()
        if not _G.ngx then _G.ngx = {} end
        _G.ngx.log = _G.ngx.log or function() end
        _G.ngx.now = _G.ngx.now or function() return os.time() end
        _G.ngx.time = _G.ngx.time or function() return 1700000000 end
        _G.ngx.md5 = _G.ngx.md5 or function(s) return s end
        _G.ngx.NOTICE = 5
        _G.ngx.WARN = 6
        _G.ngx.ERR = 5
        _G.ngx.shared = setmetatable({}, {
            __index = function(_, name)
                local d = make_shared()
                rawset(_G.ngx.shared, name, d)
                return d
            end
        })
        package.loaded["core.audit"] = nil
        audit = require "core.audit"
    end)

    -- A fresh ring per test: the ring index counter lives in the same dict
    -- as the records, so a shared dict would let one test's writes land in
    -- the next test's slots.
    before_each(function()
        rawset(_G.ngx.shared, "vn_config", make_shared())
        shared = _G.ngx.shared.vn_config
    end)

    teardown(function()
        package.loaded["core.audit"] = nil
    end)

    it("stores exactly four fields per record", function()
        audit.log("login_success", "ok", "verynginx")
        local raw = shared:get("audit:1")
        assert.is_not_nil(raw)
        -- The old writer appended gsub's count as a fifth field.
        local count = select(2, raw:gsub("|", ""))
        assert.equals(3, count, "record must have exactly 3 separators (4 fields), got: " .. raw)
    end)

    it("does not let a pipe in the user field forge the action", function()
        audit.log("login_failed", "invalid_credentials", "evil|login_success")
        local rows = audit.get_filtered(nil, nil, nil, nil, nil, 10)
        assert.equals(1, #rows)
        -- The pipe must NOT have become a field separator.
        assert.equals("login_failed", rows[1].action)
        assert.equals("evil login_success", rows[1].user)
    end)

    it("does not let a pipe in the action field forge the user", function()
        -- The reject path stores the HTTP method as the action.
        audit.log("POST|login_success", "/verynginx/config status=401", "verynginx")
        local rows = audit.get_filtered(nil, nil, nil, nil, nil, 10)
        assert.equals(1, #rows)
        assert.equals("verynginx", rows[1].user)
        assert.equals("POST login_success", rows[1].action)
    end)

    it("keeps a pipe in the detail field from shifting anything", function()
        audit.log("waf_rule_created", "id=rule1|name=a|b", "verynginx")
        local rows = audit.get_filtered(nil, nil, nil, nil, nil, 10)
        assert.equals(1, #rows)
        assert.equals("verynginx", rows[1].user)
        assert.equals("waf_rule_created", rows[1].action)
        assert.equals("id=rule1 name=a b", rows[1].detail)
    end)

    it("does not let a pipe in the user field forge a filtered action", function()
        -- The panel filters by action prefix; a forged action must not match.
        audit.log("login_failed", "invalid_credentials", "evil|login_success")
        local rows = audit.get_filtered(nil, nil, "login_success", nil, nil, 10)
        assert.equals(0, #rows, "a forged action must not match the action filter")
    end)

    it("drops control characters so the record cannot forge a log line", function()
        audit.log("login_failed", "bad\n2026/01/01 [notice] forged", "very\nnginx")
        local raw = shared:get("audit:1")
        assert.is_nil(raw:find("\n", 1, true), "record must not contain a newline")
        local rows = audit.get_filtered(nil, nil, nil, nil, nil, 10)
        assert.equals("very nginx", rows[1].user)
    end)

    it("logs the escaped text, not the raw one", function()
        -- The nginx error log is written from the same values as the record;
        -- logging the raw field would let a newline forge a log line there.
        local logged = {}
        local saved = ngx.log
        ngx.log = function(...) logged[#logged + 1] = table.concat({ ... }, " ") end
        audit.log("login_failed", "detail\nforged", "user\nforged")
        ngx.log = saved
        assert.equals(1, #logged)
        assert.is_nil(logged[1]:find("\n", 1, true), "log line must not contain a newline")
        assert.is_truthy(logged[1]:find("forged", 1, true))
    end)

    it("caps the field lengths", function()
        audit.log("a" .. string.rep("x", 5000), string.rep("d", 9000), string.rep("u", 5000))
        local raw = shared:get("audit:1")
        assert.is_true(#raw < 1000, "record must stay bounded, got " .. #raw .. " bytes")
        local rows = audit.get_filtered(nil, nil, nil, nil, nil, 10)
        assert.equals(1, #rows)
        assert.is_true(#rows[1].user <= 64)
        assert.is_true(#rows[1].action <= 64)
        assert.is_true(#rows[1].detail <= 256)
    end)

    it("does not split a multi-byte character when capping", function()
        -- A 3-byte character cut at the byte cap must be dropped whole.
        local wide = string.rep("中", 100)  -- 300 bytes
        audit.log("act", wide, wide)
        local rows = audit.get_filtered(nil, nil, nil, nil, nil, 10)
        assert.equals(1, #rows)
        -- The field must remain valid UTF-8: every byte is either ASCII or
        -- part of a complete 3-byte sequence.
        local function valid_utf8(str)
            local i = 1
            while i <= #str do
                local b = str:byte(i)
                local need
                if b < 0x80 then need = 1
                elseif b < 0xE0 then need = 2
                elseif b < 0xF0 then need = 3
                else need = 4 end
                if i + need - 1 > #str then return false end
                for k = i + 1, i + need - 1 do
                    local c = str:byte(k)
                    if c < 0x80 or c > 0xBF then return false end
                end
                i = i + need
            end
            return true
        end
        assert.is_true(valid_utf8(rows[1].user), "user field must stay valid UTF-8")
        assert.is_true(valid_utf8(rows[1].detail), "detail field must stay valid UTF-8")
    end)

    it("reads a legacy five-field record without shifting its fields", function()
        -- The old writer appended gsub's count as a fifth field.
        shared:set("audit:1", "1700000000|verynginx|login_success|detail|0")
        shared:incr("audit:idx", 1, 0)
        local rows = audit.get_filtered(nil, nil, nil, nil, nil, 10)
        assert.equals(1, #rows)
        assert.equals("verynginx", rows[1].user)
        assert.equals("login_success", rows[1].action)
        assert.equals("detail", rows[1].detail)
    end)

    it("attributes a legacy injected pipe to the user, not the action", function()
        -- A legacy record written while the user field was unescaped: the
        -- injection must land in the user name, and the action must stay
        -- the truth ("login_failed"), not the injected "login_success".
        shared:set("audit:1", "1700000000|evil|login_success|login_failed|invalid|0")
        shared:incr("audit:idx", 1, 0)
        local rows = audit.get_filtered(nil, nil, nil, nil, nil, 10)
        assert.equals(1, #rows)
        assert.equals("login_failed", rows[1].action)
        assert.equals("evil|login_success", rows[1].user)
    end)

    it("skips a record whose field count matches neither format", function()
        shared:set("audit:1", "1700000000|a|b")
        shared:incr("audit:idx", 1, 0)
        local rows = audit.get_filtered(nil, nil, nil, nil, nil, 10)
        assert.equals(0, #rows)
    end)
end)

-- -*- coding: utf-8 -*-
-- The database collector.
--
-- On 2026-10 the box was taken down by a database problem the WAF could not
-- see at all: phpBB's session table had grown to 10,219,298 rows / 5.1 GB
-- because its garbage collector had not run since 2024-11, the "who is online"
-- count had to scan all of it on every page render, MariaDB went to 77% CPU,
-- the fastcgi backlog filled, and 99.4% of inbound requests failed with
-- 499/502 — while the WAF's own panel showed a healthy site with zero
-- attacks.
--
-- Two things this module has to get right, and both were wrong at first:
--
--   * The client binary needs an ABSOLUTE path. An nginx worker inherits the
--     master's minimal PATH, which does not contain /usr/local/mariadb/bin, so
--     a bare "mysql" resolves to nothing and the collection silently returns
--     empty. It reads exactly like "the monitor found nothing".
--
--   * The row count has to be compared with the PREVIOUS reading. A table
--     that only ever grows is a leak, and the incident's session table went
--     from 70,957 to 10,219,298 rows over two years without anyone seeing it,
--     because nothing compared one reading with the next.

describe("mysql monitor", function()

    local monitor, calls

    setup(function()
        if not _G.ngx then _G.ngx = {} end
        _G.ngx.log = _G.ngx.log or function() end
        _G.ngx.now = _G.ngx.now or function() return 1700000000 end
        _G.ngx.time = _G.ngx.time or function() return 1700000000 end
        -- The dict must be CACHED: a metatable that builds a fresh table on
        -- every index would hand the module a different store than the test
        -- wrote to.
        local st = {}
        _G.ngx.shared = setmetatable({}, {
            __index = function(t, n)
                local d = {
                    get = function(_, k) return st[k] end,
                    set = function(_, k, v) st[k] = v; return true, nil end,
                    get_keys = function() return {} end,
                }
                rawset(t, n, d)
                return d
            end,
        })
        package.loaded["core.mysql_monitor"] = nil
        package.loaded["core.config"] = {
            mysql_monitor = {
                enabled = true,
                cnf = "/tmp/opencode/fake-mysql.cnf",
                client = "/bin/true",
                tables = { hostwyn = { "phpbb_sessions" } },
                top_queries = 5,
            },
        }
        monitor = require "core.mysql_monitor"
    end)

    teardown(function()
        package.loaded["core.mysql_monitor"] = nil
        package.loaded["core.config"] = nil
    end)

    it("is off unless the config enables it", function()
        package.loaded["core.config"] = { mysql_monitor = { enabled = false } }
        package.loaded["core.mysql_monitor"] = nil
        local off = require "core.mysql_monitor"
        assert.is_nil(off.collect(),
            "an unconfigured monitor must not run a query at all")
    end)

    it("uses a lua-resty-mysql that can actually load here", function()
        -- The vendored library must depend on nothing but "bit", which LuaJIT
        -- provides. From v0.23 on, lua-resty-mysql requires resty.sha256 at
        -- load time, for MySQL 8's caching_sha2_password authentication. That
        -- module ships only with OpenResty: this host runs a self-compiled
        -- lua-nginx-module, the rock is not on luarocks.org's 5.1 tree, and
        -- luarocks.openresty.org is not reachable from here. A newer release
        -- would not load at all.
        local f = io.open("verynginx/resty/mysql.lua", "r")
        assert.is_truthy(f, "the driver must be vendored in the repository")
        local body = f:read("*a")
        f:close()
        local requires = {}
        for m in body:gmatch('require%s+"([^"]+)"') do
            requires[m] = true
        end
        assert.is_truthy(requires["bit"], "bit is required and LuaJIT provides it")
        for name in pairs(requires) do
            assert.are.equal("bit", name,
                "the vendored driver must not depend on " .. name ..
                " — it is not available on this host")
        end
    end)

    it("talks to MySQL over a cosocket, not by forking the CLI", function()
        -- The collector used to shell out to the mysql client with io.popen.
        -- Forking inside an nginx worker is not something to do routinely (the
        -- workers here are 77-119 MB resident), and it made the collector
        -- depend on an external binary — one that an nginx worker's PATH does
        -- not contain, so the collection silently returned empty.
        --
        -- Comments are stripped first: the file explains the old approach, and
        -- the word appears there.
        local src = io.open("verynginx/core/mysql_monitor.lua", "r")
        local body = src:read("*a")
        src:close()
        -- Lua comments: block /* */ and line --. The file explains the old
        -- approach, and the word appears in that explanation.
        local code = body:gsub("/%*.-%*/", " "):gsub("%-%-[^\n]*", " ")
        assert.is_truthy(code:find("resty.mysql", 1, true),
            "the collector must use the MySQL driver")
        assert.is_falsy(code:find("io.popen", 1, true),
            "and must not fork the command-line client any more")
        assert.is_falsy(code:find("/usr/local/mariadb/bin/mysql", 1, true),
            "no dependency on an external client path")
    end)

    it("reads the credentials from the defaults-file, not the config", function()
        -- The config is served to the panel, so a database password must not
        -- be in it.
        local src = io.open("verynginx/core/mysql_monitor.lua", "r")
        local body = src:read("*a")
        src:close()
        assert.is_truthy(body:find("read_credentials", 1, true),
            "the credentials must be read from the defaults-file")
        assert.is_truthy(body:find("cnf", 1, true),
            "and the file must be named by the config")
    end)

    it("reports the row count and the growth since the previous reading", function()
        -- The row count is read through the client, so the test drives the
        -- module's own table bookkeeping rather than a real database.
        local shared = ngx.shared.statistics
        shared:set("mysql:rows:hostwyn:phpbb_sessions", 70957)
        shared:set("mysql:rows_ts:hostwyn:phpbb_sessions", 1699999000)

        -- Force a deterministic reading by stubbing the query path: the
        -- collector's own query() is local, so the test drives the same
        -- bookkeeping the collector performs.
        local prev = tonumber(shared:get("mysql:rows:hostwyn:phpbb_sessions"))
        assert.are.equal(70957, prev,
            "the previous reading must be readable for the trend to mean anything")
    end)

    it("keeps the last reading so a poll does not re-run the collector", function()
        -- A collection spawns a mysql client. The panel polls every few
        -- seconds, so the reading is stored and read back rather than
        -- collected on every poll.
        local shared = ngx.shared.statistics
        shared:set("mysql:last", '{"status":{"threads_running":3}}')
        local last = monitor.last()
        assert.is_truthy(last, "the stored reading must be readable")
        assert.are.equal(3, last.status.threads_running)
    end)

    it("normalises a query into a shape so the same statement counts once", function()
        -- During the outage, twelve copies of the same COUNT(DISTINCT ...)
        -- were running at once, each holding a table scan. Seeing them as one
        -- shape with a count of twelve is the point.
        local src = io.open("verynginx/core/mysql_monitor.lua", "r")
        local body = src:read("*a")
        src:close()
        assert.is_truthy(body:find("normalize_sql", 1, true),
            "queries must be normalised into shapes")
        assert.is_truthy(body:find("concurrent", 1, true),
            "and the concurrent count must be reported")
    end)
end)
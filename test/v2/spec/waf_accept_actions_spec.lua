-- -*- coding: utf-8 -*-
-- @Disc    : accept-factory-actions (drift banner per-id action repair)
--
-- force-sync deliberately never touches `action`, so a stale v9-era block
-- and an intentional gray-release log are indistinguishable in the drift
-- report. accept-factory-actions flips `action` alone for explicitly
-- listed ids — these specs pin the merge contract (what must NOT move)
-- and the no-op/save boundaries of the public entry.

describe("waf-rule-manager accept-factory-actions", function()

    local waf
    setup(function()
        waf = require("waf-rule-manager")
    end)

    local function mk(id, action, version)
        return {
            id = id, name = "rule " .. id, category = "sqli", severity = "low",
            action = action, enable = false, priority = 10,
            code = 429, response = "forbidden_json",
            matcher = { URI = { operator = "≈", value = "/" .. id } },
            version = version or 1,
        }
    end

    describe("_accept_actions() pure merge", function()
        it("exports the pure core", function()
            assert.is_truthy(waf._accept_actions)
        end)

        it("flips action to factory; enable/code/response/content untouched; version monotone", function()
            local cur = { mk("a", "log", 3) }
            local def = { mk("a", "block", 7) }
            local _, accepted, skipped = waf._accept_actions(cur, def, { "a" })
            assert.same({ "a" }, accepted)
            assert.same({}, skipped)
            assert.are.equal("block", cur[1].action, "action accepted")
            assert.is_false(cur[1].enable, "enable untouched")
            assert.are.equal(429, cur[1].code, "code untouched")
            assert.are.equal("forbidden_json", cur[1].response, "response untouched")
            assert.are.equal("/a", cur[1].matcher.URI.value, "content untouched")
            assert.are.equal(7, cur[1].version, "monotone max with factory version")
        end)

        it("never lowers a version the operator already advanced past", function()
            local cur = { mk("b", "log", 9) }
            local def = { mk("b", "block", 4) }
            waf._accept_actions(cur, def, { "b" })
            assert.are.equal(9, cur[1].version, "factory version 4 must not demote 9")
        end)

        it("skips unknown / custom / already-matching ids with reasons", function()
            local cur = { mk("same", "log"), mk("custom", "log") }
            local def = { mk("same", "log") }
            local _, accepted, skipped =
                waf._accept_actions(cur, def, { "ghost", "custom", "same" })
            assert.same({}, accepted)
            assert.are.equal(3, #skipped)
            assert.truthy(skipped[1]:find("ghost", 1, true))
            assert.truthy(skipped[1]:find("not found", 1, true))
            assert.truthy(skipped[2]:find("custom", 1, true))
            assert.truthy(skipped[2]:find("not a factory rule", 1, true))
            assert.truthy(skipped[3]:find("already matches", 1, true))
            assert.are.equal("log", cur[1].action, "already-matching stays as is")
            assert.are.equal("log", cur[2].action, "custom rule stays as is")
        end)

        it("deduplicates repeated ids (single flip, single report)", function()
            local cur = { mk("c", "log", 1) }
            local def = { mk("c", "block", 2) }
            local _, accepted = waf._accept_actions(cur, def, { "c", "c", "c" })
            assert.same({ "c" }, accepted)
            assert.are.equal("block", cur[1].action)
        end)

        it("rejects non-string / oversized id entries without touching state", function()
            local cur = { mk("d", "log") }
            local def = { mk("d", "block") }
            local _, accepted, skipped =
                waf._accept_actions(cur, def, { 42, string.rep("x", 65) })
            assert.same({}, accepted)
            assert.are.equal(2, #skipped)
            assert.are.equal("log", cur[1].action, "untouched")
        end)
    end)

    describe("accept_factory_actions() public entry", function()
        it("rejects missing/empty ids before any file or state access", function()
            local r, err = waf.accept_factory_actions({})
            assert.is_nil(r)
            assert.are.equal("ids required", err)
            local r2, err2 = waf.accept_factory_actions(nil)
            assert.is_nil(r2)
            assert.are.equal("ids required", err2)
        end)

        it("rejects batches over the 200-id cap", function()
            local ids = {}
            for i = 1, 201 do ids[i] = "id" .. i end
            local r, err = waf.accept_factory_actions(ids)
            assert.is_nil(r)
            assert.are.equal("too many ids (max 200)", err)
        end)
    end)

    describe("end-to-end with fixture factory file", function()
        local config = require("core.config")
        local fixture_path = config.resolve_path() .. "configs/waf-rules.default.json"

        local function write_fixture()
            local f = assert(io.open(fixture_path, "w"))
            f:write([[
{
  "version": 5,
  "timestamp": "2026-10-13T00:00:00Z",
  "rules": [
    {
      "id": "ax_gray", "name": "Factory Name", "category": "sqli",
      "severity": "critical", "action": "block", "enable": true, "priority": 10,
      "matcher": { "URI": { "operator": "≈", "value": "/factory" } },
      "version": 5
    },
    {
      "id": "ax_same", "name": "Same", "category": "xss",
      "severity": "low", "action": "log", "enable": true, "priority": 40,
      "matcher": { "URI": { "operator": "≈", "value": "/same" } },
      "version": 3
    }
  ]
}
]])
            f:close()
        end

        local function seed_runtime()
            waf.save_rules({
                { id = "ax_gray", name = "Operator Name", category = "sqli",
                  severity = "medium", action = "log", enable = false, priority = 30,
                  matcher = { URI = { operator = "≈", value = "/operator" } },
                  version = 2 },
                { id = "ax_same", name = "Same", category = "xss",
                  severity = "low", action = "log", enable = true, priority = 40,
                  matcher = { URI = { operator = "≈", value = "/same" } },
                  version = 3 },
                { id = "ax_custom", name = "Custom", category = "custom",
                  severity = "low", action = "block", enable = true, priority = 50,
                  matcher = { URI = { operator = "≈", value = "/custom" } },
                  version = 1 },
            })
        end

        setup(write_fixture)
        teardown(function() os.remove(fixture_path) end)

        it("accepts the drifted action, persists it, leaves everything else", function()
            write_fixture()
            seed_runtime()
            local result, err = waf.accept_factory_actions({ "ax_gray" })
            assert.is_nil(err)
            assert.same({ "ax_gray" }, result.accepted)
            local by_id = {}
            for _, r in ipairs(waf.load_rules().rules) do by_id[r.id] = r end
            assert.are.equal("block", by_id.ax_gray.action, "factory action accepted")
            assert.is_false(by_id.ax_gray.enable, "enable preserved")
            assert.are.equal("Operator Name", by_id.ax_gray.name, "content preserved")
            assert.are.equal("/operator", by_id.ax_gray.matcher.URI.value, "content preserved")
            assert.are.equal(5, by_id.ax_gray.version, "monotone with factory v5")
            assert.are.equal("block", by_id.ax_custom.action, "custom untouched")
        end)

        it("no-op batch reports message and skips the save", function()
            write_fixture()
            seed_runtime()
            local before = waf.load_rules().version
            local result, err = waf.accept_factory_actions(
                { "ax_same", "ax_custom", "ax_ghost" })
            assert.is_nil(err)
            assert.same({}, result.accepted)
            assert.are.equal(3, #result.skipped)
            assert.truthy(result.message)
            assert.are.equal(before, waf.load_rules().version,
                "no save means no version churn")
            local by_id = {}
            for _, r in ipairs(waf.load_rules().rules) do by_id[r.id] = r end
            assert.are.equal("log", by_id.ax_gray.action, "untouched by no-op batch")
        end)
    end)
end)

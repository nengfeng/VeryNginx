-- waf-rule-manager factory drift (P0-2 visibility) and the factory-file
-- fallback when the runtime rules file is missing.
--
-- P0-2: upgrades keep an existing waf-rules.json untouched and force-sync
-- intentionally never touches action, so a factory fix can silently never
-- reach an install. factory_drift() makes the divergence reviewable.

describe("waf-rule-manager factory drift + fallback", function()
    local waf

    setup(function()
        waf = require("waf-rule-manager")
    end)

    local function rule(id, action, mvalue)
        return { id = id, action = action, enable = true,
                 matcher = { URI = { operator = "≈", value = mvalue } } }
    end

    local factory = { version = 11, rules = {
        rule("vn_a", "block", "aaa"),
        rule("vn_b", "log", "bbb"),
        rule("vn_gone", "block", "ggg"),
    } }

    describe("_factory_drift_report", function()
        it("identical set -> no drift, checked count reported", function()
            local rep = assert(waf._factory_drift_report({ rules = {
                rule("vn_a", "block", "aaa"),
                rule("vn_b", "log", "bbb"),
                rule("vn_gone", "block", "ggg"),
            } }, factory))
            assert.are.equal(0, #rep.drift)
            assert.are.equal(3, rep.checked)
        end)

        it("detects matcher (content) drift", function()
            local rep = assert(waf._factory_drift_report({ rules = {
                rule("vn_a", "block", "CHANGED"),
                rule("vn_b", "log", "bbb"),
                rule("vn_gone", "block", "ggg"),
            } }, factory))
            assert.are.equal(1, #rep.drift)
            assert.are.equal("vn_a", rep.drift[1].id)
            assert.are.equal("content", rep.drift[1].kind)
        end)

        it("detects action drift with both sides reported", function()
            local rep = assert(waf._factory_drift_report({ rules = {
                rule("vn_a", "log", "aaa"),   -- operator overrode block->log
                rule("vn_b", "log", "bbb"),
                rule("vn_gone", "block", "ggg"),
            } }, factory))
            assert.are.equal(1, #rep.drift)
            assert.are.equal("action", rep.drift[1].kind)
            assert.are.equal("log", rep.drift[1].runtime_action)
            assert.are.equal("block", rep.drift[1].factory_action)
        end)

        it("detects a factory rule missing from runtime; custom rules ignored", function()
            local rep = assert(waf._factory_drift_report({ rules = {
                rule("vn_a", "block", "aaa"),
                rule("vn_b", "log", "bbb"),
                rule("my_custom", "block", "xxx"),
            } }, factory))
            assert.are.equal(1, #rep.drift)
            assert.are.equal("vn_gone", rep.drift[1].id)
            assert.are.equal("missing", rep.drift[1].kind)
        end)
    end)

    describe("load_from_file factory fallback", function()
        local base = "/tmp/vnt-spec/configs/"
        local saved_runtime, saved_factory = nil, nil

        local function slurp(path)
            local f = io.open(path, "r")
            if not f then return nil end
            local d = f:read("*all"); f:close()
            return d
        end

        local function restore()
            if saved_runtime then
                local f = assert(io.open(base .. "waf-rules.json", "w"))
                f:write(saved_runtime); f:close()
            else
                os.remove(base .. "waf-rules.json")
            end
            if saved_factory then
                local f = assert(io.open(base .. "waf-rules.default.json", "w"))
                f:write(saved_factory); f:close()
            else
                os.remove(base .. "waf-rules.default.json")
            end
        end

        before_each(function()
            os.execute("mkdir -p " .. base)
            saved_runtime = slurp(base .. "waf-rules.json")
            saved_factory = slurp(base .. "waf-rules.default.json")
        end)

        after_each(restore)

        it("falls back to waf-rules.default.json when runtime file is missing", function()
            os.remove(base .. "waf-rules.json")
            local f = assert(io.open(base .. "waf-rules.default.json", "w"))
            f:write('{"version":7,"timestamp":"t","rules":[{"id":"factory_1",'
                .. '"name":"F","category":"sqli","severity":"high","action":"log",'
                .. '"enable":true,"priority":10,'
                .. '"matcher":{"URI":{"operator":"=","value":"/f"}}}]}')
            f:close()
            local data = waf.load_from_file()
            assert.is_not_nil(data, "factory fallback must load when runtime file is missing")
            assert.are.equal(1, #data.rules)
            assert.are.equal("factory_1", data.rules[1].id)
        end)

        it("returns nil only when BOTH runtime and factory files are missing", function()
            os.remove(base .. "waf-rules.json")
            os.remove(base .. "waf-rules.default.json")
            assert.is_nil(waf.load_from_file())
        end)

        it("runtime file wins when both exist", function()
            local f = assert(io.open(base .. "waf-rules.json", "w"))
            f:write('{"version":9,"timestamp":"t","rules":[{"id":"runtime_1",'
                .. '"name":"R","category":"sqli","severity":"high","action":"block",'
                .. '"enable":true,"priority":10,'
                .. '"matcher":{"URI":{"operator":"=","value":"/r"}}}]}')
            f:close()
            f = assert(io.open(base .. "waf-rules.default.json", "w"))
            f:write('{"version":7,"timestamp":"t","rules":[{"id":"factory_1",'
                .. '"name":"F","category":"sqli","severity":"high","action":"log",'
                .. '"enable":true,"priority":10,'
                .. '"matcher":{"URI":{"operator":"=","value":"/f"}}}]}')
            f:close()
            local data = waf.load_from_file()
            assert.is_not_nil(data)
            assert.are.equal("runtime_1", data.rules[1].id)
        end)
    end)
end)

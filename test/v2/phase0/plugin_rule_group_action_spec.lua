-- -*- coding: utf-8 -*-
-- Plugin rule groups could not be configured at all.
--
-- Every group under config.rule is a PLUGIN rule group: browser_verify,
-- static_file, proxy_pass, redirect, scheme_lock, uri_rewrite,
-- frequency_limit. WAF rules live in config.waf_rules and are validated by
-- waf-rule-manager, which does require an action.
--
-- The config validator, however, demanded a resolvable action from every
-- rule in every config.rule group. No plugin group reads rule.action — each
-- plugin sets its own action at run time through ctx.set_action() — and the
-- only consumer of rule.action in the rule engine, rule_engine.execute(), has
-- no callers at all. The plugins use their own field names instead:
-- proxy_host/upstream for proxy_pass, root/path/expires for static_file,
-- replace_re/to_uri for uri_rewrite.
--
-- The result was that a rule in any of those groups was rejected with
-- "unknown action 'nil'" and the config could not be saved. It only ever
-- passed for frequency_limit, whose rules carry an action:"block" that nothing
-- reads. The browser_verify group — shipped in the codebase, with its
-- JavaScript challenge implemented — was unreachable for exactly this reason.
--
-- A rule that DOES name an action must still name a valid one, so a typo is
-- still caught. These tests pin both halves.

describe("plugin rule groups need not declare an action", function()

    local config

    setup(function()
        if not _G.ngx then _G.ngx = {} end
        _G.ngx.log = _G.ngx.log or function() end
        _G.ngx.now = _G.ngx.now or function() return os.time() end
        _G.ngx.time = _G.ngx.time or function() return os.time() end
        _G.ngx.md5 = _G.ngx.md5 or function(s) return tostring(#s) end
        _G.ngx.shared = _G.ngx.shared or setmetatable({}, { __index = function() return nil end })
        package.loaded["core.config"] = nil
        config = require "core.config"
    end)

    teardown(function()
        package.loaded["core.config"] = nil
    end)

    local function validate(cfg)
        return config.validate_config(cfg)
    end

    it("accepts a browser_verify rule with no action", function()
        local ok, err = validate({
            rule = {
                browser_verify = {
                    { id = "vn_crawler_challenge_0001", enable = true,
                      type = { "javascript" },
                      matcher = {
                          Host = { operator = "=", value = "www.hostwyn.com" },
                          Composite = { operator = "OR", conditions = {
                              { Args = { name_operator = "=", name_value = "sid",
                                         operator = "≈", value = "^[0-9a-f]{32}$" } },
                          } },
                      } },
                },
            },
        })
        assert.is_true(ok, "a browser_verify rule must be saveable: " .. tostring(err))
    end)

    it("accepts a static_file rule with no action", function()
        -- static_file rules carry root/path/expires, never an action.
        local ok, err = validate({
            rule = {
                static_file = {
                    { id = "sf_1", enable = true, root = "/data/wwwroot/x",
                      path = "/a.jpg", expires = 86400 },
                },
            },
        })
        assert.is_true(ok, "a static_file rule must be saveable: " .. tostring(err))
    end)

    it("still rejects a rule that names an action which does not exist", function()
        local ok, err = validate({
            rule = {
                frequency_limit = {
                    { id = "freq_x", enable = true, action = "blok",
                      limit = 10, window = 60, code = 429 },
                },
            },
        })
        assert.is_false(ok, "a typo'd action must still be rejected")
        assert.is_truthy(tostring(err):find("unknown action", 1, true), tostring(err))
    end)

    it("still accepts a rule that names a valid action", function()
        local ok, err = validate({
            rule = {
                frequency_limit = {
                    { id = "freq_ok", enable = true, action = "block",
                      limit = 10, window = 60, code = 429 },
                },
            },
        })
        assert.is_true(ok, tostring(err))
    end)

    it("treats an empty-string action as no action at all", function()
        -- An empty action is an omission, not a bad value: the codebase
        -- already treats "" as unset in the same situation (plugin/
        -- frequency_limit falls back to a default template when the response
        -- field is an empty string). Pinning it here keeps the two consistent
        -- rather than leaving it to chance.
        local ok, err = validate({
            rule = {
                frequency_limit = {
                    { id = "freq_empty", enable = true, action = "",
                      limit = 10, window = 60, code = 429 },
                },
            },
        })
        assert.is_true(ok,
            "an empty action must not be rejected as an unknown one: " .. tostring(err))
    end)
end)
-- Regression test for the H-3 audit finding: browser_verify used to call
-- challenge() (which only ngx.say's the HTML) and return WITHOUT setting a
-- terminal action, so the plugin chain continued past the challenge and
-- proxy_pass could serve the protected resource to non-browsers.
-- The plugin must set a terminal "challenge" action instead; rule_engine.apply
-- issues the page + ngx.exit(200) outside pcall.

describe("browser_verify challenge is terminal", function()

    local bv

    before_each(function()
        package.loaded["core.config"] = {
            rule = {
                browser_verify = {
                    { enable = true, type = { "cookie" }, matcher = {} },
                },
            },
        }
        package.loaded["matcher.init"] = {
            resolve = function(rule) return rule.matcher end,
            test = function() return true end,
        }
        package.loaded["plugin.browser_verify.cookie_verify"] = {
            check = function() return false end,
            challenge = function() error("challenge() must not be called inside pcall") end,
        }
        package.loaded["plugin.browser_verify.javascript_verify"] = {
            check = function() return true end,
            challenge = function() end,
        }
        bv = require("plugin.browser_verify.init")
    end)

    after_each(function()
        package.loaded["core.config"] = nil
        package.loaded["matcher.init"] = nil
        package.loaded["plugin.browser_verify.cookie_verify"] = nil
        package.loaded["plugin.browser_verify.javascript_verify"] = nil
        package.loaded["plugin.browser_verify.init"] = nil
    end)

    local function make_ctx()
        local ctx = {
            request = { uri = "/protected", scheme = "http" },
            _actions = {},
        }
        function ctx:set_action(atype, data)
            self._actions[#self._actions + 1] = { type = atype, data = data }
        end
        function ctx:set_data() end
        return ctx
    end

    it("failed cookie check sets a terminal challenge action", function()
        local ctx = make_ctx()
        bv.on_access(ctx)

        assert.equals(1, #ctx._actions)
        assert.equals("challenge", ctx._actions[1].type)
        assert.is_not_nil(ctx._actions[1].data.cookie_verify)
    end)

    it("plugin name/priority contract unchanged", function()
        assert.equals("browser_verify", bv.name)
        assert.equals(300, bv.priority)
    end)

end)

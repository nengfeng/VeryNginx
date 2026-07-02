describe("plugin TERMINAL_ACTIONS", function()

    local plugin

    setup(function()
        plugin = require("core.plugin")
    end)

    it("includes challenge as terminal action", function()
        local ctx = {
            action_result = { type = "challenge" }
        }
        assert.is_true(plugin._is_terminal(ctx))
    end)

    it("includes block as terminal action", function()
        local ctx = {
            action_result = { type = "block" }
        }
        assert.is_true(plugin._is_terminal(ctx))
    end)

    it("includes redirect as terminal action", function()
        local ctx = {
            action_result = { type = "redirect" }
        }
        assert.is_true(plugin._is_terminal(ctx))
    end)

    it("includes response as terminal action", function()
        local ctx = {
            action_result = { type = "response" }
        }
        assert.is_true(plugin._is_terminal(ctx))
    end)

    it("excludes non-terminal actions like proxy", function()
        local ctx = {
            action_result = { type = "proxy" }
        }
        assert.is_false(plugin._is_terminal(ctx))
    end)

    it("excludes actions with nil action_result", function()
        local ctx = {}
        assert.is_false(plugin._is_terminal(ctx))
    end)

end)

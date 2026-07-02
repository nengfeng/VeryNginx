describe("rule_engine challenge action", function()

    local rule_engine, javascript_verify
    local call_log

    setup(function()
        rule_engine = require("core.rule_engine")
        javascript_verify = require("plugin.browser_verify.javascript_verify")
        call_log = {}
    end)

    it("apply calls challenge() when action type is CHALLENGE", function()
        local challenge_called = false
        local original_challenge = javascript_verify.challenge
        javascript_verify.challenge = function(ctx)
            challenge_called = true
            assert.is_not_nil(ctx)
        end

        local ctx = {
            action_result = {
                type = "challenge",
                data = {
                    javascript_verify = javascript_verify
                }
            },
            request = {
                scheme = "http",
                uri = "/test",
                remote_addr = "127.0.0.1",
            }
        }

        ngx.header = {}
        ngx.say = function() end
        ngx.exit = function(code)
            assert.equals(200, code)
        end

        rule_engine.apply(ctx, "access")

        assert.is_true(challenge_called)

        javascript_verify.challenge = original_challenge
    end)

    it("RESULT table includes CHALLENGE", function()
        assert.equals("challenge", rule_engine.RESULT.CHALLENGE)
    end)

end)

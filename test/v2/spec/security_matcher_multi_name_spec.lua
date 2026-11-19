-- Security: Cookie/Header matchers must not stop at the first name match.
--
-- Both matchers used to `return compare.match(value, ...)` as soon as the
-- NAME matched. When a rule's name pattern is broad (for example ".*" or
-- "^X-.*$"), an attacker controls several names and can put a safe value
-- first and the payload second. Table iteration order then decides whether
-- the rule fires; the fix keeps scanning until a name+value pair matches.

describe("security: multi-name cookie/header matchers", function()

    local saved_re, saved_get_headers
    local saved_cookie_loaded, saved_cookie_preload
    local saved_cookie_mod, saved_header_mod

    local function ordered_table(t, order)
        return setmetatable(t, {
            __pairs = function(_)
                local i = 0
                return function()
                    i = i + 1
                    local k = order[i]
                    if k then return k, t[k] end
                end
            end,
        })
    end

    before_each(function()
        saved_re = ngx.re
        saved_get_headers = ngx.req.get_headers
        saved_cookie_loaded = package.loaded["cookie"]
        saved_cookie_preload = package.preload["cookie"]
        saved_cookie_mod = package.loaded["matcher.cookie"]
        saved_header_mod = package.loaded["matcher.header"]

        ngx.re = {
            compile = function(pattern) return pattern end,
            match = function(subject, pattern)
                return subject and subject:find(pattern) or nil
            end,
        }
        package.loaded["matcher.cookie"] = nil
        package.loaded["matcher.header"] = nil
    end)

    after_each(function()
        ngx.re = saved_re
        ngx.req.get_headers = saved_get_headers
        package.loaded["cookie"] = saved_cookie_loaded
        package.preload["cookie"] = saved_cookie_preload
        package.loaded["matcher.cookie"] = saved_cookie_mod
        package.loaded["matcher.header"] = saved_header_mod
    end)

    it("cookie: a safe cookie earlier in iteration does not shadow a malicious sibling", function()
        local fields = ordered_table({ safe = "ok", evil = "malicious" },
                                     { "safe", "evil" })
        package.loaded["cookie"] = {
            new = function() return { get_all = function() return fields end } end,
        }
        local cookie_matcher = require("matcher.cookie")
        local ctx = {}
        local condition = {
            name_operator = "≈", name_value = "^[se]",
            operator = "≈", value = "^malicious$",
        }
        assert.is_true(cookie_matcher.test(condition, ctx))
    end)

    it("header: a safe header earlier in iteration does not shadow a malicious sibling", function()
        ngx.req.get_headers = function()
            return ordered_table({ ["X-Safe"] = "ok", ["X-Evil"] = "malicious" },
                                 { "X-Safe", "X-Evil" })
        end
        local header_matcher = require("matcher.header")
        local condition = {
            name_operator = "≈", name_value = "^X-.*$",
            operator = "≈", value = "^malicious$",
        }
        assert.is_true(header_matcher.test(condition, {}))
    end)

    it("cookie: still false when no value matches", function()
        local fields = ordered_table({ safe = "ok", other = "fine" },
                                     { "safe", "other" })
        package.loaded["cookie"] = {
            new = function() return { get_all = function() return fields end } end,
        }
        local cookie_matcher = require("matcher.cookie")
        local condition = {
            name_operator = "≈", name_value = "^[so]",
            operator = "≈", value = "^malicious$",
        }
        assert.is_false(cookie_matcher.test(condition, {}))
    end)

end)

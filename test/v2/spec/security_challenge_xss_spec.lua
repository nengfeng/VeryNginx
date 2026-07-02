local function extract_target(html)
    local _, _, target = html:find("location='(.-)';")
    return target or ""
end

describe("security: challenge XSS prevention", function()

    local javascript_verify

    setup(function()
        javascript_verify = require("plugin.browser_verify.javascript_verify")
    end)

    local function capture_challenge(ctx)
        local output = {}
        ngx.header = {}
        ngx.say = function(s) table.insert(output, s) end
        ngx.exit = function() end
        javascript_verify.challenge(ctx)
        return table.concat(output)
    end

    it("escapes double quote in URI", function()
        local ctx = {
            request = {
                scheme = "http",
                uri = '/"><script>alert(1)</script>',
                remote_addr = "127.0.0.1",
                user_agent = "test",
            }
        }
        ngx.var = {
            http_host = "example.com",
            http_user_agent = "test",
            query_string = "",
            http_cookie = "",
        }
        local html = capture_challenge(ctx)
        local target = extract_target(html)
        assert.is_nil(target:find('"', 1, true),
            "raw double quote in reflected target should be escaped")
    end)

    it("escapes less-than and greater-than in URI", function()
        local ctx = {
            request = {
                scheme = "http",
                uri = '/<script>alert(1)</script>',
                remote_addr = "127.0.0.1",
                user_agent = "test",
            }
        }
        ngx.var = {
            http_host = "example.com",
            http_user_agent = "test",
            query_string = "",
            http_cookie = "",
        }
        local html = capture_challenge(ctx)
        local target = extract_target(html)
        assert.is_nil(target:find('<', 1, true),
            "raw < in reflected target should be escaped")
        assert.is_nil(target:find('>', 1, true),
            "raw > in reflected target should be escaped")
    end)

    it("escapes query_string with XSS payload", function()
        local ctx = {
            request = {
                scheme = "http",
                uri = "/test",
                remote_addr = "127.0.0.1",
                user_agent = "test",
            }
        }
        ngx.var = {
            http_host = "example.com",
            http_user_agent = "test",
            query_string = "q=\"><script>alert(1)</script>",
            http_cookie = "",
        }
        local html = capture_challenge(ctx)
        local target = extract_target(html)
        assert.is_nil(target:find('"', 1, true),
            "raw double quote in reflected query should be escaped")
        assert.is_nil(target:find('<', 1, true),
            "raw < in reflected query should be escaped")
    end)

    it("escapes backslash in URI", function()
        local ctx = {
            request = {
                scheme = "http",
                uri = '/\\";alert(1)//',
                remote_addr = "127.0.0.1",
                user_agent = "test",
            }
        }
        ngx.var = {
            http_host = "example.com",
            http_user_agent = "test",
            query_string = "",
            http_cookie = "",
        }
        local html = capture_challenge(ctx)
        local target = extract_target(html)
        -- Backslash should be escaped to \\\\ (double backslash in JS string)
        assert.is_nil(target:find('\\";', 1, true),
            "raw backslash followed by quote should be escaped")
    end)

    it("prevents javascript: protocol in redirect target", function()
        local ctx = {
            request = {
                scheme = "http",
                uri = "/test",
                remote_addr = "127.0.0.1",
                user_agent = "test",
            }
        }
        ngx.var = {
            http_host = "javascript:alert(1)",
            http_user_agent = "test",
            query_string = "",
            http_cookie = "",
        }
        local html = capture_challenge(ctx)
        local target = extract_target(html)
        -- The sanitize function should redirect to / for non-http URLs
        assert.is_nil(target:find('javascript:', 1, true),
            "javascript: protocol should not appear in redirect target")
    end)

end)

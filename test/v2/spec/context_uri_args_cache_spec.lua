-- -*- coding: utf-8 -*-
-- Regression guard for the per-request URI-args cache.
--
-- With the deployed rule set a single request hits ~19 `Args` conditions;
-- without a cache every one of them re-ran ngx.req.get_uri_args() (C→Lua table
-- construction) plus the query-string overflow scan. The query string cannot
-- change during a request, so exactly one parse per request is correct.

describe("context.get_uri_args caches per request", function()
    local context

    before_each(function()
        package.loaded["core.context"] = nil
        context = require "core.context"
    end)

    local function new_ctx()
        local ctx = context.new()
        return ctx
    end

    it("parses the query string only once across repeated calls", function()
        local calls = 0
        local args = { q = "union select 1", page = "2" }
        local saved = ngx.req.get_uri_args
        ngx.req.get_uri_args = function()
            calls = calls + 1
            return args
        end
        ngx.var.query_string = "q=union+select+1&page=2"
        local ctx = new_ctx()

        local a1 = ctx.get_uri_args(ctx)
        local a2 = ctx.get_uri_args(ctx)
        local a3 = context.get_uri_args(ctx)

        ngx.req.get_uri_args = saved
        ngx.var.query_string = nil
        assert.is_equal(1, calls, "ngx.req.get_uri_args must be called once")
        assert.is_equal(args, a1)
        assert.is_equal(args, a2)
        assert.is_equal(args, a3)
    end)

    it("preserves the args_truncated overflow flag on cached calls", function()
        local saved = ngx.req.get_uri_args
        ngx.req.get_uri_args = function() return { a = "1" } end
        ngx.var.query_string = string.rep("a=1&", 1100) -- exceeds the 1000 default cap
        local ctx = new_ctx()

        context.get_uri_args(ctx)
        assert.is_equal("args_truncated", ctx.request._uri_args_error)
        -- A later cached call must still see the flag (it is stored on ctx).
        context.get_uri_args(ctx)
        assert.is_equal("args_truncated", ctx.request._uri_args_error)
        assert.is_true(ctx.request._uri_args_read)

        ngx.req.get_uri_args = saved
        ngx.var.query_string = nil
    end)

    it("uses a fresh cache after a new context (internal redirect)", function()
        local calls = 0
        local saved = ngx.req.get_uri_args
        ngx.req.get_uri_args = function()
            calls = calls + 1
            return { n = tostring(calls) }
        end
        ngx.var.query_string = nil

        local ctx1 = new_ctx()
        context.get_uri_args(ctx1)
        context.get_uri_args(ctx1)
        local ctx2 = new_ctx() -- simulates the fresh ctx after ngx.exec / redirect
        context.get_uri_args(ctx2)

        ngx.req.get_uri_args = saved
        assert.is_equal(2, calls, "each context must parse once")
    end)
end)

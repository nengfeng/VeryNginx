-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : request context unit tests

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

describe("Request context", function()
    local context

    setup(function()
        context = require "core.context"
    end)

    before_each(function()
        ngx.var.connection = "1"
        ngx.var.connection_requests = "1"
    end)

    it("parses JSON body into args table", function()
        ngx.var.content_type = "application/json; charset=utf-8"
        ngx.var.content_length = "18"
        ngx.req.get_body_data = function() return '{"key": "value"}' end
        local ctx = context.new()
        local args = ctx.get_body_args(ctx)
        assert.is_not_nil(args)
        assert.are_equal("value", args["key"])
        assert.is_nil(ctx.request._body_error)
    end)

    it("sets _body_error on malformed JSON", function()
        ngx.var.content_type = "application/json; charset=utf-8"
        ngx.var.content_length = "10"
        ngx.req.get_body_data = function() return "not json" end
        local ctx = context.new()
        local args = ctx.get_body_args(ctx)
        assert.is_nil(args)
        assert.truthy(ctx.request._body_error:find("json_decode_failed"),
            "error should contain json_decode_failed, got: " .. tostring(ctx.request._body_error))
    end)

    it("sets _body_error on JSON non-table value", function()
        ngx.var.content_type = "application/json; charset=utf-8"
        ngx.var.content_length = "4"
        ngx.req.get_body_data = function() return "null" end
        local ctx = context.new()
        local args = ctx.get_body_args(ctx)
        assert.is_nil(args)
        assert.truthy(ctx.request._body_error:find("unexpected type"),
            "error should mention unexpected type, got: " .. tostring(ctx.request._body_error))
    end)

    it("caches body args after first read", function()
        ngx.var.content_type = "application/json; charset=utf-8"
        ngx.var.content_length = "18"
        local call_count = 0
        ngx.req.get_body_data = function()
            call_count = call_count + 1
            return '{"key": "value"}'
        end
        local ctx = context.new()
        ctx.get_body_args(ctx)
        ctx.get_body_args(ctx)
        assert.are_equal(1, call_count, "body data should be read only once")
    end)

    it("sets _body_error on body too large", function()
        ngx.var.content_type = "application/json; charset=utf-8"
        ngx.var.content_length = "99999999"
        local ctx = context.new()
        local args = ctx.get_body_args(ctx)
        assert.is_nil(args)
        assert.are_equal("body_too_large", ctx.request._body_error)
    end)

    it("sets _body_error=args_truncated when JSON leaves exceed max_args", function()
        -- P0-1: the JSON flatten used to drop the tail silently (no
        -- _body_error) while the backend parses the full body — a payload
        -- past the cap walked past the scanner. Now it fails closed like
        -- the urlencoded/URI/multipart overflow guards.
        local config = require("core.config")
        local limit = tonumber(config.body and config.body.max_args) or 100
        local parts = {}
        for i = 1, limit + 5 do parts[#parts + 1] = '"k' .. i .. '":"v"' end
        local body = "{" .. table.concat(parts, ",") .. "}"
        ngx.var.content_type = "application/json"
        ngx.var.content_length = tostring(#body)
        ngx.req.get_body_data = function() return body end
        local ctx = context.new()
        local args = ctx.get_body_args(ctx)
        assert.is_not_nil(args, "head of the body must still be scanned")
        assert.is_not_nil(args["k1"], "first leaves must be visible")
        assert.are_equal("args_truncated", ctx.request._body_error)
    end)

    it("does NOT set _body_error when JSON leaves fit within max_args", function()
        local config = require("core.config")
        local limit = tonumber(config.body and config.body.max_args) or 100
        local parts = {}
        for i = 1, limit - 1 do parts[#parts + 1] = '"k' .. i .. '":"v"' end
        local body = "{" .. table.concat(parts, ",") .. "}"
        ngx.var.content_type = "application/json"
        ngx.var.content_length = tostring(#body)
        ngx.req.get_body_data = function() return body end
        local ctx = context.new()
        ctx.get_body_args(ctx)
        assert.is_nil(ctx.request._body_error)
    end)
end)

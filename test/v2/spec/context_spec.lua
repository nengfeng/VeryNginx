-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : request context unit tests

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

describe("Request context", function()
    local context

    before_each(function()
        ngx.var = {}
        ngx.req.get_body_data = function() end
        ngx.req.get_uri_args = function() return {} end
        context = require "core.context"
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
        assert.are_equal("json_decode_failed: Expected value but found invalid token at character 1", ctx.request._body_error)
    end)

    it("sets _body_error on JSON non-table value", function()
        ngx.var.content_type = "application/json; charset=utf-8"
        ngx.var.content_length = "4"
        ngx.req.get_body_data = function() return "null" end
        local ctx = context.new()
        local args = ctx.get_body_args(ctx)
        assert.is_nil(args)
        assert.are_equal("json_decode_failed: unexpected type boolean", ctx.request._body_error)
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
end)

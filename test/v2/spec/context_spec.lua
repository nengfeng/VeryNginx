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
        assert.is_not_nil(args, "partial args must still be returned for scanning")
        -- WHICH leaves survive depends on pairs() hash order (differs across
        -- LuaJIT builds) — assert the deterministic count, not specific keys.
        local n = 0
        for _ in pairs(args) do n = n + 1 end
        assert.are_equal(limit, n, "exactly max_args leaves must be retained")
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

    it("reads the body back from nginx's spool file (E-2)", function()
        -- content_length within max_size but the body spilled to disk
        -- (exceeded client_body_buffer_size, commonly 8-16k on default LNMP
        -- installs). Must be read back and parsed — a spilled 20k form used
        -- to be invisible to the scanner entirely.
        local body = '{"cmd":"sleep(5)","note":"hello"}'
        local path = "/tmp/vnt-spool-spec.body"
        local f = assert(io.open(path, "wb"))
        f:write(body)
        f:close()
        ngx.var.content_type = "application/json"
        ngx.var.content_length = tostring(#body)
        ngx.req.get_body_data = function() return nil end        -- spilled
        ngx.req.get_body_file = function() return path end
        local ctx = context.new()
        local args = ctx.get_body_args(ctx)
        os.remove(path)
        assert.is_not_nil(args, "spooled JSON body must still be parsed")
        assert.are_equal("sleep(5)", args["cmd"])
        assert.is_nil(ctx.request._body_error)
    end)

    it("spool read respects max_size (file larger than cap -> body_too_large)", function()
        local path = "/tmp/vnt-spool-oversize.body"
        local f = assert(io.open(path, "wb"))
        f:write(string.rep("x", 64))
        f:close()
        ngx.var.content_type = "application/json"
        ngx.var.content_length = "50"              -- honest small length; file lies
        ngx.req.get_body_data = function() return nil end
        ngx.req.get_body_file = function() return path end
        -- Shrink max_size via config stub for this test
        local config = require("core.config")
        local created = false
        if not config.body then config.body = {}; created = true end
        local saved = config.body.max_size
        config.body.max_size = 16
        local ctx = context.new()
        ctx.get_body_args(ctx)
        config.body.max_size = saved
        if created then config.body = nil end
        os.remove(path)
        assert.are_equal("body_too_large", ctx.request._body_error)
    end)
end)

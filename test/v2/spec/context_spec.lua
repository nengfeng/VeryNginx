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

    it("large body -> scans the budget prefix (ProcessPartial, observe)", function()
        -- ModSecurity SecRequestBodyLimitAction ProcessPartial analog: a body
        -- bigger than max_size is NEVER rejected for size — the affordable
        -- prefix is scanned and the tail recorded as unscanned.
        local config = require("core.config")
        local created = false
        if not config.body then config.body = {}; created = true end
        local saved = config.body.max_size
        config.body.max_size = 16
        ngx.var.content_type = "application/json"
        ngx.var.content_length = "99999999"
        ngx.req.get_body_data = function()
            return '{"cmd":"sleep(5)","pad":"' .. string.rep("x", 64) .. '"}'
        end
        local ctx = context.new()
        local args = ctx.get_body_args(ctx)
        config.body.max_size = saved
        if created then config.body = nil end
        assert.is_not_nil(args, "budget prefix must be returned for scanning")
        assert.are_equal(16, #args._body_raw, "prefix bounded by max_size")
        assert.are_equal('{"cmd":"sleep(5)', args._body_raw,
            "prefix must be the first max_size bytes")
        assert.are_equal("body_truncated", ctx.request._body_error)
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

    it("spool read returns the budget prefix (file larger than cap)", function()
        local path = "/tmp/vnt-spool-oversize.body"
        local f = assert(io.open(path, "wb"))
        f:write(string.rep("x", 64) .. "PAYLOAD")
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
        -- ProcessPartial: prefix read from the spool, tail unscanned,
        -- observe-only (a large body must never be rejected for size).
        assert.is_not_nil(ctx.request._body_args)
        assert.are_equal(16, #ctx.request._body_args._body_raw)
        assert.are_equal("body_truncated", ctx.request._body_error)
    end)

    it("urlencoded large body -> prefix args parsed and scannable", function()
        local config = require("core.config")
        local created = false
        if not config.body then config.body = {}; created = true end
        local saved = config.body.max_size
        config.body.max_size = 32
        local body = "q=sleep(5)&pad=" .. string.rep("x", 100)
        ngx.var.content_type = "application/x-www-form-urlencoded"
        ngx.var.content_length = tostring(#body)
        ngx.req.get_body_data = function() return body end
        local ctx = context.new()
        local args = ctx.get_body_args(ctx)
        config.body.max_size = saved
        if created then config.body = nil end
        assert.is_not_nil(args, "prefix args must be returned for scanning")
        assert.are_equal("sleep(5)", args.q, "payload field within prefix is scannable")
        assert.are_equal("body_truncated", ctx.request._body_error)
    end)

    it("urlencoded prefix cut mid %XX still decodes the rest", function()
        local config = require("core.config")
        local created = false
        if not config.body then config.body = {}; created = true end
        local saved = config.body.max_size
        config.body.max_size = 10                   -- cut right after "q=%4"
        ngx.var.content_type = "application/x-www-form-urlencoded"
        ngx.req.get_body_data = function()
            return "q=%41%42%43defghijklmnop"
        end
        local ctx = context.new()
        local args = ctx.get_body_args(ctx)
        config.body.max_size = saved
        if created then config.body = nil end
        assert.is_not_nil(args)
        assert.are_equal("body_truncated", ctx.request._body_error)
        -- "q=%41%42%4" -> strip dangling "%4" -> q decodes "AB"
        assert.are_equal("AB", args.q)
    end)

    it("scan_exempt path skips body read entirely (no args, no error)", function()
        local config = require("core.config")
        local created = false
        if not config.body then config.body = {}; created = true end
        local saved_se = config.body.scan_exempt
        local saved_data = ngx.req.get_body_data
        config.body.scan_exempt = { "/phpMyAdmin" }
        local read_called = false
        ngx.var.uri = "/phpMyAdmin/import.php"
        ngx.var.content_type = "application/x-www-form-urlencoded"
        ngx.req.get_body_data = function() read_called = true return "q=x" end
        local ctx = context.new()
        local args = ctx.get_body_args(ctx)
        ngx.var.uri = "/"
        ngx.req.get_body_data = saved_data
        config.body.scan_exempt = saved_se
        if created then config.body = nil end
        assert.is_nil(args, "exempt path returns no body args")
        assert.is_falsy(read_called, "exempt path must not even read the body")
        assert.is_nil(ctx.request._body_error,
            "deliberate exclusion is not an inspection failure")
    end)

    it("scan_exempt is boundary-aware (sibling prefix does not match)", function()
        local config = require("core.config")
        local created = false
        if not config.body then config.body = {}; created = true end
        local saved_se = config.body.scan_exempt
        config.body.scan_exempt = { "/phpMyAdmin" }
        local function probe(uri)
            ngx.var.uri = uri
            return context._body_scan_exempt()
        end
        local r1 = probe("/phpMyAdmin")
        local r2 = probe("/phpMyAdmin/import.php")
        local r3 = probe("/phpMyAdminEvil")
        local r4 = probe("/other/phpMyAdmin")
        ngx.var.uri = "/"
        config.body.scan_exempt = saved_se
        if created then config.body = nil end
        assert.is_true(r1, "exact path matches")
        assert.is_true(r2, "child path matches")
        assert.is_false(r3, "sibling with same prefix must NOT match")
        assert.is_false(r4, "prefix only matches from URI start")
    end)

    it("max_field is decoupled from max_size (per-field budget honored)", function()
        local config = require("core.config")
        local created = false
        if not config.body then config.body = {}; created = true end
        local saved_size, saved_field = config.body.max_size, config.body.max_field
        config.body.max_size = 1048576             -- generous total budget...
        config.body.max_field = 16                 -- ...but tiny per-field cap
        local margs, merr = context._parse_multipart_body(
            "--B\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\n"
                .. string.rep("x", 64) .. "\r\n--B--\r\n", "B", 100)
        config.body.max_size, config.body.max_field = saved_size, saved_field
        if created then config.body = nil end
        -- 64-byte field exceeds max_field=16 -> surfaced, not silently kept
        assert.is_truthy(merr, "field over max_field must be flagged")
        assert.is_nil(margs and margs.k, "oversize field value must not be returned")
    end)
end)

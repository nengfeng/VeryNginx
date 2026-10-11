-- -*- coding: utf-8 -*-
-- @Disc    : multipart/form-data parser (core/context) unit tests
-- Verifies field extraction, file-CONTENT skipping, filename recording,
-- boundary robustness, truncation, and overflow fail-closed behaviour.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

describe("Multipart parser (core.context)", function()
    local context

    setup(function()
        context = require "core.context"
    end)

    local B = "----WebKitFormBoundaryX1"
    local CD = "Content-Disposition: form-data"

    -- Build one part: boundary + headers + blank line + content + CRLF
    local function part(headers, content)
        return "--" .. B .. "\r\n" .. headers .. "\r\n\r\n" .. content .. "\r\n"
    end
    -- Concatenate parts and append the closing boundary
    local function body(...)
        return table.concat({ ... }) .. "--" .. B .. "--\r\n"
    end

    before_each(function()
        ngx.var.uri = "/upload"
        ngx.var.connection = "1"
        ngx.var.connection_requests = "1"
        ngx.var.content_type = nil
        ngx.var.content_length = nil
        ngx.req.get_body_data = function() return nil end
        ngx.req.get_body_file = function() return nil end
    end)

    describe("_multipart_boundary", function()
        it("extracts an unquoted boundary", function()
            assert.are_equal(B, context._multipart_boundary(
                "multipart/form-data; boundary=" .. B))
        end)
        it("extracts a quoted boundary", function()
            assert.are_equal(B, context._multipart_boundary(
                'multipart/form-data; boundary="' .. B .. '"'))
        end)
        it("is case-insensitive and ignores extra params", function()
            assert.are_equal(B, context._multipart_boundary(
                "Multipart/Form-Data; charset=utf-8; BOUNDARY = " .. B))
        end)
        it("returns nil when boundary is absent", function()
            assert.is_nil(context._multipart_boundary("multipart/form-data"))
        end)
    end)

    describe("_cd_param", function()
        local h = 'Content-Disposition: form-data; filename="x.bin"; name="q"'
        it("finds name even when filename precedes it", function()
            assert.are_equal("q", context._cd_param(h, "name"))
        end)
        it("finds filename", function()
            assert.are_equal("x.bin", context._cd_param(h, "filename"))
        end)
        it("supports unquoted values", function()
            assert.are_equal("q", context._cd_param(CD .. "; name=q", "name"))
        end)
        it("returns nil when param absent", function()
            assert.is_nil(context._cd_param(CD .. '; name="q"', "filename"))
        end)
    end)

    describe("_parse_multipart_body", function()
        it("extracts a simple field value", function()
            local args = context._parse_multipart_body(
                body(part(CD .. '; name="q"', "hello")), B, 100)
            assert.are_equal("hello", args.q)
        end)

        it("decodes field values with embedded newlines", function()
            local args = context._parse_multipart_body(
                body(part(CD .. '; name="msg"', "line1\r\nline2")), B, 100)
            assert.are_equal("line1\r\nline2", args.msg)
        end)

        it("SKIPS file content but records the filename", function()
            local args = context._parse_multipart_body(
                body(part(CD .. '; name="f"; filename="x.bin"\r\nContent-Type: application/octet-stream',
                    "union select 1 from users--")), B, 100)
            assert.are_equal("x.bin", args.f)
            assert.is_nil(args.f:find("union", 1, true), "file content must be skipped")
        end)

        it("records a traversal filename (detectable)", function()
            local args = context._parse_multipart_body(
                body(part(CD .. '; name="f"; filename="../../../etc/cron.d/pwn"', "data")), B, 100)
            assert.are_equal("../../../etc/cron.d/pwn", args.f)
        end)

        it("treats filename=\"\" as a regular field (content scanned)", function()
            local args = context._parse_multipart_body(
                body(part(CD .. '; name="q"; filename=""', "union select 1")), B, 100)
            assert.are_equal("union select 1", args.q)
        end)

        it("collects repeated field names into a list", function()
            local args = context._parse_multipart_body(
                body(part(CD .. '; name="q"', "a"), part(CD .. '; name="q"', "b")), B, 100)
            assert.same({ "a", "b" }, args.q)
        end)

        it("supports LF-only line endings", function()
            local data = "--" .. B .. "\n" .. CD .. '; name="q"\n\nval\n--' .. B .. "--\n"
            local args = context._parse_multipart_body(data, B, 100)
            assert.are_equal("val", args.q)
        end)

        it("handles mixed fields and files", function()
            local args = context._parse_multipart_body(
                body(
                    part(CD .. '; name="title"', "My Photo"),
                    part(CD .. '; name="img"; filename="p.jpg"', "\xFF\xD8binary"),
                    part(CD .. '; name="note"', "ok")), B, 100)
            assert.are_equal("My Photo", args.title)
            assert.are_equal("p.jpg", args.img)
            assert.are_equal("ok", args.note)
        end)

        it("parses fields before an unclosed (truncated) body", function()
            local data = part(CD .. '; name="q"', "a") .. part(CD .. '; name="r"', "b")
            local args = context._parse_multipart_body(data, B, 100)
            assert.are_equal("a", args.q)
            assert.are_equal("b", args.r)
        end)

        it("errors when the boundary is missing", function()
            local args, err = context._parse_multipart_body("garbage", B, 100)
            assert.is_nil(args)
            assert.are_equal("multipart_no_boundary", err)
        end)

        it("fails closed on max_args overflow", function()
            local args, err = context._parse_multipart_body(
                body(part(CD .. '; name="a"', "1"), part(CD .. '; name="b"', "2"),
                    part(CD .. '; name="c"', "3")), B, 2)
            assert.is_nil(args)
            assert.are_equal("args_truncated", err)
        end)

        it("ignores preamble text before the first boundary", function()
            local data = "preamble\r\n" .. body(part(CD .. '; name="q"', "v"))
            local args = context._parse_multipart_body(data, B, 100)
            assert.are_equal("v", args.q)
        end)
    end)

    describe("get_body_args integration", function()
        it("parses an in-memory multipart body, skipping file content", function()
            ngx.var.content_type = "multipart/form-data; boundary=" .. B
            ngx.req.get_body_data = function()
                return body(
                    part(CD .. '; name="q"', "union select 1"),
                    part(CD .. '; name="f"; filename="a.bin"', "union select 2"))
            end
            local ctx = context.new()
            local args = ctx.get_body_args(ctx)
            assert.are_equal("union select 1", args.q)     -- field scanned
            assert.are_equal("a.bin", args.f)              -- file content skipped
            assert.is_nil(ctx.request._body_error)
        end)

        it("parses a BODY FILE (buffered upload) without failing closed", function()
            local tmp = os.tmpname()
            local fh = assert(io.open(tmp, "wb"))
            fh:write(body(
                part(CD .. '; name="q"', "hello"),
                part(CD .. '; name="f"; filename="big.bin"', string.rep("Z", 4096))))
            fh:close()

            ngx.var.content_type = "multipart/form-data; boundary=" .. B
            ngx.req.get_body_data = function() return nil end
            ngx.req.get_body_file = function() return tmp end

            local ctx = context.new()
            local args = ctx.get_body_args(ctx)
            os.remove(tmp)
            assert.are_equal("hello", args.q)
            assert.are_equal("big.bin", args.f)
            assert.is_nil(ctx.request._body_error, "large buffered upload must not fail closed")
        end)

        it("returns empty args when there is no body", function()
            ngx.var.content_type = "multipart/form-data; boundary=" .. B
            local ctx = context.new()
            local args = ctx.get_body_args(ctx)
            assert.same({}, args)
            assert.is_nil(ctx.request._body_error)
        end)

        it("fails closed when the boundary is missing", function()
            ngx.var.content_type = "multipart/form-data"
            ngx.req.get_body_data = function() return "no boundary here" end
            local ctx = context.new()
            local args = ctx.get_body_args(ctx)
            assert.is_nil(args)
            assert.are_equal("multipart_bad_boundary", ctx.request._body_error)
        end)
    end)

    describe("matcher integration", function()
        local matcher
        setup(function()
            package.loaded["core.config"] = package.loaded["core.config"]
                or require "core.config"
            matcher = require "matcher.init"
            matcher.register("Args", require("matcher.args").test)
        end)

        local function ctx_with(body_str)
            ngx.var.content_type = "multipart/form-data; boundary=" .. B
            ngx.req.get_body_data = function() return body_str end
            ngx.req.get_uri_args = function() return {} end
            return context.new()
        end

        it("matches a payload in a text field", function()
            local ctx = ctx_with(body(part(CD .. '; name="q"', "union select 1")))
            assert.is_true(matcher.test(
                { Args = { name_operator = "*", operator = "=", value = "union select 1" } }, ctx))
        end)

        it("does NOT match file content (skipped)", function()
            local ctx = ctx_with(
                body(part(CD .. '; name="f"; filename="a.bin"', "union select 1")))
            assert.is_false(matcher.test(
                { Args = { name_operator = "*", operator = "=", value = "union select 1" } }, ctx))
        end)

        it("matches a malicious filename (traversal)", function()
            local ctx = ctx_with(
                body(part(CD .. '; name="f"; filename="../../etc/passwd"', "x")))
            assert.is_true(matcher.test(
                { Args = { name_operator = "*", operator = "=", value = "../../etc/passwd" } }, ctx))
        end)
    end)
end)

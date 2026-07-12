-- -*- coding: utf-8 -*-
-- Tests for IPC Protocol v1 framing and envelope encoding.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.DEBUG = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.sleep = function() end

local proto = require "core.kernel_blocking.ipc_protocol"

describe("IPC Protocol v1 framing", function()
    it("encode_request produces 4-byte length prefix + JSON body", function()
        local framed, err = proto.encode_request("req-123", "add", "automatic",
            { set = "scanner_drop", ip = "203.0.113.1" })
        assert.truthy(framed, "encode should succeed: " .. tostring(err))
        -- Length prefix
        local b1, b2, b3, b4 = string.byte(framed, 1, 4)
        local len = b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
        assert.are.equal(#framed - 4, len)
    end)

    it("encode_request rejects unsupported operation", function()
        local framed, err = proto.encode_request("req-1", "evil_op", "automatic", {})
        assert.is_nil(framed)
        assert.are.equal("unsupported_operation", err)
    end)

    it("encode_request rejects invalid source", function()
        local framed, err = proto.encode_request("req-1", "add", "hacker", {})
        assert.is_nil(framed)
        assert.are.equal("invalid_source", err)
    end)

    it("read_frame decodes a complete frame", function()
        local body = '{"version":1,"request_id":"abc","ok":true,"result":{"x":1}}'
        local len = #body
        local header = string.char(
            math.floor(len / 16777216) % 256,
            math.floor(len / 65536) % 256,
            math.floor(len / 256) % 256,
            len % 256
        )
        local envelope, remainder, err = proto.read_frame(header .. body)
        assert.truthy(envelope, "should decode: " .. tostring(err))
        assert.are.equal("abc", envelope.request_id)
        assert.is_true(envelope.ok)
        assert.are.equal(1, envelope.result.x)
    end)

    it("read_frame returns incomplete when buffer too short", function()
        local envelope, remainder, err = proto.read_frame("\x00\x00\x00\x10only5bytes")
        assert.is_nil(envelope)
        assert.are.equal("incomplete", err)
    end)

    it("read_frame handles invalid frame length (0)", function()
        local envelope, remainder, err = proto.read_frame("\x00\x00\x00\x00")
        assert.is_nil(envelope)
        assert.are.equal("invalid_frame_length", err)
    end)

    it("decode_response rejects non-JSON body", function()
        local env, err = proto.decode_response("not-json")
        assert.is_nil(env)
        assert.are.equal("invalid_json", err)
    end)
end)

describe("IPC Protocol client (mock socket)", function()
    -- Stub out ngx.socket.tcp to return a mock connection
    local mock_responses = {}
    local sent_data = {}

    before_each(function()
        sent_data = {}
        mock_responses = {}

        _G.ngx.socket = {
            tcp = function()
                local conn = {}
                function conn:settimeouts() end
                function conn:connect()
                    return true
                end
                function conn:send(data)
                    sent_data[#sent_data + 1] = data
                    return #data
                end
                function conn:receiveany(n)
                    if #mock_responses > 0 then
                        return table.remove(mock_responses, 1)
                    end
                    return nil, "timeout"
                end
                function conn:setkeepalive() end
                function conn:close() end
                return conn
            end,
        }
    end)

    it("client sends framed request and parses response", function()
        local sent_count = 0
        local dkjson = require "dkjson"
        _G.ngx.socket = {
            tcp = function()
                local conn = {}
                function conn:settimeouts() end
                function conn:connect() return true end
                function conn:send(data)
                    sent_count = sent_count + 1
                    local body = string.sub(data, 5)
                    local env = dkjson.decode(body)
                    local resp = {
                        version = 1, request_id = env.request_id,
                        ok = true, result = { entries = {} },
                    }
                    local resp_body = dkjson.encode(resp)
                    local len = #resp_body
                    local header = string.char(
                        math.floor(len / 16777216) % 256,
                        math.floor(len / 65536) % 256,
                        math.floor(len / 256) % 256,
                        len % 256
                    )
                    mock_responses[#mock_responses + 1] = header .. resp_body
                    return #data
                end
                function conn:receiveany(n)
                    if #mock_responses > 0 then
                        return table.remove(mock_responses, 1)
                    end
                    return nil, "timeout"
                end
                function conn:setkeepalive() end
                function conn:close() end
                return conn
            end,
        }
        package.loaded["core.kernel_blocking.ipc_client"] = nil
        local client = require "core.kernel_blocking.ipc_client"
        local resp, err = client.request("list", "automatic",
            { set = "scanner_drop", family = "ipv4" })
        assert.truthy(resp, "should get response: " .. tostring(err))
        assert.are.equal(1, sent_count)
    end)
end)

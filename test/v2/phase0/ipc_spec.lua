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

        -- Mock shared dict for IPC client mutex
        _G.ngx.shared = _G.ngx.shared or {}
        _G.ngx.shared.vn_locks = _G.ngx.shared.vn_locks or {
            data = {},
            add = function(self, key, value, ttl)
                if self.data[key] then return nil, "exists" end
                self.data[key] = value
                return true
            end,
            get = function(self, key)
                return self.data[key]
            end,
            delete = function(self, key)
                self.data[key] = nil
            end,
        }

        _G.ngx.socket = {
            tcp = function()
                local conn = {}
                local resp_buf = ""
                function conn:settimeouts() end
                function conn:settimeout() end
                function conn:connect()
                    return true
                end
                function conn:send(data)
                    sent_data[#sent_data + 1] = data
                    return #data
                end
                -- Byte-stream receive(n): top up from queued full frames until
                -- n bytes are available, then return exactly n bytes. Mirrors
                -- the real ngx.socket.tcp:receive(n) used by ipc_client.
                function conn:receive(n)
                    while #resp_buf < n and #mock_responses > 0 do
                        resp_buf = resp_buf .. table.remove(mock_responses, 1)
                    end
                    if #resp_buf < n then
                        return nil, "timeout"
                    end
                    local data = string.sub(resp_buf, 1, n)
                    resp_buf = string.sub(resp_buf, n + 1)
                    return data
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
                local resp_buf = ""
                function conn:settimeouts() end
                function conn:settimeout() end
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
                -- Byte-stream receive(n): mirrors ngx.socket.tcp:receive(n).
                function conn:receive(n)
                    while #resp_buf < n and #mock_responses > 0 do
                        resp_buf = resp_buf .. table.remove(mock_responses, 1)
                    end
                    if #resp_buf < n then
                        return nil, "timeout"
                    end
                    local data = string.sub(resp_buf, 1, n)
                    resp_buf = string.sub(resp_buf, n + 1)
                    return data
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

describe("IPC executor reconcile metadata", function()
    it("forwards chunk totals required by the helper", function()
        local saved_client = package.loaded["core.kernel_blocking.ipc_client"]
        local saved_binding = package.loaded["core.kernel_blocking.scope_binding"]
        local saved_config = package.loaded["core.config"]
        local saved_executor = package.loaded["core.kernel_blocking.executor_ipc"]
        local captured

        package.loaded["core.kernel_blocking.ipc_client"] = {
            request = function(operation, source, payload)
                assert.are.equal("reconcile", operation)
                assert.are.equal("reconcile", source)
                captured = payload
                return { ok = true, result = {} }, nil
            end,
        }
        package.loaded["core.kernel_blocking.scope_binding"] = {
            drop_writes_allowed = function() return true, nil end,
            binding_fields = function() return { scope_digest = "test" } end,
            invalidate = function() end,
        }
        package.loaded["core.config"] = { kernel_ip_blocking = {} }
        package.loaded["core.kernel_blocking.executor_ipc"] = nil

        local ok, err = pcall(function()
            local executor = require "core.kernel_blocking.executor_ipc"
            local result = executor.chunked_reconcile({
                snapshot_id = "snapshot-1",
                chunk_index = 1,
                final_chunk = true,
                total_desired = 12,
                total_chunks = 2,
                desired = {},
                remove = {},
            })
            assert.truthy(result)
            assert.are.equal(12, captured.total_desired)
            assert.are.equal(2, captured.total_chunks)
        end)

        package.loaded["core.kernel_blocking.ipc_client"] = saved_client
        package.loaded["core.kernel_blocking.scope_binding"] = saved_binding
        package.loaded["core.config"] = saved_config
        package.loaded["core.kernel_blocking.executor_ipc"] = saved_executor
        assert.is_true(ok, tostring(err))
    end)
end)

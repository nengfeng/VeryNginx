-- Scope binding unit tests (Design §8.3.4) using smoke runner describe/it.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7; _G.ngx.NOTICE = 8
_G.ngx.time = function() return 1700000000 end
_G.ngx.md5 = function(s)
    local h = 0
    for i = 1, #s do h = (h * 31 + s:byte(i)) % 1000000007 end
    return string.format("%032d", h)
end
_G.ngx.shared = setmetatable({_cache = {}}, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v) if st[k] then return false, "exists" end; st[k] = v; return true, nil end,
                incr = function(_, k, d, i) if st[k] == nil then st[k] = (i or 0) end; st[k] = st[k] + d; return st[k], nil end,
                delete = function(_, k) st[k] = nil end,
                expire = function() end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

local mock_config = {
    kernel_ip_blocking = {
        enabled = true,
        mode = "enforce",
        scope = "web",
        protected_addresses = { "203.0.113.10", "203.0.113.11" },
        protected_ports = { 80, 443 },
        ipv4 = { enabled = true },
        ipv6 = { enabled = false },
    },
}
package.loaded["core.config"] = mock_config
package.loaded["core.kernel_blocking.lifecycle"] = {
    get_state = function() return { global_activation_generation = 3 } end,
}
package.loaded["core.kernel_blocking.scope_binding"] = nil

local sb = require "core.kernel_blocking.scope_binding"

describe("Scope binding", function()
    before_each(function()
        ngx.shared.vn_locks:flush_all()
        mock_config.kernel_ip_blocking.protected_addresses = { "203.0.113.10", "203.0.113.11" }
        mock_config.kernel_ip_blocking.protected_ports = { 80, 443 }
        package.loaded["core.kernel_blocking.lifecycle"] = {
            get_state = function() return { global_activation_generation = 3 } end,
        }
    end)

    it("computes stable order-independent digest", function()
        local d1 = sb.compute_scope_digest()
        local d2 = sb.compute_scope_digest()
        assert.are.equal(d1, d2)
        assert.truthy(d1 ~= "")
        mock_config.kernel_ip_blocking.protected_addresses = { "203.0.113.11", "203.0.113.10" }
        assert.are.equal(d1, sb.compute_scope_digest())
    end)

    it("changes digest when ports change", function()
        local d1 = sb.compute_scope_digest()
        mock_config.kernel_ip_blocking.protected_ports = { 8080 }
        assert.truthy(sb.compute_scope_digest() ~= d1)
    end)

    it("blocks DROP until ensure_base validation", function()
        local b0 = sb.get_binding()
        assert.is_false(b0.validated == true)
        local allowed = sb.drop_writes_allowed()
        assert.is_false(allowed)
        local payload = sb.ensure_base_payload()
        assert.are.equal(3, payload.activation_generation)
        sb.mark_validated({
            helper_instance_id = "abc123",
            scope_digest = payload.scope_digest,
            table_generation = 7,
            local_address_digest = "loc1",
        }, payload.scope_digest, 3)
        allowed = sb.drop_writes_allowed()
        assert.is_true(allowed)
    end)

    it("invalidates on helper_instance_id mismatch", function()
        local payload = sb.ensure_base_payload()
        sb.mark_validated({
            helper_instance_id = "abc123",
            scope_digest = payload.scope_digest,
            table_generation = 7,
            local_address_digest = "loc1",
        }, payload.scope_digest, 3)
        local ok, reason = sb.validate_health({
            state = "ok",
            helper_instance_id = "other",
            scope_digest = payload.scope_digest,
            table_generation = 7,
            local_address_digest = "loc1",
        })
        assert.is_false(ok)
        assert.are.equal("helper_instance_changed", reason)
    end)

    it("invalidates on scope_digest mismatch", function()
        local payload = sb.ensure_base_payload()
        sb.mark_validated({
            helper_instance_id = "abc123",
            scope_digest = payload.scope_digest,
            table_generation = 7,
            local_address_digest = "loc1",
        }, payload.scope_digest, 3)
        local ok, reason = sb.validate_health({
            state = "ok",
            helper_instance_id = "abc123",
            scope_digest = "deadbeef",
            table_generation = 7,
            local_address_digest = "loc1",
        })
        assert.is_false(ok)
        assert.are.equal("scope_digest_mismatch", reason)
    end)

    it("invalidates session on IPC reconnect", function()
        local payload = sb.ensure_base_payload()
        sb.mark_validated({
            helper_instance_id = "abc123",
            scope_digest = payload.scope_digest,
            table_generation = 7,
            local_address_digest = "loc1",
        }, payload.scope_digest, 3)
        sb.on_ipc_disconnect()
        local b = sb.get_binding()
        assert.is_false(b.validated)
        assert.are.equal("ipc_reconnect", b.reason)
        assert.truthy((b.connection_generation or 0) >= 1)
        assert.is_false(sb.drop_writes_allowed())
    end)
end)

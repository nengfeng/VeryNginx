-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : TLS fingerprint extraction for improved client identification
--
-- DEPRECATED: superseded by core/tls_fingerprint.lua (JA4-first, and the one
-- the WAF actually consults). This shim is kept so anything still requiring
-- "core.ja3" keeps working — it returns the same prefixed string as before.

local tls = require "core.tls_fingerprint"

local _M = {}

--- Legacy accessor: "ja4:<hash>" > "ja3:<hash>" > "tls:<protocol|cipher>" > nil
function _M.get_fingerprint()
    return tls.get_fingerprint()
end

--- Raw JA3 hash only when this nginx has a JA3 module compiled in.
function _M.get_ja3()
    local rec = tls.get()
    if rec and rec.kind == "ja3" then return rec.hash end
    return nil
end

function _M.get_ja3_text()
    if ngx.var and ngx.var.ssl_client_ja3_text and ngx.var.ssl_client_ja3_text ~= "" then
        return ngx.var.ssl_client_ja3_text
    end
    return nil
end

--- The negotiated-cipher fallback is no longer this module's business; callers
--- that want the whole record go through core.tls_fingerprint.get().
function _M.get_simple_fingerprint()
    local rec = tls.get()
    if rec and rec.kind == "tls" then return rec.hash end
    return nil
end

return _M
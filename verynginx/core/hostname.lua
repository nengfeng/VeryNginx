-- -*- coding: utf-8 -*-
-- @Date    : 2026-10-31
-- @Author  : VeryNginx v2
-- @Disc    : one canonical normalization for the Host header
--
-- The statistics engine, the frequency limiter and the live view all key
-- shared-dict namespaces by host. They MUST agree: a host normalized one way
-- by the writer and another way by the reader is a silent miss, and an
-- unnormalized Host header is an unbounded key-creation surface (a rotating
-- Host can fill the 20 MB statistics dict and evict real data by LRU).
--
-- The rules are here, in one place:
--   * empty -> server_name, then "_";
--   * lowercase;
--   * strip one trailing dot (the DNS root label);
--   * replace ":" and "[]" (IPv6 syntax) and "," (the separator in the live
--     view's host list) with "_" so no value can alias another key or entry;
--   * truncate to 64 bytes.

local _M = {}

function _M.normalize(host)
    if not host or host == "" then
        if ngx and ngx.var then
            host = ngx.var.server_name or ""
        else
            host = ""
        end
    end
    host = tostring(host):lower()
    host = host:gsub("%.$", "")
    host = host:gsub("[:%[%],]", "_")
    if #host > 64 then
        host = host:sub(1, 64)
    end
    if host == "" then
        host = "_"
    end
    return host
end

return _M

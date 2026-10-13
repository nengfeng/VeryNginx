-- -*- coding: utf-8 -*-
-- @Date    : 2026-10-13
-- @Author  : VeryNginx v2
-- @Disc    : TLS/HTTP client fingerprint extraction (JA4 > JA3 > simple fallback)
--
-- Replaces core/ja3.lua (kept as a shim). Two things were broken before this
-- module existed, and both were structural rather than cosmetic:
--
--   1. ja3.lua read $ssl_client_j3_hash, which only exists when nginx is built
--      with a JA3 module. LNMP's vanilla nginx (--with-openssl, no extra module)
--      never has it, so the hash was always nil and the fingerprint degraded to
--      a "protocol|cipher" string that fingerprint_db.match() — an exact
--      equality lookup — can never match. The enforcement chain (block /
--      challenge in plugin/filter, cross-IP alerting) was dead on arrival.
--
--   2. plugin/filter/init.lua read ctx.request.ja3_fingerprint, but NOTHING
--      ever wrote that key: the only producer ran inside waf-rule-manager's
--      hit-detail builder, i.e. after enforcement. Even with a JA3-capable
--      nginx the match() call would have seen nil forever.
--
-- This module fixes both by computing the fingerprint ONCE per handshake in
-- the ssl_client_hello phase (cheap, before any HTTP work) and exposing one
-- accessor that the filter plugin, hit details and alerting all share.
--
-- Fingerprint namespaces ("kind:value"): JA4 is the primary signal (stable
-- under GREASE randomisation because ciphers/extensions are sorted), JA3 stays
-- for sites already curated against it, and the "tls:" fallback is explicitly
-- non-matchable — a negotiated-cipher string is not a client identifier, and
-- matching it would block every visitor who happens to negotiate the same
-- cipher as a blocked tool.

local _M = {}

local CTX_JA4 = "vn_fp_ja4"

local ffi_loaded = false
local ja4_mod = nil

-- Load the vendored JA4 module lazily and defensively. Everything in it that
-- matters here runs under pcall at the call sites below; a missing module must
-- degrade to "no JA4", never take down a handshake.
local function load_ja4()
    if ffi_loaded then return ja4_mod end
    ffi_loaded = true
    local ok, mod = pcall(require, "resty.ja4")
    if ok and type(mod) == "table" then
        pcall(function() mod.configure({ hash = true }) end)
        ja4_mod = mod
    end
    return ja4_mod
end

local function ja4_enabled()
    local ok, config = pcall(require, "core.config")
    if not ok or not config then return false end
    local fp = config.fingerprints
    if not fp or fp.enable == false then return false end
    local ja4 = fp.ja4
    if type(ja4) == "table" and ja4.enable == false then return false end
    return true
end

--- ssl_client_hello_by_lua* hook. Installed at http level in
--- nginx_conf/in_http_block.conf. Runs once per TLS handshake, before any
--- request is parsed, so a request never pays for it twice.
function _M.hello_phase()
    if not ja4_enabled() then return end
    local ja4 = load_ja4()
    if not ja4 then return end
    local ok, fp = pcall(ja4.compute)
    if not ok or not fp then return end
    -- ja4.compute() already stores into ngx.ctx; store explicitly too so the
    -- value survives regardless of the library's own store()/get() bookkeeping.
    if ngx.ctx then ngx.ctx[CTX_JA4] = fp end
    pcall(function() ja4.store(fp) end)
end

--- JA4H over the live HTTP request. Off by default: JA4H is part of "JA4+"
--- under FoxIO License 1.1 (JA4 itself is BSD-3). Self-use is permitted;
--- shipping it in a distributed product needs a licensing decision, so it stays
--- opt-in. HTTP/1.x path needs no extra C symbols; the HTTP/2 path uses
--- lua-resty-core header FFI.
function _M.http_fingerprint()
    local ok, cfg = pcall(require, "core.config")
    if not ok or not cfg then return nil end
    local fp = cfg.fingerprints
    if not fp or fp.enable == false then return nil end
    local ja4 = fp.ja4
    if type(ja4) ~= "table" or not ja4.http_enable then return nil end
    local ok2, mod = pcall(require, "resty.ja4h")
    if not ok2 or type(mod) ~= "table" then return nil end
    pcall(function() mod.configure({ hash = true }) end)
    local ok3, val = pcall(mod.compute)
    if not ok3 or not val then return nil end
    return val
end

--- Legacy JA3, only if this nginx actually has the module compiled in.
local function get_ja3()
    local v = ngx.var
    if v and v.ssl_client_j3_hash and v.ssl_client_j3_hash ~= "" then
        return v.ssl_client_j3_hash
    end
    return nil
end

--- Negotiated-cipher string. NOT a client fingerprint: never matchable, kept
--- only for continuity with existing hit records.
local function simple_fingerprint()
    local parts = {}
    local v = ngx.var or {}
    local ssl_protocol = v.ssl_protocol or ""
    local ssl_cipher = v.ssl_cipher or ""
    local ssl_client_s_dn = v.ssl_client_s_dn or ""
    if ssl_protocol ~= "" then parts[#parts + 1] = ssl_protocol end
    if ssl_cipher ~= "" then parts[#parts + 1] = ssl_cipher end
    if ssl_client_s_dn ~= "" then parts[#parts + 1] = ngx.md5(ssl_client_s_dn):sub(1, 8) end
    if #parts == 0 then return nil end
    return table.concat(parts, "|")
end

--- JA4 section A is the first 10 chars ("t13d1516h2"): transport, version,
--- SNI presence, counts, ALPN. Human-readable and stable across a client's
--- cipher-list churn — the reason family matching is worth having at all.
local function family_of(hash)
    if not hash or #hash < 10 then return nil end
    return hash:sub(1, 10)
end

--- Build the per-request fingerprint record. Cached on ngx.ctx so the filter
--- plugin, hit-detail builder and alerting all see one identical value.
--- @return table|nil { kind, value, hash, family, ja4, ja4h }
function _M.get()
    if not ngx.ctx then return nil end
    local cached = ngx.ctx[CTX_JA4 .. "_rec"]
    if cached then return cached end

    local rec
    local ja4 = ngx.ctx[CTX_JA4]
    if ja4 and ja4 ~= "" then
        rec = {
            kind = "ja4",
            hash = ja4,
            value = "ja4:" .. ja4,
            family = family_of(ja4),
            ja4 = ja4,
        }
        local ja4h = _M.http_fingerprint()
        if ja4h and ja4h ~= "" then
            rec.ja4h = ja4h
            rec.ja4h_family = family_of(ja4h)
        end
    else
        local j3 = get_ja3()
        if j3 then
            rec = { kind = "ja3", hash = j3, value = "ja3:" .. j3 }
        else
            local simple = simple_fingerprint()
            if simple then
                rec = { kind = "tls", hash = simple, value = "tls:" .. simple }
            end
        end
    end

    if rec then ngx.ctx[CTX_JA4 .. "_rec"] = rec end
    return rec
end

--- Legacy string form ("ja4:…"). waf hit details keep storing this under the
--- historical ja3_fingerprint key: renaming a storage key would orphan every
--- existing record and alert statistic.
function _M.get_fingerprint()
    local rec = _M.get()
    if rec then return rec.value end
    return nil
end

--- Test seams (the spec drives the record assembler without a TLS handshake).
function _M._reset()
    ffi_loaded = false
    ja4_mod = nil
    if ngx.ctx then ngx.ctx[CTX_JA4] = nil ngx.ctx[CTX_JA4 .. "_rec"] = nil end
end

function _M._family_of(hash) return family_of(hash) end
function _M._ctx_key() return CTX_JA4 end

return _M
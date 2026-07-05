-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-25
-- @Author  : VeryNginx v2
-- @Disc    : TLS fingerprint database — known scanner/bot JA3 hashes

local _M = {}

local config = require "core.config"

-- Default known bad fingerprints (JA3 hashes)
-- Source: abuse.ch, ja3er.com, curated patterns
local DEFAULT_FINGERPRINTS = {
    -- Masscan / ZGrab
    { hash = "e7d705a3286e19ea42f587b344ee6865", name = "Masscan", category = "scanner", action = "block" },
    { hash = "8f5e1fcbe16c4d69e0823a81a8538aac", name = "ZGrab", category = "scanner", action = "block" },
    { hash = "6734f37431670b3ab4292b8f60f29984", name = "Nmap", category = "scanner", action = "block" },

    -- Python requests (common in scrapers/bots)
    { hash = "669d4b813ef83a5e21b629f479629a8e", name = "python-requests",
      category = "automation", action = "challenge" },
    { hash = "b32309a26951912be7dba3763981b434", name = "Python urllib",
      category = "automation", action = "challenge" },
    { hash = "bb00950074f0c5822be154c7e4de5f1b", name = "curl",
      category = "automation", action = "challenge" },

    -- Go net/http (commonly abused)
    { hash = "9060d6b8cf20b89f42c30d5977799e1b", name = "Go http", category = "automation", action = "challenge" },

    -- Java-based scanners
    { hash = "e12821e20e2b702351168e0e2b702351", name = "Java scanner", category = "automation", action = "challenge" },

    -- Burp Suite / vulnerability scanners
    { hash = "fa63024cdabb4d8e85c5a87c0f9f8a24", name = "Burp Suite", category = "scanner", action = "block" },

    -- sqlmap
    { hash = "bc6c386f480ee97b8b9b9a6c6fef696c", name = "sqlmap", category = "attack", action = "block" },

    -- User-Agent anomalies (detected by TLS fingerprint mismatch)
    { hash = "72a589da586844d7f0818ce684948eea", name = "Chrome bot", category = "bot", action = "challenge" },
}

-- In-memory fingerprint store (loaded from config or defaults)
local _fingerprints = {}
local _initialized = false

--- Load fingerprint database from config or defaults.
function _M.reload()
    local fp_config = config.fingerprints
    if fp_config and fp_config.entries and #fp_config.entries > 0 then
        _fingerprints = {}
        for _, entry in ipairs(fp_config.entries) do
            if entry.hash and entry.name then
                _fingerprints[#_fingerprints + 1] = {
                    hash = entry.hash:lower(),
                    name = entry.name,
                    category = entry.category or "unknown",
                    action = entry.action or "log",
                    description = entry.description or "",
                    enabled = entry.enable ~= false,
                }
            end
        end
    else
        -- Use defaults
        _fingerprints = {}
        for _, entry in ipairs(DEFAULT_FINGERPRINTS) do
            _fingerprints[#_fingerprints + 1] = {
                hash = entry.hash:lower(),
                name = entry.name,
                category = entry.category,
                action = entry.action,
                description = "",
                enabled = true,
            }
        end
    end
    _initialized = true
end

--- Ensure fingerprints are loaded.
local function ensure_loaded()
    if not _initialized then
        _M.reload()
    end
end

--- Match a JA3 hash against the fingerprint database.
-- @param ja3_hash string: the JA3 hash to look up
-- @return table|nil: { hash, name, category, action, description } or nil
function _M.match(ja3_hash)
    ensure_loaded()
    if not ja3_hash then return nil end
    local target = ja3_hash:lower()
    for _, fp in ipairs(_fingerprints) do
        if fp.enabled and fp.hash == target then
            return fp
        end
    end
    return nil
end

--- Get all fingerprint entries.
-- @return table: list of fingerprint entries
function _M.list()
    ensure_loaded()
    return _fingerprints
end

--- Get fingerprint by hash.
-- @param ja3_hash string
-- @return table|nil
function _M.get(ja3_hash)
    ensure_loaded()
    if not ja3_hash then return nil end
    local target = ja3_hash:lower()
    for _, fp in ipairs(_fingerprints) do
        if fp.hash == target then
            return fp
        end
    end
    return nil
end

--- Add or update a fingerprint entry.
-- @param entry table: { hash, name, category, action, description, enable }
-- @return boolean: true if added/updated
function _M.add(entry)
    ensure_loaded()
    if not entry or not entry.hash or not entry.name then
        return false
    end
    local hash = entry.hash:lower()
    -- Check if already exists
    for i, fp in ipairs(_fingerprints) do
        if fp.hash == hash then
            _fingerprints[i] = {
                hash = hash,
                name = entry.name,
                category = entry.category or fp.category,
                action = entry.action or fp.action,
                description = entry.description or fp.description,
                enabled = entry.enable ~= false,
            }
            return true
        end
    end
    -- Add new
    _fingerprints[#_fingerprints + 1] = {
        hash = hash,
        name = entry.name,
        category = entry.category or "unknown",
        action = entry.action or "log",
        description = entry.description or "",
        enabled = entry.enable ~= false,
    }
    return true
end

--- Remove a fingerprint by hash.
-- @param ja3_hash string
-- @return boolean: true if removed
function _M.remove(ja3_hash)
    ensure_loaded()
    if not ja3_hash then return false end
    local target = ja3_hash:lower()
    local new_list = {}
    for _, fp in ipairs(_fingerprints) do
        if fp.hash ~= target then
            new_list[#new_list + 1] = fp
        end
    end
    local removed = #new_list < #_fingerprints
    _fingerprints = new_list
    return removed
end

--- Get categories and counts for stats.
-- @return table: { category -> count }
function _M.categories()
    ensure_loaded()
    local cats = {}
    for _, fp in ipairs(_fingerprints) do
        if fp.enabled then
            cats[fp.category] = (cats[fp.category] or 0) + 1
        end
    end
    return cats
end

--- Get default fingerprint definitions (for initial config generation).
-- @return table
function _M.get_defaults()
    return DEFAULT_FINGERPRINTS
end

return _M

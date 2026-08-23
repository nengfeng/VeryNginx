-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-25
-- @Author  : VeryNginx v2
-- @Disc    : TLS fingerprint database — known scanner/bot JA3 hashes

local _M = {}

local json = require "dkjson"
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
-- config.local_hash at the time of the last reload. ensure_loaded() compares
-- it so every worker converges within one request after another worker (or
-- the dashboard) persists a change — on_rewrite's config.check_update()
-- refreshes the local config first, then our hash mismatch triggers reload.
local _loaded_hash = nil

--- Decode one persisted entry. Entries are stored as JSON strings in
--- config.fingerprints.entries (schema items="string"); hand-edited configs
--- may carry native tables — accept both, skip garbage.
--- @return table|nil
local function decode_entry(raw)
    if type(raw) == "table" and raw.hash and raw.name then
        return {
            hash = tostring(raw.hash):lower(),
            name = raw.name,
            category = raw.category or "unknown",
            action = raw.action or "log",
            description = raw.description or "",
            enabled = raw.enable ~= false and raw.enabled ~= false,
        }
    end
    if type(raw) ~= "string" or raw == "" then return nil end
    local ok, t = pcall(json.decode, raw)
    if not ok or type(t) ~= "table" or not t.hash or not t.name then
        return nil
    end
    return {
        hash = tostring(t.hash):lower(),
        name = t.name,
        category = t.category or "unknown",
        action = t.action or "log",
        description = t.description or "",
        enabled = t.enable ~= false,
    }
end

--- Encode an in-memory entry back into its persisted string form.
local function encode_entry(fp)
    return json.encode({
        hash = fp.hash,
        name = fp.name,
        category = fp.category,
        action = fp.action,
        description = fp.description,
        enable = fp.enabled ~= false,
    })
end

--- Persist the given working set into config.fingerprints.entries under the
--- config save lock. `list` is the desired array of encoded strings.
local function persist_entries(list)
    local ok, err = config.atomic_mutate(function(cfg)
        cfg.fingerprints = cfg.fingerprints or {}
        cfg.fingerprints.entries = list
        return cfg
    end)
    if not ok then
        return false, tostring(err or "atomic_mutate failed")
    end
    return true
end

--- Load fingerprint database from config or defaults.
function _M.reload()
    local fp_config = config.fingerprints
    if fp_config and fp_config.entries and #fp_config.entries > 0 then
        _fingerprints = {}
        for _, entry in ipairs(fp_config.entries) do
            local decoded = decode_entry(entry)
            if decoded then
                _fingerprints[#_fingerprints + 1] = decoded
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
    _loaded_hash = config.local_hash
end

--- Ensure fingerprints are loaded AND current. Besides the first load, this
--- re-syncs whenever the active config generation changed underneath us
--- (another worker saved via atomic_mutate → check_update() refreshed our
--- config → hash mismatch).
local function ensure_loaded()
    if not _initialized or _loaded_hash ~= config.local_hash then
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

--- Add or update a fingerprint entry AND persist it to config.
-- @param entry table: { hash, name, category, action, description, enable }
--   `enable` is the canonical key; `enabled` (the key list() returns) is
--   accepted as a fallback so echoing a list item back toggles correctly
--   instead of always re-enabling.
-- @return boolean ok, string? err — false,err means persistence failed and
--   the caller should surface a 5xx instead of a silent no-op.
function _M.add(entry)
    ensure_loaded()
    if not entry or not entry.hash or not entry.name then
        return false, "hash and name are required"
    end
    local enable = entry.enable
    if enable == nil then enable = entry.enabled end
    local normalized = {
        hash = tostring(entry.hash):lower(),
        name = entry.name,
        category = entry.category or "unknown",
        action = entry.action or "log",
        description = entry.description or "",
        enabled = enable ~= false,
    }

    -- Build the desired persisted list from the CURRENT working set (which
    -- ensure_loaded just synced with the active config generation), replacing
    -- any same-hash entry. Seeding: the first custom add must also persist the
    -- built-in defaults, otherwise reload() switches to the config branch and
    -- every built-in silently disappears.
    local desired = {}
    local seen = {}
    if #_fingerprints > 0 and #((config.fingerprints or {}).entries or {}) == 0 then
        for _, fp in ipairs(_fingerprints) do
            desired[#desired + 1] = encode_entry(fp)
            seen[fp.hash] = true
        end
    else
        for _, raw in ipairs((config.fingerprints or {}).entries or {}) do
            local d = decode_entry(raw)
            if d then
                desired[#desired + 1] = encode_entry(d)
                seen[d.hash] = true
            end
        end
    end
    if seen[normalized.hash] then
        for i, s in ipairs(desired) do
            local d = decode_entry(s)
            if d and d.hash == normalized.hash then
                desired[i] = encode_entry(normalized)
                break
            end
        end
    else
        desired[#desired + 1] = encode_entry(normalized)
    end

    local ok, err = persist_entries(desired)
    if not ok then return false, err end

    -- Resync memory + hash marker from the freshly saved config generation.
    _M.reload()
    return true
end

--- Remove a fingerprint by hash AND persist the change.
-- @param ja3_hash string
-- @return boolean removed, string? err
function _M.remove(ja3_hash)
    ensure_loaded()
    if not ja3_hash then return false end
    local target = ja3_hash:lower()

    local found = false
    for _, fp in ipairs(_fingerprints) do
        if fp.hash == target then found = true; break end
    end
    if not found then return false end

    local desired = {}
    for _, raw in ipairs((config.fingerprints or {}).entries or {}) do
        local d = decode_entry(raw)
        if d and d.hash ~= target then
            desired[#desired + 1] = encode_entry(d)
        elseif not d then
            -- keep unparsable entries untouched rather than destroy them
            desired[#desired + 1] = raw
        end
    end

    local ok, err = persist_entries(desired)
    if not ok then return false, err end

    _M.reload()
    return true
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

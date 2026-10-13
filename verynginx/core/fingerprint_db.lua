-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-25
-- @Author  : VeryNginx v2
-- @Disc    : TLS fingerprint database — known scanner/bot TLS fingerprints

local _M = {}

local json = require "dkjson"
local config = require "core.config"

-- ---------------------------------------------------------------------------
-- Fingerprint namespaces. Entries and lookups are kind-scoped: a JA3 MD5 and a
-- JA4 fingerprint are different algorithms over the same handshake, so they
-- must never cross-match. "tls" (the negotiated protocol|cipher fallback) is
-- deliberately NOT a matchable kind — it identifies a negotiated connection,
-- not a client, and matching it would block every visitor who happened to
-- negotiate the same cipher as a blocked tool.
local KINDS = { ja3 = true, ja4 = true, ja4h = true }

--- Guess the kind of a bare hash (legacy entries carry no "kind" field).
--- Section A widths, as produced by the vendored implementation:
---   JA4  10 chars: transport(1) version(2) sni(1) ciphers(2) exts(2) alpn(2)
---        e.g. t13d1516h2_<12hex>_<12hex>
---   JA4H 12 chars: method(2) version(2) cookie(1) referer(1) headers(2) lang(4)
---        e.g. ge11nn05enus_<12hex>_…  (lang may be "0000" when absent)
--- JA3 is a bare 32-char MD5 and matches neither shape.
local RE_JA4_A  = "^[a-z][0-9][0-9][a-z][0-9][0-9][0-9][0-9][a-z0-9][a-z0-9]_"
local RE_JA4H_A = "^[a-z][a-z][0-9][0-9][a-z][a-z][0-9][0-9][a-z0-9]{4}_"
local function infer_kind(hash)
    if type(hash) ~= "string" then return "ja3" end
    if hash:match(RE_JA4_A) then return "ja4" end
    if hash:match(RE_JA4H_A) then return "ja4h" end
    return "ja3"
end

local function normalize_kind(kind, hash)
    if kind == nil then return infer_kind(hash) end
    kind = tostring(kind):lower()
    if not KINDS[kind] then return nil end
    return kind
end

--- Accept either a record table (from core/tls_fingerprint) or a legacy string
--- ("ja4:xxx" prefixed, or a bare hash). Returns kind, hash or nil.
local function parse_target(target)
    if type(target) == "table" then
        local kind = normalize_kind(target.kind, target.hash)
        if not kind or not target.hash then return nil end
        return kind, tostring(target.hash):lower(), target.family
    end
    if type(target) ~= "string" or target == "" then return nil end
    local kind, hash = target:match("^(ja4h|ja4|ja3|tls):(.+)$")
    if kind then
        if kind == "tls" then return nil, nil end
        return kind, hash:lower()
    end
    hash = target:lower()
    return infer_kind(hash), hash
end

--- Family = the human-readable, churn-resistant section A prefix: 10 chars for
--- JA4 (transport/version/SNI/counts/ALPN), 12 for JA4H (method/version/
--- cookie+referer flags/header count/language). A client that reorders or
--- swaps cipher lists moves segment B but keeps A, so family matching
--- survives the client updates that break exact hashes.
local function family_of(hash, kind)
    if not hash then return nil end
    local width = 10
    if kind == "ja4h" then width = 12 end
    if #hash < width then return nil end
    return hash:sub(1, width)
end

-- Default known bad fingerprints.
-- The JA3 set predates JA4 and stays for sites curated against it (kind is
-- inferred as "ja3"). The JA4 set is seeded from the official FoxIO mapping
-- (ja4plus-mapping.csv), scanner/malware rows ONLY, and every seed is
-- action=log: an imported library entry is a lead, not a verdict. Promotion to
-- block is an operator decision made on observed traffic, same discipline as
-- the gray-release rule promotions.
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

    -- --- JA4 seeds (FoxIO ja4plus-mapping.csv; scanner/C2 rows only) ------
    -- Deliberately excluded despite appearing in the mapping: GoLang library
    -- and Sliver C2 share t13d190900_9dc949149365_97f8aa674fd9, so a JA4-only
    -- block there would hit ordinary Go services.
    { hash = "t12i190700_d83cc789557e_16bbda4055b2", kind = "ja4",
      name = "Cobalt Strike beacon v4.9.1 (wininet)", category = "attack", action = "log",
      description = "FoxIO ja4plus-mapping.csv" },
    { hash = "t12d190800_d83cc789557e_16bbda4055b2", kind = "ja4",
      name = "Cobalt Strike beacon v4.9.1 (winhttp)", category = "attack", action = "log",
      description = "FoxIO ja4plus-mapping.csv" },
    { hash = "t12d210700_76e208dd3e22_16bbda4055b2", kind = "ja4",
      name = "Cobalt Strike beacon v4.9.1 (winhttp, TLS1.2)", category = "attack", action = "log",
      description = "FoxIO ja4plus-mapping.csv" },
    { hash = "t13d201100_2b729b4bf6f3_9e7b989ebec8", kind = "ja4",
      name = "IcedID", category = "attack", action = "log",
      description = "FoxIO ja4plus-mapping.csv" },
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
--- "kind" and "match_mode" are optional: legacy entries predate both and are
--- inferred (kind from the hash shape, match_mode exact). The schema is
--- unchanged, so old config.json files load untouched.
--- @return table|nil
local function decode_entry(raw)
    local t = raw
    if type(raw) == "string" then
        if raw == "" then return nil end
        local ok, decoded = pcall(json.decode, raw)
        if not ok or type(decoded) ~= "table" then return nil end
        t = decoded
    end
    if type(t) ~= "table" or not t.hash or not t.name then return nil end
    local kind = normalize_kind(t.kind, t.hash)
    if not kind then return nil end
    local hash = tostring(t.hash):lower()
    local mode = t.match_mode or "exact"
    if mode ~= "exact" and mode ~= "family" then mode = "exact" end
    if mode == "family" and not family_of(hash, kind) then mode = "exact" end
    return {
        hash = hash,
        kind = kind,
        match_mode = mode,
        family = mode == "family" and family_of(hash, kind) or nil,
        name = t.name,
        category = t.category or "unknown",
        action = t.action or "log",
        description = t.description or "",
        enabled = t.enable ~= false and t.enabled ~= false,
    }
end

--- Encode an in-memory entry back into its persisted string form.
local function encode_entry(fp)
    return json.encode({
        hash = fp.hash,
        kind = fp.kind,
        match_mode = fp.match_mode,
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
            local hash = entry.hash:lower()
            local kind = normalize_kind(entry.kind, hash) or "ja3"
            _fingerprints[#_fingerprints + 1] = {
                hash = hash,
                kind = kind,
                match_mode = "exact",
                family = family_of(hash, kind),
                name = entry.name,
                category = entry.category,
                action = entry.action,
                description = entry.description or "",
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

--- Match a fingerprint against the database.
-- @param target table|string: a core/tls_fingerprint record, a "ja4:…"
--   prefixed string, or a bare hash (legacy callers).
-- @return table|nil: { hash, kind, match_mode, name, category, action, description }
function _M.match(target)
    ensure_loaded()
    local kind, hash, rec_family = parse_target(target)
    if not kind or not hash then return nil end
    local fam = rec_family or family_of(hash, kind)
    for _, fp in ipairs(_fingerprints) do
        if fp.enabled and fp.kind == kind then
            if fp.match_mode == "family" and fp.family and fam then
                if fp.family == fam then return fp end
            elseif fp.hash == hash then
                return fp
            end
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

--- Get fingerprint by hash. Optional kind disambiguates when the same hash
--- exists under two kinds. NOTE: a bare family prefix ("t13d3013h2") carries no
--- section separator, so infer_kind() calls it ja3 — a kind-less lookup for a
--- family entry therefore needs the explicit kind argument.
-- @param ja3_hash string
-- @param kind string|nil
-- @return table|nil
function _M.get(ja3_hash, kind)
    ensure_loaded()
    if not ja3_hash then return nil end
    local target = tostring(ja3_hash):lower()
    local want = kind and normalize_kind(kind, target) or nil
    local fallback
    for _, fp in ipairs(_fingerprints) do
        if fp.hash == target then
            if want == nil or fp.kind == want then
                return fp
            end
            fallback = fallback or fp
        end
    end
    -- kind given but not stored under it: return the hash match anyway so a
    -- caller asking for the wrong kind still sees the entry it exists in.
    return fallback
end

--- Add or update a fingerprint entry AND persist it to config.
-- @param entry table: { hash, kind, match_mode, name, category, action, description, enable }
--   `enable` is the canonical key; `enabled` (the key list() returns) is
--   accepted as a fallback so echoing a list item back toggles correctly
--   instead of always re-enabling.
-- @return boolean ok, string? err, string? class — on failure `class` is
--   "validation" (the request is malformed → caller should surface 4xx) or
--   "persist" (in-memory change was lost → 5xx, never a silent no-op).
function _M.add(entry)
    ensure_loaded()
    if not entry or not entry.hash or not entry.name then
        return false, "hash and name are required", "validation"
    end
    local hash = tostring(entry.hash):lower()
    local kind = normalize_kind(entry.kind, hash)
    if not kind then
        return false, "kind must be one of ja3/ja4/ja4h (the tls fallback is not matchable)", "validation"
    end
    local mode = entry.match_mode or "exact"
    if mode ~= "exact" and mode ~= "family" then
        return false, "match_mode must be exact or family", "validation"
    end
    if mode == "family" then
        if kind ~= "ja4" and kind ~= "ja4h" then
            return false, "family match_mode requires kind ja4 or ja4h", "validation"
        end
        if not family_of(hash, kind) then
            return false, "family match_mode needs a full section A prefix (JA4: 10 chars, JA4H: 12)", "validation"
        end
    end
    local enable = entry.enable
    if enable == nil then enable = entry.enabled end
    local normalized = {
        hash = hash,
        kind = kind,
        match_mode = mode,
        family = mode == "family" and family_of(hash, kind) or nil,
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
            seen[fp.kind .. ":" .. fp.hash] = true
        end
    else
        for _, raw in ipairs((config.fingerprints or {}).entries or {}) do
            local d = decode_entry(raw)
            if d then
                desired[#desired + 1] = encode_entry(d)
                seen[d.kind .. ":" .. d.hash] = true
            end
        end
    end
    local nkey = normalized.kind .. ":" .. normalized.hash
    if seen[nkey] then
        for i, s in ipairs(desired) do
            local d = decode_entry(s)
            if d and d.kind == normalized.kind and d.hash == normalized.hash then
                desired[i] = encode_entry(normalized)
                break
            end
        end
    else
        desired[#desired + 1] = encode_entry(normalized)
    end

    local ok, err = persist_entries(desired)
    if not ok then return false, err, "persist" end

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

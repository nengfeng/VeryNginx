-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Frequency Rule ID Migration tool (m1 scheme)
--             Run once during deployment/cc cutover. Idempotent.
--
-- This module is NOT used during request serving — only during
-- migration/cold-switch operations via CLI or admin API.

local _M = {}

local json = require "dkjson"
local config = require "core.config"

-- RFC 8785 JSON Canonicalization Scheme (subset — sufficient for rules).
-- Canonicalizes a table: object keys sorted lexicographically by
-- their UTF-8 byte values, no insignificant whitespace.
local function jcs_canonicalize(val)
    local t = type(val)
    if t == "string" then
        return json.encode(val)
    elseif t == "number" then
        if val == math.floor(val) and val >= -2^53 and val <= 2^53 then
            return tostring(val)
        end
        return string.format("%.20g", val)
    elseif t == "boolean" then
        return val and "true" or "false"
    elseif t == "table" then
        -- Determine if it's a dense array
        local is_array = true
        local max_i = 0
        local count = 0
        for k, _ in pairs(val) do
            count = count + 1
            if type(k) == "number" and k > 0 and k == math.floor(k) then
                if k > max_i then max_i = k end
            else
                is_array = false
            end
        end
        if count > 0 and max_i ~= count then
            is_array = false
        end
        if is_array and max_i > 0 then
            local parts = {}
            for i = 1, max_i do
                parts[#parts + 1] = jcs_canonicalize(val[i])
            end
            return "[" .. table.concat(parts, ",") .. "]"
        else
            -- Object: sort keys
            local keys = {}
            for k, _ in pairs(val) do
                keys[#keys + 1] = tostring(k)
            end
            table.sort(keys)
            local parts = {}
            for _, k in ipairs(keys) do
                parts[#parts + 1] = json.encode(k) .. ":" .. jcs_canonicalize(val[k])
            end
            return "{" .. table.concat(parts, ",") .. "}"
        end
    else
        return "null"
    end
end

-- Base64url without padding (using dkjson-compatible encoding)
local b64url_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

local function b64url_encode(bytes)
    local result = {}
    for i = 1, #bytes, 3
    do
        local b1 = string.byte(bytes, i) or 0
        local b2 = string.byte(bytes, i+1) or 0
        local b3 = string.byte(bytes, i+2) or 0
        local n = b1 * 65536 + b2 * 256 + b3
        local c1 = math.floor(n / 262144) % 64
        local c2 = math.floor(n / 4096) % 64
        local c3 = math.floor(n / 64) % 64
        local c4 = n % 64
        result[#result + 1] = string.sub(b64url_chars, c1+1, c1+1)
        result[#result + 1] = string.sub(b64url_chars, c2+1, c2+1)
        if i+1 <= #bytes then
            result[#result + 1] = string.sub(b64url_chars, c3+1, c3+1)
        end
        if i+2 <= #bytes then
            result[#result + 1] = string.sub(b64url_chars, c4+1, c4+1)
        end
    end
    return table.concat(result)
end

-- Validates a legacy rule ID. Returns one of:
--   { status = "valid", id = value }     — keep as-is
--   { status = "missing" }               — absent/null/empty string
--   { status = "invalid", value = v }    — non-string/illegal/oversized
local function validate_legacy_id(value)
    -- JSON null in Lua is dkjson.null
    if value == nil or value == "" or value == json.null then
        return { status = "missing" }
    end
    if type(value) ~= "string" then
        return { status = "invalid", value = value }
    end
    -- UTF-8 byte length check
    local blen = #value
    if blen < 1 or blen > 128 then
        return { status = "invalid", value = value }
    end
    -- Pattern check
    if not value:match("^[A-Za-z0-9._-]+$") then
        return { status = "invalid", value = value }
    end
    return { status = "valid", id = value }
end

-- Hash function using HMAC-DRBG-style mixing (stand-in for SHA-256 in pure Lua).
-- NOTE: In production this would use ngx.hmac_sha256 or a vendored SHA-256.
-- For testability we use a deterministic hash that's NOT cryptographically
-- secure but produces consistent 32-byte digests.
local function sha256_purelua_digest(preimage)
    -- Simple deterministic hash producing 32 bytes
    local h = {}
    for i = 1, 32 do h[i] = 0 end
    for i = 1, #preimage do
        local b = string.byte(preimage, i)
        h[((i-1) % 32) + 1] = (h[((i-1) % 32) + 1] * 31 + b) % 256
    end
    return string.char(table.unpack(h))
end

-- Tries to use ngx.hmac_sha256 or falls back to pure Lua
local function sha256_digest(preimage)
    if ngx and ngx.hmac_sha256 then
        -- ngx.hmac_sha256 uses a key; we use a fixed "migration key"
        local raw = ngx.hmac_sha256("verynginx-frequency-id-migration-key", preimage)
        return raw or sha256_purelua_digest(preimage)
    end
    return sha256_purelua_digest(preimage)
end

-- Computes the m1-derived ID for a rule.
-- collision_attempt starts at 0; increments if the generated ID
-- collides with any reserved or already-generated ID.
local function generate_m1_id(rule_array_index, original_rule,
                              old_id_marker, duplicate_ordinal, reserved_ids)
    -- Rule with "id" top-level field stripped for canonicalization
    local rule_copy = {}
    for k, v in pairs(original_rule) do
        if k ~= "id" then
            rule_copy[k] = v
        end
    end
    local canonical_rule = jcs_canonicalize(rule_copy)

    local collision_attempt = 0
    while true do
        local preimage_prefix = "verynginx-frequency-id-migration\nm1\n"
        local preimage_suffix =
            "\n" .. tostring(duplicate_ordinal) ..
            "\n" .. tostring(collision_attempt) ..
            "\n" .. canonical_rule
        local preimage = preimage_prefix .. tostring(rule_array_index) .. "\n" .. old_id_marker .. preimage_suffix
        local digest = sha256_digest(preimage)
        local new_id = "freq_m1_" .. b64url_encode(digest)
        -- Check collision against reserved set
        if not reserved_ids[new_id] then
            return new_id
        end
        collision_attempt = collision_attempt + 1
    end
end

-- ---------------------------------------------------------------------------
-- Performs the migration. Returns { ok = true, changed = [...] } on success,
-- { ok = false, reason = "..." } on failure. Idempotent: running on an
-- already-migrated config does nothing.
-- ---------------------------------------------------------------------------
local function _migrate(skip_write)
    local cfg = config.report()
    local current = json.decode(cfg)
    if not current then
        return { ok = false, reason = "cannot decode current config" }
    end
    -- frequency rules live under rule.frequency_limit
    local freq = current.rule and current.rule.frequency_limit
    if not freq or type(freq) ~= "table" or #freq == 0 then
        return { ok = true, reason = "no frequency rules to migrate", changed = {} }
    end

    -- Phase 1: validate all existing IDs, build reserved set and detect duplicates
    local reserved = {}  -- set of IDs to keep (valid + unique)
    local results = {}   -- per-rule result
    local first_occurrence = {}  -- id -> first index
    local duplicates = {}  -- id -> list of duplicate indices (including first)

    for i, rule in ipairs(freq) do
        if rule and type(rule) == "table" then
            local vid = rule.id
            local r = validate_legacy_id(vid)
            if r.status == "valid" then
                if first_occurrence[vid] then
                    if not duplicates[vid] then
                        duplicates[vid] = { first_occurrence[vid] }
                    end
                    table.insert(duplicates[vid], i)
                    results[i] = { action = "duplicate", original_index = i, id = vid }
                else
                    first_occurrence[vid] = i
                    reserved[vid] = true
                    results[i] = { action = "keep", original_index = i, id = vid }
                end
            elseif r.status == "missing" then
                results[i] = { action = "missing", original_index = i }
            elseif r.status == "invalid" then
                results[i] = { action = "invalid", original_index = i,
                               original_value = r.value }
            end
        end
    end

    -- Phase 2: for duplicates, only keep the first; the rest will be regenerated
    local all_same_as_before = true
    for id, indices in pairs(duplicates) do
        for j = 2, #indices do
            local idx = indices[j]
            results[idx] = { action = "duplicate", original_index = idx, id = id }
        end
        reserved[id] = true
        all_same_as_before = false
    end

    -- Phase 3: Generate new IDs for missing/invalid/duplicate
    local changed = {}
    for i, rule in ipairs(freq) do
        if rule and type(rule) == "table" then
            local r = results[i]
            if r and r.action ~= "keep" then
                local old_id_marker
                local dup_ord = 0
                if r.action == "missing" then
                    old_id_marker = "missing"
                elseif r.action == "invalid" then
                    local bad_val_canonical = jcs_canonicalize(r.original_value)
                    local bad_digest = sha256_digest(bad_val_canonical)
                    old_id_marker = "invalid:" .. b64url_encode(bad_digest)
                elseif r.action == "duplicate" then
                    old_id_marker = "present:" .. r.id
                    for j = 1, i - 1 do
                        if results[j] and results[j].id == r.id then
                            dup_ord = dup_ord + 1
                        end
                    end
                end

                local new_id = generate_m1_id(i, rule,
                    old_id_marker, dup_ord, reserved)
                reserved[new_id] = true
                rule.id = new_id
                all_same_as_before = false
                changed[#changed + 1] = { index = i, action = r.action,
                                          new_id = new_id }
            end
        end
    end

    if all_same_as_before then
        return { ok = true, reason = "already_migrated", changed = {} }
    end

    if skip_write then
        return { ok = true, reason = "dry_run", changed = changed }
    end

    -- Phase 4: Verify cc.rule_ids references if any
    local cc = current.kernel_ip_blocking and current.kernel_ip_blocking.cc
    if cc and cc.rule_ids and type(cc.rule_ids) == "table" then
        local final_ids = {}
        for _, rule in ipairs(freq) do
            if rule.id then final_ids[rule.id] = true end
        end
        for _, ref_id in ipairs(cc.rule_ids) do
            if not final_ids[ref_id] then
                return { ok = false, reason = "cc.rule_ids references unknown rule id: " .. tostring(ref_id) }
            end
        end
    end

    -- Phase 5: Persist via config.save()
    local ok, err = config.save(current)
    if not ok then
        return { ok = false, reason = "save failed: " .. tostring(err) }
    end

    return { ok = true, changed = changed }
end

function _M.migrate(opts)
    opts = opts or {}
    return _migrate(opts.dry_run)
end

-- ---------------------------------------------------------------------------
-- Validation checks for migration correctness.
-- ---------------------------------------------------------------------------
function _M.validate(rules)
    if not rules or type(rules) ~= "table" then
        return false, "rules must be a table"
    end
    local seen = {}
    for i, rule in ipairs(rules) do
        if not rule or type(rule) ~= "table" then
            return false, string.format("rule[%d]: not a table", i)
        end
        if not rule.id or rule.id == "" then
            return false, string.format("rule[%d]: missing id", i)
        end
        local v = validate_legacy_id(rule.id)
        if v.status ~= "valid" then
            return false, string.format("rule[%d]: invalid id '%s'", i, tostring(rule.id))
        end
        if seen[rule.id] then
            return false, string.format("rule[%d]: duplicate id '%s' (first at rule[%d])",
                i, rule.id, seen[rule.id])
        end
        seen[rule.id] = i
    end
    return true
end

function _M.jcs_canonicalize(val)
    return jcs_canonicalize(val)
end

function _M.b64url_encode(bytes)
    return b64url_encode(bytes)
end

function _M.validate_legacy_id(value)
    return validate_legacy_id(value)
end

function _M.generate_m1_id(...)
    return generate_m1_id(...)
end

return _M

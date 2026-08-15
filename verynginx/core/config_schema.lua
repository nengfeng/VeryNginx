-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Recursive config schema walker with type-checking and cross-field validation

local _M = {}

local function deep_copy(t)
    if type(t) ~= "table" then return t end
    local copy = {}
    for k, v in pairs(t) do
        copy[k] = deep_copy(v)
    end
    return copy
end

local function is_array(t)
    if type(t) ~= "table" then return false end
    local count = 0
    local max_idx = 0
    for k, _ in pairs(t) do
        count = count + 1
        if type(k) == "number" and k > max_idx and math.floor(k) == k and k > 0 then
            max_idx = k
        end
    end
    return max_idx == count
end

-- ---------------------------------------------------------------------------
-- Recursively normalize a config subtable against a schema node
-- ---------------------------------------------------------------------------
-- schema_node: { default=..., children={...}, enum={...}, min=I, max=I,
--                type="auto"|"string"|"number"|"boolean"|"array"|"object" }
-- raw_value: what user provided (may be nil or partial)
-- opts: { path="...", reject_unknown=false, strict_type=false }
--
-- Returns: { value=<table>, errors={...} }
function _M.normalize_node(schema_node, raw_value, opts)
    opts = opts or {}
    local errors = {}

    if schema_node == nil then
        return { value = raw_value, errors = {} }
    end

    local function add_err(msg)
        local p = opts.path and (opts.path .. ": ") or ""
        errors[#errors + 1] = p .. msg
    end

    -- If no children defined, this is a leaf field
    if not schema_node.children then
        local default = schema_node.default
        local val = raw_value

        if val == nil then
            val = deep_copy(default)
        end

        -- Type validation
        if val ~= nil then
            local decl_type = schema_node.type
            if decl_type == nil or decl_type == "auto" then
                -- infer from default
                if default ~= nil then
                    decl_type = type(default)
                    if decl_type == "table" then
                        decl_type = is_array(default) and "array" or "object"
                    end
                end
            end

            if decl_type == "string" then
                if type(val) ~= "string" then
                    add_err("expected string, got " .. type(val))
                    val = deep_copy(default)
                end
                if schema_node.enum then
                    local found = false
                    for _, ev in ipairs(schema_node.enum) do
                        if ev == val then found = true; break end
                    end
                    if not found then
                        add_err("invalid enum value '" .. tostring(val) .. "'")
                        val = deep_copy(default)
                    end
                end
                if schema_node.min_len and #val < schema_node.min_len then
                    add_err("string too short (min_len=" .. schema_node.min_len .. ")")
                    val = deep_copy(default)
                end
                if schema_node.max_len and #val > schema_node.max_len then
                    add_err("string too long (max_len=" .. schema_node.max_len .. ")")
                    val = deep_copy(default)
                end
                if schema_node.pattern and not val:match(schema_node.pattern) then
                    add_err("string does not match pattern '" .. schema_node.pattern .. "'")
                    val = deep_copy(default)
                end
            elseif decl_type == "number" or decl_type == "integer" then
                if type(val) ~= "number" then
                    add_err("expected number, got " .. type(val))
                    val = deep_copy(default)
                else
                    if decl_type == "integer" and math.floor(val) ~= val then
                        add_err("expected integer, got float")
                        val = math.floor(val)
                    end
                    if schema_node.min and val < schema_node.min then
                        add_err("value " .. tostring(val) .. " below min=" .. tostring(schema_node.min))
                        val = schema_node.min
                    end
                    if schema_node.max and val > schema_node.max then
                        add_err("value " .. tostring(val) .. " above max=" .. tostring(schema_node.max))
                        val = schema_node.max
                    end
                end
            elseif decl_type == "boolean" then
                if type(val) ~= "boolean" then
                    add_err("expected boolean, got " .. type(val))
                    val = deep_copy(default)
                end
            elseif decl_type == "array" then
                if type(val) ~= "table" or not is_array(val) then
                    add_err("expected array, got " .. type(val))
                    val = deep_copy(default)
                else
                    -- validate min/max element count
                    local n = #val
                    if schema_node.min and n < schema_node.min then
                        add_err("array too short (min=" .. schema_node.min .. ")")
                    end
                    if schema_node.max and n > schema_node.max then
                        add_err("array too long (max=" .. schema_node.max .. ")")
                    end
                    -- validate each element type if item_schema given
                    if schema_node.items then
                        local item_type = schema_node.items
                        for i, elem in ipairs(val) do
                            if item_type == "string" and type(elem) ~= "string" then
                                add_err("array[" .. i .. "]: expected string, got " .. type(elem))
                            elseif item_type == "integer" and (type(elem) ~= "number" or math.floor(elem) ~= elem) then
                                add_err("array[" .. i .. "]: expected integer, got " .. type(elem))
                            end
                        end
                    end
                    -- validate uniqueness if unique_items = true
                    if schema_node.unique_items then
                        local seen = {}
                        for i, elem in ipairs(val) do
                            local key = tostring(elem)
                            if seen[key] then
                                add_err("array[" .. i .. "]: duplicate value '" .. key .. "'")
                            end
                            seen[key] = true
                        end
                    end
                end
            elseif decl_type == "object" or decl_type == "table" then
                if type(val) ~= "table" then
                    add_err("expected table, got " .. type(val))
                    val = deep_copy(default)
                end
            end
        end

        return { value = val, errors = errors }
    end

    -- Has children: recursive merge
    local default = schema_node.default or {}
    local val = raw_value

    if val == nil then
        val = deep_copy(default)
        -- no further validation needed on a fully-defaulted table
        return { value = val, errors = errors }
    end

    if type(val) ~= "table" then
        add_err("expected table, got " .. type(val))
        return { value = deep_copy(default), errors = errors }
    end

    -- Check unknown fields first (before merge) so they get flagged
    local reject_unknown = opts.reject_unknown
    if schema_node.reject_unknown ~= nil then
        reject_unknown = schema_node.reject_unknown
    end

    local unknowns = {}
    for key, _ in pairs(val) do
        if schema_node.children[key] == nil then
            unknowns[#unknowns + 1] = key
        end
    end

    if reject_unknown and #unknowns > 0 then
        table.sort(unknowns)
        add_err("unknown field(s): " .. table.concat(unknowns, ", "))
    end

    -- Recursively merge each child
    local merged = deep_copy(default)
    for key, child_schema in pairs(schema_node.children) do
        local child_val = val[key]
        if child_val ~= nil or child_schema.default ~= nil then
            local child_result = _M.normalize_node(
                child_schema,
                child_val,
                {
                    path = (opts.path and (opts.path .. "." .. key)) or key,
                    reject_unknown = reject_unknown
                }
            )
            merged[key] = child_result.value
            for _, e in ipairs(child_result.errors) do
                errors[#errors + 1] = e
            end
        end
    end

    -- Also preserve any user fields not in schema (unless reject_unknown is set)
    if not reject_unknown and schema_node.preserve_unknown ~= false then
        for key, uv in pairs(val) do
            if schema_node.children[key] == nil then
                merged[key] = deep_copy(uv)
            end
        end
    end

    return { value = merged, errors = errors }
end

return _M

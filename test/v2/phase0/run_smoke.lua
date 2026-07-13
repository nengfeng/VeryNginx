-- Minimal busted-like runner for phase0 smoke tests under LuaJIT.
package.path = table.concat({
    "verynginx/?.lua",
    "verynginx/?/init.lua",
    "verynginx/lua_script/?.lua",
    "verynginx/lua_script/module/?.lua",
    "test/v2/phase0/?.lua",
    package.path,
}, ";")

local failures = 0
local passes = 0
local current = { suite = nil, befores = {} }

local function deep_copy(t)
    if type(t) ~= "table" then return t end
    local n = {}
    for k, v in pairs(t) do n[k] = deep_copy(v) end
    return n
end

_G.describe = function(name, fn)
    local prev = current
    current = { suite = name, befores = deep_copy(prev.befores) }
    print("\n== " .. name .. " ==")
    fn()
    current = prev
end

_G.before_each = function(fn)
    table.insert(current.befores, fn)
end

_G.it = function(name, fn)
    for _, b in ipairs(current.befores) do b() end
    local ok, err = pcall(fn)
    if ok then
        passes = passes + 1
        print("  PASS  " .. name)
    else
        failures = failures + 1
        print("  FAIL  " .. name)
        print("        " .. tostring(err))
    end
end

local function fail(msg)
    error(msg, 2)
end

_G.assert = setmetatable({}, {
    __call = function(_, cond, msg)
        if not cond then fail(msg or "assertion failed") end
    end
})

function assert.is_true(v) if v ~= true then fail("expected true, got " .. tostring(v)) end end
function assert.is_false(v) if v ~= false then fail("expected false, got " .. tostring(v)) end end
function assert.truthy(v) if not v then fail("expected truthy, got " .. tostring(v)) end end
function assert.is_truthy(v, msg) if not v then fail(msg or ("expected truthy, got " .. tostring(v))) end end
assert.are = {
    equal = function(a, b)
        if a ~= b then fail("expected " .. tostring(a) .. " == " .. tostring(b)) end
    end,
}

local function clear_module_cache()
    for k, _ in pairs(package.loaded) do
        if type(k) == "string" and (
            k:find("^core%.", 1) or
            k:find("^core/", 1) or
            k == "dkjson" or
            k == "json"
        ) then
            package.loaded[k] = nil
        end
    end
end

local specs = {
    "test/v2/phase0/reconciliation_spec.lua",
    "test/v2/phase0/promotion_enforce_spec.lua",
    "test/v2/phase0/lifecycle_readiness_spec.lua",
    "test/v2/phase0/scope_binding_spec.lua",
    "test/v2/phase0/ttl_ladder_spec.lua",
    "test/v2/phase0/kernel_blocking_controller_spec.lua",
}

for _, path in ipairs(specs) do
    clear_module_cache()
    print("\n######## loading " .. path)
    local ok, err = pcall(dofile, path)
    if not ok then
        failures = failures + 1
        print("LOAD FAIL " .. path .. ": " .. tostring(err))
    end
end

print(string.format("\nSummary: %d passed, %d failed", passes, failures))
if failures > 0 then os.exit(1) end

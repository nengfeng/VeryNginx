-- -*- coding: utf-8 -*-
-- @Disc    : bitwise ops that resolve LuaJIT bit -> bit32 -> pure-Lua shim
--
-- Production runs on OpenResty/LuaJIT where `require "bit"` always succeeds.
-- Unit tests, however, run under stock Lua 5.3 (CI), which has no `bit`
-- module — a bare top-level require there aborted the whole spec file. This
-- module resolves to LuaJIT's bit when present (zero runtime change), then
-- Lua 5.2's bit32, then a small pure-Lua fallback sufficient for this
-- codebase's 32-bit-and-below operands.

local _M

local ok, bit = pcall(require, "bit")
if ok then
    _M = bit
else
    ok, bit = pcall(require, "bit32")
    if ok then
        _M = bit
    else
        local function bitop(a, b, op)
            local r, p = 0, 1
            for _ = 0, 30 do
                local ab, bb = a % 2, b % 2
                local rb
                if op == "and" then
                    rb = (ab == 1 and bb == 1) and 1 or 0
                elseif op == "or" then
                    rb = (ab == 1 or bb == 1) and 1 or 0
                else
                    rb = (ab ~= bb) and 1 or 0
                end
                if rb == 1 then r = r + p end
                a = (a - ab) / 2
                b = (b - bb) / 2
                p = p * 2
            end
            return r
        end

        _M = {
            band = function(a, b) return bitop(a, b, "and") end,
            bor  = function(a, b) return bitop(a, b, "or") end,
            bxor = function(a, b) return bitop(a, b, "xor") end,
        }
    end
end

return _M

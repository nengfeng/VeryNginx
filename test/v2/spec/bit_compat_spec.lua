-- -*- coding: utf-8 -*-
-- core/bit_compat: the pure-Lua fallback is what actually runs under CI's
-- stock Lua 5.3 (no bit, no bit32). Pin the primitives, including the
-- sign-bit case the original 0..30 loop silently dropped.

describe("core.bit_compat", function()
    local bit = require "core.bit_compat"

    it("band / bor / bxor on byte-sized operands (the codebase's real inputs)", function()
        assert.equals(0x30, bit.band(0xF0, 0x3C))
        assert.equals(0x81, bit.bor(0x80, 0x01))
        assert.equals(0x02, bit.bxor(0x03, 0x01))
        assert.equals(0xFF, bit.band(0xFF, 0xFF))
    end)

    -- Regression (audit follow-up): the fallback loop covered bits 0..30 and
    -- silently dropped bit 31. Compare modulo 2^32 so the assertion also
    -- holds under LuaJIT's real bit library (which returns signed 32-bit).
    it("preserves bit 31 on full-width operands", function()
        assert.equals(0x80000000, bit.band(0x80000000, 0xFFFFFFFF) % 2 ^ 32)
        assert.equals(0x80000001, bit.bxor(0x80000000, 0x00000001) % 2 ^ 32)
        assert.equals(0xFFFFFFFF, bit.bor(0x80000000, 0x7FFFFFFF) % 2 ^ 32)
    end)
end)

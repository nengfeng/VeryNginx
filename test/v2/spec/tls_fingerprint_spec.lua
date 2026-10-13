-- TLS fingerprinting: JA4 extraction, kind-scoped matching, and the two dead
-- paths this module closed.
--
--   * Golden vector + section-A widths: test/v2/ja4_golden.lua (needs LuaJIT
--     FFI; busted's Lua 5.3 has none).
--   * infer_kind: bare-hash classification. Legacy entries have no "kind" key;
--     a JA4 hash misclassified as ja3 can never match a JA4 handshake, which
--     is a silent whole-subsystem failure.
--   * match(): kind isolation, family matching, and the explicit non-matchable
--     "tls" fallback namespace.
--   * tls_fingerprint.get(): the record the filter plugin now consults. The
--     old code read ctx.request.ja3_fingerprint, which nothing ever wrote.

describe("tls fingerprint", function()
    local tls, db

    setup(function()
        tls = require "core.tls_fingerprint"
        db  = require "core.fingerprint_db"
        db.reload()
    end)

    before_each(function()
        tls._reset()
    end)

    -- NOTE: the golden-vector / section-width checks live in
    -- test/v2/ja4_golden.lua because busted runs on system Lua 5.3, where the
    -- LuaJIT FFI the vendored JA4 module needs is unavailable. Same standing
    -- gate discipline as the PCRE battery (test/v2/factory_rules_battery.py).

    -- ------------------------------------------------------------------
    describe("kind inference (legacy entries without a kind field)", function()
        it("classifies real JA4 hashes as ja4", function()
            -- seeded default entries
            local m = db.match({ kind = "ja4", hash = "t13d201100_2b729b4bf6f3_9e7b989ebec8" })
            assert.is_truthy(m)
            -- and by inference alone (string target, no kind)
            assert.is_truthy(db.match("t13d201100_2b729b4bf6f3_9e7b989ebec8"))
        end)

        it("classifies JA4H hashes as ja4h, not ja3", function()
            assert.is_falsy(db.match({ kind = "ja4h", hash = "ge11cn060000_4e59edc1297a_4da5efaf0cbd" }))
            -- prefixed string keeps its namespace even when no entry exists
            assert.is_falsy(db.match("ja4h:ge11cn060000_4e59edc1297a_4da5efaf0cbd"))
        end)

        it("classifies a bare 32-char MD5 as ja3", function()
            -- legacy default entry, kind inferred
            assert.is_truthy(db.match("e7d705a3286e19ea42f587b344ee6865"))
        end)
    end)

    -- ------------------------------------------------------------------
    describe("match() namespace isolation", function()
        it("never matches the tls: fallback namespace", function()
            -- This is the whole point: the negotiated-cipher string is not a
            -- client identifier. Any match here would ban every visitor who
            -- negotiated the same cipher as a blocked tool.
            assert.is_nil(db.match("tls:TLSv1.3|TLS_AES_256_GCM_SHA384"))
            assert.is_nil(db.match({ kind = "tls", hash = "TLSv1.3|TLS_AES_256_GCM_SHA384" }))
        end)

        it("does not let a JA4 lookup hit a JA3 entry with the same string", function()
            local ja3_only = "669d4b813ef83a5e21b629f479629a8e"
            assert.is_truthy(db.match({ kind = "ja3", hash = ja3_only }))
            assert.is_nil(db.match({ kind = "ja4", hash = ja3_only }))
        end)

        it("is case-insensitive on hashes", function()
            local m = db.match("T13D201100_2B729B4BF6F3_9E7B989EBEC8")
            assert.is_truthy(m)
            assert.are.equal("IcedID", m.name)
        end)
    end)

    -- ------------------------------------------------------------------
    describe("family matching", function()
        local function with_entry(entry, fn)
            local ok, err = db.add(entry)
            assert.is_truthy(ok, tostring(err))
            db.reload()
            local ok2, err2 = pcall(fn)
            db.remove(entry.hash)
            db.reload()
            assert(ok2, tostring(err2))
        end

        it("matches a different B-segment of the same family", function()
            with_entry({
                hash = "t13d1516h2_111111111111_222222222222", kind = "ja4",
                match_mode = "family", name = "fam-test", action = "log",
            }, function()
                -- same A (transport/version/SNI/counts/ALPN), different B
                local m = db.match({ kind = "ja4", hash = "t13d1516h2_333333333333_444444444444" })
                assert.is_truthy(m)
                assert.are.equal("fam-test", m.name)
            end)
        end)

        it("does NOT match across families", function()
            with_entry({
                hash = "t13d1516h2_111111111111_222222222222", kind = "ja4",
                match_mode = "family", name = "fam-test", action = "log",
            }, function()
                assert.is_nil(db.match({ kind = "ja4", hash = "t12d0907h1_333333333333_444444444444" }))
            end)
        end)

        it("rejects family mode for ja3 and for truncated hashes", function()
            local ok, err, class = db.add({ hash = "e7d705a3286e19ea42f587b344ee6865", kind = "ja3",
                                            match_mode = "family", name = "x", action = "log" })
            assert.is_falsy(ok)
            assert.matches("ja4 or ja4h", err)
            -- class drives the HTTP status in the controller: malformed input
            -- must read as 4xx, not 5xx
            assert.are.equal("validation", class)

            -- a bare 10-char section A IS a complete JA4 family key and is a
            -- legitimate stored value; 9 chars is not
            local ok2, err2 = db.add({ hash = "t13d1516h2", kind = "ja4",
                                       match_mode = "family", name = "x", action = "log" })
            assert.is_truthy(ok2, tostring(err2))
            db.remove("t13d1516h2")
            db.reload()

            local ok3, err3 = db.add({ hash = "t13d1516h", kind = "ja4",
                                       match_mode = "family", name = "x", action = "log" })
            assert.is_falsy(ok3)
            assert.matches("section A", err3)
        end)

        it("rejects the non-matchable tls kind", function()
            local ok, err, class = db.add({ hash = "abc123", kind = "tls", name = "x", action = "log" })
            assert.is_falsy(ok)
            assert.matches("not matchable", err)
            assert.are.equal("validation", class)
        end)

        it("get() resolves a bare family prefix when told the kind", function()
            -- "t13d3013h2" has no section separator, so shape inference calls
            -- it ja3; the explicit kind is what makes the lookup work.
            local ok = db.add({ hash = "t13d3013h2", kind = "ja4", match_mode = "family",
                                name = "fam-get", action = "log" })
            assert.is_truthy(ok)
            db.reload()
            local byKind = db.get("t13d3013h2", "ja4")
            assert.is_truthy(byKind)
            assert.are.equal("fam-get", byKind.name)
            -- kind-less lookup still finds it rather than returning nil
            assert.is_truthy(db.get("t13d3013h2"))
            db.remove("t13d3013h2")
            db.reload()
        end)
    end)

    -- ------------------------------------------------------------------
    describe("persistence round-trip keeps kind + match_mode", function()
        it("survives a save/reload cycle", function()
            local ok = db.add({
                hash = "t12d0000h1_aaaaaaaaaaaa_bbbbbbbbbbbb", kind = "ja4",
                match_mode = "family", name = "rt-test", category = "test", action = "log",
            })
            assert.is_truthy(ok)
            db.reload()
            local m = db.get("t12d0000h1_aaaaaaaaaaaa_bbbbbbbbbbbb")
            assert.is_truthy(m)
            assert.are.equal("ja4", m.kind)
            assert.are.equal("family", m.match_mode)
            assert.are.equal("t12d0000h1", m.family)
            db.remove("t12d0000h1_aaaaaaaaaaaa_bbbbbbbbbbbb")
            db.reload()
            assert.is_nil(db.get("t12d0000h1_aaaaaaaaaaaa_bbbbbbbbbbbb"))
        end)
    end)

    -- ------------------------------------------------------------------
    describe("per-request record", function()
        it("prefers JA4 and derives the family", function()
            ngx.ctx[tls._ctx_key()] = "t13d1516h2_8daaf6152771_cb7bf5808d99"
            local rec = tls.get()
            assert.are.equal("ja4", rec.kind)
            assert.are.equal("ja4:t13d1516h2_8daaf6152771_cb7bf5808d99", rec.value)
            assert.are.equal("t13d1516h2", rec.family)
        end)

        it("falls back to the negotiated-cipher record, tagged tls:", function()
            ngx.ctx[tls._ctx_key()] = nil
            ngx.var.ssl_protocol = "TLSv1.3"
            ngx.var.ssl_cipher = "TLS_AES_256_GCM_SHA384"
            ngx.var.ssl_client_s_dn = ""
            local rec = tls.get()
            assert.are.equal("tls", rec.kind)
            assert.matches("^tls:", rec.value)
        end)

        it("caches the record on ngx.ctx (one computation per request)", function()
            ngx.ctx[tls._ctx_key()] = "t13d1516h2_8daaf6152771_cb7bf5808d99"
            local first = tls.get()
            ngx.ctx[tls._ctx_key()] = "t99d9999h9_deadbeefcafe_deadbeefcafe"
            local second = tls.get()
            assert.are.equal(first, second)  -- same table: not recomputed
        end)
    end)

    -- ------------------------------------------------------------------
    describe("legacy shim", function()
        it("core.ja3 keeps returning the prefixed string", function()
            ngx.ctx[tls._ctx_key()] = "t13d1516h2_8daaf6152771_cb7bf5808d99"
            local ja3 = require "core.ja3"
            assert.are.equal("ja4:t13d1516h2_8daaf6152771_cb7bf5808d99", ja3.get_fingerprint())
            assert.is_nil(ja3.get_ja3())  -- no JA3 module here, and that's honest
        end)
    end)
end)
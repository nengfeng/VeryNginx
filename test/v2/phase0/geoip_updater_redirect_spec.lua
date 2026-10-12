-- -*- coding: utf-8 -*-
-- Unit tests for geoip_updater's redirect-following download path.
-- lua-resty-http (vendored 0.17.2) does NOT follow redirects, and GitHub's
-- releases/latest/download endpoints always answer 302 -> release-assets
-- CDN, so the old plain request_uri call reported "HTTP 302" and every
-- such mirror was treated as dead ("all mirrors failed ... HTTP 302").
-- These tests drive _download_file/_get_remote_etag through a scripted
-- fake resty.http, including the real two-hop GitHub chain shape, the
-- redirect cap, and Location resolution.

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
if not _G.ngx.log then _G.ngx.log = function() end end
_G.ngx.WARN = _G.ngx.WARN or 6
_G.ngx.ERR = _G.ngx.ERR or 5
_G.ngx.time = _G.ngx.time or function() return 1700000000 end

describe("geoip_updater redirect following", function()
    local updater, resolve, download, etag_of
    local fake -- { requests = {...}, responses = { [url] = {...} } }
    local DEST = "/tmp/vnt-spec/geoip-redirect-dl.mmdb"

    local function new_fake_http()
        return {
            new = function()
                return {
                    set_timeout = function() end,
                    request_uri = function(_, uri, params)
                        fake.requests[#fake.requests + 1] =
                            { url = uri, method = params and params.method }
                        local r = fake.responses[uri]
                        if not r then return nil, "connection refused: " .. uri end
                        if r.err then return nil, r.err end
                        return { status = r.status, headers = r.headers or {},
                                 body = r.body or "" }
                    end,
                }
            end,
        }
    end

    setup(function()
        package.loaded["core.audit"] = { log = function() end }
        package.loaded["core.dict_guard"] = {
            set = function() return true end,
            incr = function() return true end,
            write_failed = function() end,
        }
        package.loaded["core.geoip"] = {
            reload = function() return true end,
            get_status = function() return {} end,
            validate_mmdb = function() return true end,
        }
        package.loaded["core.config"] = { geoip = {} }
        os.execute("mkdir -p /tmp/vnt-spec")
        updater = require "core.geoip_updater"
        resolve = updater._resolve_redirect
        download = updater._download_file
        etag_of = updater._get_remote_etag
        assert.truthy(resolve, "_resolve_redirect must be exported")
        assert.truthy(download, "_download_file must be exported")
        assert.truthy(etag_of, "_get_remote_etag must be exported")
    end)

    setup(function()
        fake = { requests = {}, responses = {} }
        package.loaded["resty.http"] = new_fake_http()
    end)

    before_each(function()
        fake.requests = {}
        fake.responses = {}
    end)

    teardown(function()
        package.loaded["resty.http"] = nil
        os.remove(DEST)
    end)

    describe("_resolve_redirect", function()
        it("passes absolute http(s) URLs through", function()
            assert.are.equal("https://b/y.mmdb",
                resolve("https://a/x.mmdb", "https://b/y.mmdb"))
            assert.are.equal("http://b/y",
                resolve("https://a/x", "http://b/y"))
        end)
        it("resolves scheme-relative references", function()
            assert.are.equal("https://cdn.z/mmdb",
                resolve("https://a/x/y", "//cdn.z/mmdb"))
        end)
        it("resolves root-relative references against scheme+host(+port)", function()
            assert.are.equal("https://a:8443/r/mmdb",
                resolve("https://a:8443/x/y", "/r/mmdb"))
        end)
        it("resolves relative references against the base directory", function()
            assert.are.equal("https://a/dir/next.mmdb",
                resolve("https://a/dir/page", "next.mmdb"))
        end)
        it("rejects empty/nil locations and non-http bases", function()
            assert.is_nil(resolve("https://a/x", ""))
            assert.is_nil(resolve("https://a/x", nil))
            assert.is_nil(resolve("ftp://a/b", "/x"))
            assert.is_nil(resolve("not-a-url", "/x"))
        end)
    end)

    describe("_download_file", function()
        it("follows the real GitHub two-hop 302 chain and writes the body", function()
            local m3 = "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb"
            local hop2 = "https://github.com/Loyalsoldier/geoip/releases/download/202610080033/Country.mmdb"
            local hop3 = "https://release-assets.githubusercontent.com/blob/1/Country.mmdb"
            fake.responses[m3] = { status = 302, headers = { Location = hop2 } }
            fake.responses[hop2] = { status = 302, headers = { Location = hop3 } }
            fake.responses[hop3] = { status = 200, body = "MMDB-FAKE-BODY" }
            local ok, err = download(m3, DEST)
            assert.is_nil(err)
            assert.is_true(ok)
            assert.are.equal(3, #fake.requests)
            assert.are.equal(m3, fake.requests[1].url)
            assert.are.equal(hop2, fake.requests[2].url)
            assert.are.equal(hop3, fake.requests[3].url)
            for _, r in ipairs(fake.requests) do
                assert.are.equal("GET", r.method)
            end
            local f = assert(io.open(DEST, "rb"))
            local body = f:read("*a")
            f:close()
            assert.are.equal("MMDB-FAKE-BODY", body)
        end)

        it("writes a plain 200 response with a single request (no regression)", function()
            local u = "https://raw.githubusercontent.com/x/y.mmdb"
            fake.responses[u] = { status = 200, body = "DIRECT" }
            assert.is_true(download(u, DEST))
            assert.are.equal(1, #fake.requests)
            assert.are.equal("DIRECT", (io.open(DEST, "rb"):read("*a")))
        end)

        it("still fails a bare 302 without Location (original bug surface)", function()
            local u = "https://x.example/a.mmdb"
            fake.responses[u] = { status = 302, headers = {} }
            local ok, err = download(u, DEST)
            assert.is_false(ok)
            assert.truthy(tostring(err):find("HTTP 302", 1, true))
        end)

        it("resolves relative Location headers against the requesting URL", function()
            local base = "https://m.example/a/b/c"
            fake.responses[base] = { status = 302, headers = { Location = "d.mmdb" } }
            fake.responses["https://m.example/a/b/d.mmdb"] = { status = 200, body = "OK" }
            assert.is_true(download(base, DEST))
            assert.are.equal("https://m.example/a/b/d.mmdb", fake.requests[2].url)
        end)

        it("caps redirect chains and reports the failure", function()
            fake.responses["https://l.example/a"] =
                { status = 302, headers = { Location = "https://l.example/b" } }
            fake.responses["https://l.example/b"] =
                { status = 302, headers = { Location = "https://l.example/a" } }
            local ok, err = download("https://l.example/a", DEST)
            assert.is_false(ok)
            assert.truthy(tostring(err):find("too many redirects", 1, true))
            assert.are.equal(6, #fake.requests, "MAX_REDIRECTS+1 requests max")
        end)

        it("stops when a redirect target is unreachable", function()
            local base = "https://ok.example/a"
            fake.responses[base] = { status = 302, headers = { Location = "https://down.example/b" } }
            local ok, err = download(base, DEST)
            assert.is_false(ok)
            assert.truthy(tostring(err):find("connection refused", 1, true))
        end)
    end)

    describe("_get_remote_etag", function()
        it("follows redirects and returns the FINAL response's ETag", function()
            local m3 = "https://github.com/r/releases/latest/download/Country.mmdb"
            local hop2 = "https://github.com/r/releases/download/v9/Country.mmdb"
            fake.responses[m3] = { status = 302, headers = { Location = hop2 } }
            fake.responses[hop2] = { status = 200,
                headers = { ["ETag"] = "\"deadbeef\"" } }
            assert.are.equal("\"deadbeef\"", etag_of(m3))
            assert.are.equal(2, #fake.requests)
            assert.are.equal("HEAD", fake.requests[1].method)
            assert.are.equal("HEAD", fake.requests[2].method)
        end)

        it("returns nil (not a crash) on network failure", function()
            assert.is_nil(etag_of("https://nowhere.example/x"))
        end)
    end)
end)

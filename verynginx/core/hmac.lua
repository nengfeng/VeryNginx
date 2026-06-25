local _M = {}

local hmac_sha256

if ngx.hmac_sha256 then
    hmac_sha256 = ngx.hmac_sha256
else
    local ok, ffi = pcall(require, "ffi")
    if ok then
        ffi.cdef[[
            const void *EVP_sha256(void);
            unsigned char *HMAC(const void *evp_md, const void *key, int key_len,
                                const unsigned char *data, int data_len,
                                unsigned char *md, unsigned int *md_len);
        ]]
        local C = ffi.C
        local evp_sha256 = C.EVP_sha256
        local hmac = C.HMAC
        hmac_sha256 = function(key, data)
            local md = ffi.new("unsigned char[32]")
            local md_len = ffi.new("unsigned int[1]")
            local ret = hmac(evp_sha256(), key, #key, data, #data, md, md_len)
            if not ret then
                return nil
            end
            return ffi.string(md, 32)
        end
    else
        hmac_sha256 = nil
        ngx.log(ngx.WARN, "hmac: no HMAC-SHA256 implementation available")
    end
end

function _M.hmac_sha256(key, data)
    return hmac_sha256(key, data)
end

return _M
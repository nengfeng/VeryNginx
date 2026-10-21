-- resty.sha — https://github.com/openresty/lua-resty-string
--
-- Vendored as the dependency of resty/sha256.lua, which lua-resty-mysql v0.31
-- requires.
--
-- Copyright (C) by Yichun Zhang (agentzh)


local ffi = require "ffi"


local _M = { _VERSION = '0.17' }


ffi.cdef[[
typedef unsigned long SHA_LONG;
typedef unsigned long long SHA_LONG64;

enum {
    SHA_LBLOCK = 16
};
]];

return _M

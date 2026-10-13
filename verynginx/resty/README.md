# Vendored Lua modules

| 文件 | 来源 | 版本 | 许可 |
|------|------|------|------|
| maxminddb.lua | lua-resty-maxminddb | — | 见文件头 |
| http.lua / http_headers.lua / http_connect.lua | ledgetech/lua-resty-http | v0.17.2 (tag 固定) | BSD-2-Clause (http.LICENSE) |
| ja4.lua / ja4h.lua / ja4/utils.lua | nemethhh/lua-resty-ja4 | v0.2.0 (tag 固定) | MIT (ja4.LICENSE)，含一处本地加固（见下） |

由 geoip_updater(数据库下载/ETag 探测)与 alerting(webhook)使用。
升级时替换三文件并同步本表与 LICENSE。

ja4/utils.lua 有一处本地加固（VENDOR PATCH）：上游用 `ffi.C` 绑定
`EVP_sha256`/`EVP_Digest`，静态链接 OpenSSL 的 nginx（LNMP 默认
`--with-openssl`）可能不导出这些符号，模块会在**加载期**直接
`undefined symbol` 失败、拖垮每一次 TLS 握手。改为先试 `ffi.C`，失败
再显式 `ffi.load("libcrypto.so.*")`；SHA-256 输出与 OpenSSL 版本无关，
混用安全。升级上游时需重新应用。

# VeryNginx v2 安装手册

## 系统要求

| 依赖 | 最低版本 | 说明 |
|---|---|---|
| Linux / macOS | — | 生产环境推荐 Linux |
| Python | 2.7+ / 3.x | 用于 `install.py` 脚本 |
| GCC / Make | — | 编译 OpenResty 时需要 |
| PCRE, OpenSSL, zlib 开发库 | — | 编译 OpenResty 时需要 |
| LuaJIT | 2.1 | OpenResty 内置；手动安装时需单独编译 |
| Nginx | 1.25+ | 需编译 `ngx_http_lua_module` |

---

## 方法一：install.py 一键安装（推荐）

自动下载并编译 OpenResty + VeryNginx，适合首次使用。

```bash
# 1. 克隆仓库
git clone https://github.com/alexazhou/VeryNginx.git
cd VeryNginx

# 2. 一键安装（OpenResty + VeryNginx）
python install.py install

# 3. 设置管理员密码
python install.py hash-password your_password
```

复制输出的 `password_hash`，编辑 `/opt/verynginx/verynginx/configs/config.json`，填入 `admin[0].password_hash` 字段。

```bash
# 4. 启动
/opt/verynginx/openresty/nginx/sbin/nginx

# 5. 访问管理面板
# http://<your-ip>/verynginx/index.html
# 默认用户名: verynginx
```

### 目录结构

```
/opt/verynginx/
├── openresty/                     # OpenResty 安装目录
│   └── nginx/
│       ├── sbin/nginx             # Nginx 二进制
│       └── conf/nginx.conf        # 主配置文件
│
└── verynginx/                     # VeryNginx 应用代码
    ├── core/                      # 核心框架（12 个 Lua 模块）
    ├── matcher/                   # 匹配器（11 个类型）
    ├── action/                    # 动作处理器
    ├── plugin/                    # 插件（7 个：filter, proxy_pass 等）
    ├── api/                       # REST API 控制器
    ├── dashboard/                 # Web 管理界面（Vue 3 SPA）
    ├── nginx_conf/                # Nginx 配置片段
    │   ├── in_external.conf
    │   ├── in_http_block.conf
    │   └── in_server_block.conf
    ├── lua_script/                # 捆绑的 Lua 库
    │   ├── module/                # dkjson, json, cookie, util
    │   └── resty/dns/             # DNS 解析器
    ├── configs/                   # 运行时配置
    │   ├── config.json            # 主配置（由 Web UI 写入）
    │   ├── config.default.json    # 默认配置模板
    │   └── backups/               # 自动备份（保留最近 10 份）
    └── on_rewrite.lua             # rewrite 阶段入口
    └── on_access.lua              # access 阶段入口
    └── on_log.lua                 # log 阶段入口
```

---

## 方法二：使用已有的 OpenResty

如果已经安装了 OpenResty，只需部署 VeryNginx 应用代码。

```bash
# 1. 克隆仓库，只复制 verynginx 目录
git clone https://github.com/alexazhou/VeryNginx.git
cd VeryNginx

# 2. 复制应用代码
cp -r verynginx /opt/verynginx/

# 3. 初始化配置
cp verynginx/configs/config.default.json /opt/verynginx/verynginx/configs/config.json
mkdir -p /opt/verynginx/verynginx/configs/backups
chmod -R 755 /opt/verynginx/verynginx/configs

# 4. 设置密码
python install.py hash-password your_password
# 复制输出，填入 config.json 的 admin[0].password_hash

# 5. 编辑 OpenResty nginx.conf，加入以下三个 include
#
#    在 http 配置块之外:
#    include /opt/verynginx/verynginx/nginx_conf/in_external.conf;
#
#    在 http 配置块之内:
#    include /opt/verynginx/verynginx/nginx_conf/in_http_block.conf;
#
#    在 server 配置块之内:
#    include /opt/verynginx/verynginx/nginx_conf/in_server_block.conf;

# 6. 启动 / 重载
/path/to/openresty/nginx/sbin/nginx -s reload
```

> **注意**：如果 OpenResty 安装路径不是 `/opt/verynginx/openresty`，确保 in_external.conf 中的 `lua_package_path` 指向正确的绝对路径，并且 on_rewrite/on_access/on_log 中的路径也相应调整。

---

## 方法三：使用 Nginx + lua-nginx-module + lua-resty-core

VeryNginx 不需要完整的 OpenResty 发行版，只需标准 Nginx 加 Lua 模块即可。

### 3.1 编译安装 LuaJIT

```bash
curl -L https://github.com/openresty/luajit2/archive/refs/tags/v2.1-20250117.tar.gz -o luajit2.tar.gz
tar -xzf luajit2.tar.gz
cd luajit2-*
make && make install

# 确保安装到了标准路径
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
```

### 3.2 编译 Nginx（带 lua-nginx-module）

```bash
# 下载 nginx
curl -L https://nginx.org/download/nginx-1.26.0.tar.gz -o nginx.tar.gz
tar -xzf nginx.tar.gz

# 下载 lua-nginx-module
curl -L https://github.com/openresty/lua-nginx-module/archive/refs/tags/v0.10.27.tar.gz -o lua-nginx-module.tar.gz
tar -xzf lua-nginx-module.tar.gz

# 下载 ngx_devel_kit（必需）
curl -L https://github.com/vision5/ngx_devel_kit/archive/refs/tags/v0.3.3.tar.gz -o ndk.tar.gz
tar -xzf ndk.tar.gz

# 配置并编译
cd nginx-1.26.0
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1

./configure --prefix=/opt/verynginx/openresty/nginx \
    --with-http_v2_module \
    --with-http_sub_module \
    --with-http_stub_status_module \
    --with-pcre-jit \
    --with-stream \
    --with-stream_ssl_module \
    --add-module=../ngx_devel_kit-0.3.3 \
    --add-module=../lua-nginx-module-0.10.27

make && make install
```

### 3.3 安装 lua-resty-core

```bash
# lua-resty-core 提供与 OpenResty 兼容的 Lua API
curl -L https://github.com/openresty/lua-resty-core/archive/refs/tags/v0.1.28.tar.gz -o lua-resty-core.tar.gz
tar -xzf lua-resty-core.tar.gz
cd lua-resty-core-*
make install  # 或手动复制 .lua 文件到 Lua 模块路径
```

### 3.4 部署 VeryNginx

```bash
git clone https://github.com/alexazhou/VeryNginx.git
cd VeryNginx

cp -r verynginx /opt/verynginx/
cp verynginx/configs/config.default.json /opt/verynginx/verynginx/configs/config.json
mkdir -p /opt/verynginx/verynginx/configs/backups
chmod -R 755 /opt/verynginx/verynginx/configs

# 设置密码
python install.py hash-password your_password
```

### 3.5 配置 nginx.conf

参考 `/opt/p/VeryNginx/nginx.conf` 或以下模板：

```nginx
user  nginx;
worker_processes  auto;
error_log  logs/error.log  warn;
pid        logs/nginx.pid;

events {
    worker_connections  1024;
}

# === 外部块：upstream 和 Lua 包路径 ===
include /opt/verynginx/verynginx/nginx_conf/in_external.conf;

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout  65;

    # === HTTP 块：共享字典和初始化 ===
    include /opt/verynginx/verynginx/nginx_conf/in_http_block.conf;

    server {
        listen       80;

        # === Server 块：请求处理和代理 ===
        include /opt/verynginx/verynginx/nginx_conf/in_server_block.conf;

        # 可选的根路径跳转
        location = / {
            return 302 /verynginx/index.html;
        }
    }
}
```

> **提示**：如果使用 LUAJIT 而非 OpenResty，可能需要调整 `lua_package_path` 以包含 lua-resty-core 的安装路径。

---

## 方法四：Docker

```bash
git clone https://github.com/alexazhou/VeryNginx.git
cd VeryNginx
docker build -t verynginx .
docker run -d --name=verynginx -p 8080:80 verynginx
```

访问 `http://localhost:8080/verynginx/index.html`，默认用户名密码 `verynginx`/`verynginx`。

如需自定义端口：`docker run -d --name=verynginx -p 你想要的端口:80 verynginx`

将已有配置挂载到容器：
```bash
docker run -d --name=verynginx \
    -p 8080:80 \
    -v /host/path/config.json:/opt/verynginx/verynginx/configs/config.json \
    verynginx
```

---

## 安装后配置

### 设置管理员密码

```bash
cd /path/to/VeryNginx
python install.py hash-password my_secure_password
# 输出: p1$12000$<salt>$<hash>
```

复制输出的完整字符串，编辑 `/opt/verynginx/verynginx/configs/config.json`：

```json
{
    "admin": [
        {
            "user": "verynginx",
            "password_hash": "p1$12000$<salt>$<hash>",
            "enable": true
        }
    ]
}
```

设置完成后**必须重启或重载 Nginx** 使新配置生效（首次安装）。

### 启动与停止

```bash
# 启动
/opt/verynginx/openresty/nginx/sbin/nginx

# 停止
/opt/verynginx/openresty/nginx/sbin/nginx -s stop

# 重载（修改 nginx.conf 后）
/opt/verynginx/openresty/nginx/sbin/nginx -s reload
```

### 验证安装

访问 http://你的服务器地址/verynginx/index.html，看到登录页面即安装成功。

---

## 更新

```bash
cd /path/to/VeryNginx
git pull

# 仅更新 VeryNginx 代码（保留现有配置）
python install.py update verynginx

# 更新 OpenResty
python install.py update openresty
```

---

## 常见安装问题

| 问题 | 原因 | 解决 |
|---|---|---|
| `lua_package_path` 找不到模块 | 路径配置不对 | 确认 in_external.conf 中的路径与实际安装路径一致 |
| `proxy_ssl_verify on` 导致上游连接失败 | 自签名证书 | 默认已是 `off`；如需验证请配置 CA 证书 |
| 管理面板 404 | nginx.conf 未正确 include | 确认三个 include 指令都已添加 |
| 登录后提示密码无效 | `password_hash` 未设置或格式错误 | 使用 `python install.py hash-password` 重新生成 |
| Docker 中无法访问面板 | Docker 端口映射错误 | 确认 `docker run -p` 映射了容器 80 端口 |

---

## 参考

- [DESIGN_V2.md](DESIGN_V2.md) — v2 架构设计文档
- [VeryNginx Wiki](https://github.com/alexazhou/VeryNginx/wiki)

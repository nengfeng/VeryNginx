var tips = new Object();

tips.tips_vm = null;
tips.show_tips = function(group){

    $('.tips_content').collapse('hide');

    if(tips.tips_vm != null){
        tips.tips_vm.$data = {tips:tips.data[group]};
        return;
    } 

    tips.tips_vm = new Vue({
        el: '#verynginx_tips',
        data: {tips:tips.data[group]},
    });

}

tips.toggle = function(tips_container){
    $(tips_container).children(':last').collapse('toggle');
}

tips.data = {
    'basic_matcher':[
        {"tips":"Purpose","content":"A Matcher used to match request"},
        {"tips":"Introduce","content":"When a request match all condition in a matcher, the request hit the matcher"},
        {"tips":"Usage","content":["You can add one or more conditions to a matcher",
		                              "A empty matcher will match all request",
                                      "Supported types: IP, Host, URI, UserAgent, Referer, Args, Header, Cookie, Method, Composite"]}
    ],
    'basic_response':[
        {"tips":"Purpose","content":"Response templates define reusable HTTP responses"},
        {"tips":"Introduce","content":"Templates can be referenced by rules via the 'response' field"},
        {"tips":"Usage","content":["Set Content-Type and body for block/response actions"]}
    ],
    'action_scheme_lock':[
        {"tips":"Purpose","content":"Lock all request on http or https"},
        {"tips":"Introduce","content":"Under rule.scheme_lock. This action will check if the scheme current using fit to the rule. If scheme wrong, it will give a 302 redirect to the right scheme" },
        {"tips":"Usage","content":["https/http means only https/http,both means not limit",
                                   "From top to bottom to match, and only use the first match rule"]
        },
    ],
    'action_redirect':[
        {"tips":"Purpose","content":"Redirect to other address"},
        {"tips":"Introduce","content":"Under rule.redirect. Redirect client to another URL"},
        {"tips":"Usage","content":["From top to bottom to match, and only use the first match rule",
                                   "Supports 301 (permanent) and 302 (temporary) status codes"]}
    ],
    'action_uri_rewrite':[
        {"tips":"Purpose","content":"Internal URI rewrite (transparent to client)"},
        {"tips":"Introduce","content":"Under rule.uri_rewrite. Rewrite the request URI internally"},
        {"tips":"Usage","content":["The rewrite happens before any proxying",
                                   "Useful for mapping legacy URLs to new paths"]}
    ],
    'action_browser_verify':[
        {"tips":"Purpose","content":"Browser verification via Cookie + JavaScript challenge"},
        {"tips":"Introduce","content":"Under rule.browser_verify. Blocks non-browser traffic (bots, CC attacks)"},
        {"tips":"Usage","content":["May block search engine crawlers",
                                   "Recommended to enable only under attack, or for specific paths"]}
    ],
    'action_frequency_limit':[
        {"tips":"Purpose","content":"Rate limiting - restrict request frequency per client"},
        {"tips":"Introduce","content":"Under rule.frequency_limit. Limit max requests in a time window"},
        {"tips":"Usage","content":["Rate format: <count>/<unit> (e.g. 100/m, 10/s, 1000/h)",
                                   "From top to bottom to match, and only use the first match rule"]}
    ],
    'action_filter':[
        {"tips":"Purpose","content":"WAF - Block malicious requests"},
        {"tips":"Introduce","content":"Under rule.filter. Filter can block, accept, or respond with custom content"},
        {"tips":"Usage","content":["Combine with matchers for complex WAF rules",
                                   "Pre-built rules for SQL injection, path traversal, scanners",
                                   "From top to bottom to match, and only use the first match rule"]}
    ],
    'backend_proxy_pass':[
        {"tips":"Purpose","content":"Reverse proxy requests to upstream backends"},
        {"tips":"Introduce","content":"Under rule.proxy_pass. Routes matching requests to configured upstreams"},
        {"tips":"Usage","content":["Requires a backend_upstream definition with health_check, tls, and timeout",
                                   "Supports WebSocket, DNS caching, and weighted load balancing"]}
    ],
    'backend_static_file':[
        {"tips":"Purpose","content":"Serve static files from local filesystem"},
        {"tips":"Introduce","content":"Under rule.static_file. Serve local files for matching requests"},
        {"tips":"Usage","content":["Configure root directory and file path pattern",
                                   "Optionally set Cache-Control expires header"]}
    ],
    'backend_upstream':[
        {"tips":"Purpose","content":"Define upstream backend servers"},
        {"tips":"Introduce","content":"Upstream definitions include nodes, health check, TLS, and timeout"},
        {"tips":"Usage","content":["Each node has host, port, and optional weight",
                                   "Health check probes are sent periodically",
                                   "Unhealthy nodes are automatically removed from rotation"]}
    ],
    'plugin_config':[
        {"tips":"Purpose","content":"Plugin system - enable/disable, set priority, mark critical"},
        {"tips":"Introduce","content":"Seven built-in plugins: filter, frequency_limit, browser_verify, router, proxy_pass, static_file, summary"},
        {"tips":"Usage","content":["Priority determines execution order (lower = earlier)",
                                   "Critical plugins cause 503 on error",
                                   "Plugins can be independently enabled or disabled"]}
    ],
    'summary_general':[
        {"tips":"Purpose","content":"General request statistics settings"},
        {"tips":"Introduce","content":"Configure statistics time windows (1m, 5m, 1h, all), flush and persist intervals"},
    ],
    'summary_collect':[
        {"tips":"功能介绍","content":"访问统计功能可以按 URI 查看各状态码的详细请求数据"},
    ],
    'system_general':[
        {"tips":"Purpose","content":"General system settings"},
        {"tips":"Introduce","content":"base_uri, cookie_prefix, dashboard_host, body limits, proxy settings"},
    ],
    'system_admin':[
        {"tips":"Purpose","content":"Admin user management"},
        {"tips":"Introduce","content":"Manage admin accounts with PBKDF2-HMAC-SHA256 password hashing"},
        {"tips":"Usage","content":["Generate password hash with: python install.py hash-password <password>",
                                   "Optional: install lua-resty-bcrypt or lua-resty-argon2 for stronger hashing"]}
    ],
    'system_allconfig':[
        {"tips":"功能介绍","content":"查看和编辑全部配置的 JSON"},
        {"tips":"操作说明","content":["点击保存配置将保存全部配置到服务器，并即刻生效",
		                              "点击读取配置将从服务器获取当前使用的配置",
									  "配置保存在 /opt/verynginx/verynginx/configs/config.json",
                                      "备份保存在 configs/backups/ 目录下",
                                      "删除 config.json 可恢复出厂设置"]}
    ],
}

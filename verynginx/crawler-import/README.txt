Crawler IP-range drop-in directory
==================================

For servers that cannot reach the vendor URLs (typical inside mainland China),
download the file from another machine and place it HERE with its original
filename:

  common-crawlers.json    https://developers.google.com/static/crawling/ipranges/common-crawlers.json
  gptbot.json             https://openai.com/gptbot.json
  bingbot.json            https://www.bing.com/toolbox/bingbot.json
  applebot.json           https://search.developer.apple.com/applebot.json
  duckduckbot.json        https://duckduckgo.com/duckduckbot.json

Do NOT rename the file — the importer derives the filename from the vendor URL
basename. The file must be the raw JSON document as published.

Then in the dashboard: IP reputation -> "Refresh list" (拉取并写入). Each
vendor is fetched over HTTP first; on failure the file in this directory is
used instead. The "取自" (source) column shows "本地导入" for entries that came
from here.

To enable the fallback, set in config.json:

  "ip_reputation": { "crawler_import_dir": "/opt/verynginx/crawler-import" }

(or use the panel's raw config editor). Empty string disables the fallback.
Files are read on each refresh, so replacing a file just needs another click.

Notes:
- Only IPv4 prefixes are used (Google's file also has IPv6 entries, ignored).
- Prefixes broader than /8 are rejected by config validation (trust boundary).
- Baiduspider publishes no range file; it is verified by DNS instead.

AI crawlers without published ranges (Claude / DeepSeek / Bytespider / Doubao)
=============================================================================
A User-Agent string is trivially forged — it must NEVER grant access by itself.
Use ip_reputation.allowed_ai_crawlers: each entry is a CLAIM that triggers DNS
verification (PTR must be inside `domains`, and that name must resolve back to
the same IP). Only a verified IP is treated as the crawler; a DNS answer of
"not you" (FAKE) is blocked. Configuration example (raw JSON config editor):

  "ip_reputation": {
    "crawler_verify": { "enabled": true },
    "allowed_ai_crawlers": [
      { "key": "claude", "ua_pattern": "(?i)claudebot",
        "domains": ["anthropic.com", "claude.ai"] },
      { "key": "deepseek", "ua_pattern": "(?i)deepseekbot",
        "domains": ["deepseek.com"] },
      { "key": "bytespider", "ua_pattern": "(?i)bytespider",
        "domains": ["bytedance.com", "byteimg.com"] },
      { "key": "doubao", "ua_pattern": "(?i)doubaobot",
        "domains": ["bytedance.com", "doubao.com"] }
    ]
  }

IMPORTANT: the `domains` above are PLACEHOLDERS — verify each vendor's actual
reverse-DNS domains before enabling (e.g. with `dig -x <known-good-ip>`). A
wrong domain makes real requests FAIL verification (403); an empty domains
list is rejected by config save. Ships empty on purpose. Gemini / Google-
Extended are already covered by Google's published ranges (common-crawlers
.json); GPT / ChatGPT-User by OpenAI's gptbot.json — those two do not need
this list.

Crawler IP-range drop-in directory
==================================

For servers that cannot reach the vendor URLs (typical inside mainland China),
download the file from another machine and place it HERE with its original
filename:

  common-crawlers.json    https://developers.google.com/static/crawling/ipranges/common-crawlers.json
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

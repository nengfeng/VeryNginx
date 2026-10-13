#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VeryNginx v2 —— FoxIO JA4+ 映射表导入工具 (tools/import_ja4db.py)

用途
----
把 FoxIO 官方 JA4+ 映射表 `ja4plus-mapping.csv` 转换成 VeryNginx 指纹库条目
(entry)，供运维导入 `config.json` 的 `fingerprints.entries`，或直接通过
`POST /verynginx/fingerprints` 逐条写入。

CSV 来源
--------
    https://github.com/FoxIO-LLC/ja4   (仓库根目录 ja4plus-mapping.csv)
    原始文件: https://github.com/FoxIO-LLC/ja4/raw/main/ja4plus-mapping.csv
本工具**不联网**，CSV 必须以本地路径传入（位置参数或环境变量 VN_JA4DB_CSV）。
请自行从官方仓库取得该 CSV 并校验其内容；本工具只做格式转换，不负责取数。

CSV 表头（11 列，逗号分隔，允许引号包裹，允许空列）::

    Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes

⚠️ 警示：这是识别库，不是黑名单
--------------------------------
官方映射表里绝大多数行是**正常客户端**（curl / Python requests / Go net/http /
浏览器 / IoT 设备）。这些指纹同样是合法运维工具和真实访客的指纹，批量 block 会
造成误伤。因此本工具：

* 默认 `action = log`（只记录，不处置）；
* 默认只导入**威胁类**行（命中 THREAT_KEYWORDS），浏览器/正常客户端/IoT 全部跳过；
* 同一个 (kind, hash) 若同时被良性应用与威胁应用共用，默认**整条跳过**
  （歧义防护，见下），因为对共用指纹做 JA4 级阻断/挑战必然会打到正常流量
  （典型：GoLang 库与 Sliver C2 共用 t13d190900_9dc949149365_97f8aa674fd9）。

是否升级为 block/challenge 是**运维在自己流量上观测后的决定**，不要直接照搬。

许可提示
--------
* JA4（TLS 指纹规范本体）为 **BSD-3-Clause** 许可（FoxIO LLC）。
* **JA4H**（HTTP 指纹）及 `ja4plus-mapping.csv` 属 **FoxIO License 1.1**，
  不是 BSD；再分发/商用前请自行核对
  https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE 。
* 本脚本只读取 CSV 并生成条目文本，不内嵌 CSV 数据。

后端契约（core/fingerprint_db.lua）
----------------------------------
entry = {hash, kind, match_mode, name, category, action, description, enable}
  kind       : ja3 | ja4 | ja4h（本工具只产出 ja4 / ja4h；ja4s/ja4x/ja4t/ja4tscan
               是不同算法，后端没有对应 kind，直接忽略并计数）
  match_mode : exact | family（family 仅对 ja4/ja4h 有效，且 hash 长度 ≥ 10）
  hash       : 不带 `ja4:`/`ja4h:` 前缀，小写
  action     : block | challenge | log
  enable     : 规范键（list() 返回的是 enabled，两者都要注意，见 AGENTS.md §7.6）
config.json 里 entries 是 **JSON 字符串数组**（schema items="string"），
本工具 `--out` 输出的 JSONL 与之一一对应（每行一个 entry 的 JSON 字符串）。

只依赖 Python 标准库：csv / json / argparse / re / os / sys / http.client /
urllib.parse（--apply 用 http.client 发请求，原因见 post_json 的注释）。
"""

import argparse
import csv
import http.client
import json
import os
import re
import sys
from urllib.parse import urlsplit as _urlsplit

TOOL_VERSION = "1.0"

# ---------------------------------------------------------------------------
# 常量：CSV 来源 / 表头 / 列语义
# ---------------------------------------------------------------------------

CSV_SOURCE_URL = "https://github.com/FoxIO-LLC/ja4"
CSV_FILENAME = "ja4plus-mapping.csv"

EXPECTED_COLUMNS = [
    "Application", "Library", "Device", "OS",
    "ja4", "ja4s", "ja4h", "ja4x", "ja4t", "ja4tscan",
    "Notes",
]

# 只处理这两个列（后端 kind 只支持 ja3/ja4/ja4h）。
KIND_COLUMNS = [("ja4", "ja4"), ("ja4h", "ja4h")]
IGNORED_HASH_COLUMNS = ["ja4s", "ja4x", "ja4t", "ja4tscan"]

# 参与威胁关键词检索的文本列（哈希列不参与，避免 hex 串误命中 "c2" 之类的短词）。
TEXT_COLUMNS = ["Application", "Library", "Device", "OS", "Notes"]

# ---------------------------------------------------------------------------
# 常量：威胁关键词表（运维可直接增删）
# ---------------------------------------------------------------------------
# 判定逻辑：这些列的文本（大小写不敏感）命中任一关键词 → 该行视为威胁类。
# 短关键词（≤3 字符）按单词边界匹配，避免 "c2" 命中 "abc23def" 这类噪声。
THREAT_KEYWORDS = (
    # --- C2 / 后门 / 远控 ---
    "cobalt strike", "cobaltstrike", "beacon", "meterpreter",
    "sliver", "sliver agent", "havoc", "brute ratel", "bruteratel",
    "icyid", "icedid", "qakbot", "pikabot", "darkgate", "lumma", "evilginx",
    "asyncrat", "quasar", "njrat", "nanocore", "remcos", "empire",
    "mimikatz", "mythic", "koadic", "merlin", "posh c2", "c2",
    "command and control", "command-and-control", "implant",
    # --- 通用恶意软件 ---
    "malware", "trojan", "ransomware", "botnet", "backdoor", "dropper",
    "stealer", "keylogger", "cryptominer", "coinminer", "loader",
    # --- 扫描器 / 爆破 / 攻击工具 ---
    "scanner", "portscan", "port scan", "masscan", "zgrab", "zmap",
    "nmap", "nuclei", "sqlmap", "nikto", "nessus", "openvas", "burp",
    "wpscan", "gobuster", "dirbuster", "censys", "shodan",
    "bruteforce", "brute force", "credential stuffing", "vuln scanner",
    "vulnerability scanner", "exploit scanner", "internet scanner",
    # 注意：这里刻意**不**收录 browser / curl / python / go / okhttp /
    # node / okhttp / iot / cisco / plex / okhttp —— 那些是正常客户端。
)

# 分类映射：(关键词, category)，按顺序命中即止；全部不命中时威胁行默认 "attack"。
CATEGORY_RULES = (
    ("cobalt", "attack"), ("sliver", "attack"), ("havoc", "attack"),
    ("icedid", "attack"), ("qakbot", "attack"), ("pikabot", "attack"),
    ("darkgate", "attack"), ("lumma", "attack"), ("evilginx", "attack"),
    ("beacon", "attack"), ("malware", "attack"), ("trojan", "attack"),
    ("ransomware", "attack"), ("botnet", "attack"), ("implant", "attack"),
    ("c2", "attack"), ("command and control", "attack"), ("command-and-control", "attack"),
    ("scanner", "scanner"), ("masscan", "scanner"), ("zgrab", "scanner"),
    ("nmap", "scanner"), ("nuclei", "scanner"), ("sqlmap", "scanner"),
    ("nikto", "scanner"), ("nessus", "scanner"), ("burp", "scanner"),
    ("bruteforce", "scanner"), ("brute force", "scanner"),
    ("credential stuffing", "scanner"),
)

DEFAULT_THREAT_CATEGORY = "attack"
DEFAULT_BENIGN_CATEGORY = "automation"
VALID_ACTIONS = ("block", "challenge", "log")
VALID_MATCH_MODES = ("exact", "family")
MIN_FAMILY_HASH_LEN = 10

# ---------------------------------------------------------------------------
# 常量：hash 形态校验
# ---------------------------------------------------------------------------
# 说明（重要）：
# 任务书给出的字面正则
#     ja4  : ^[a-z]\d{2}[a-z]\d{4}[a-z]\d{2}_[0-9a-f]{12}_[0-9a-f]{12}$
#     ja4h : ^[a-z]{2}\d{2}[a-z-z]{2}\d{6}[a-z]{4}_ + 4 段 12hex
# 与官方 CSV 的真实数据**不自洽**：字面 ja4 正则漏掉了 JA4_a 末尾 2 字符的
# ALPN 段（t13d1516h2 / t13d181000 都会判非法），字面 ja4h 正则把
# JA4H_a 的 "cookie flag + referer flag + header count"（cc nn nn + 2 位计数）
# 误当成 6 位数字 + 4 位字母，同样会把 ge11cn060000 这类官方值判非法。
# 因此默认使用按官方规范还原的 real 形态；`--hash-pattern spec` 保留字面正则，
# 便于对照与回归（用它跑官方 CSV 会把几乎所有行计入 invalid，这是预期行为）。
#
# 真实形态：
#   JA4_a = 协议(1) + 版本(2) + SNI 标志(1) + cipher/ext 计数(4) + ALPN(2)
#   JA4H_a = method(2) + HTTP 版本(2) + cookie 标志(1) + referer 标志(1)
#             + header 计数(2) + Accept-Language 前 4 字符
#   JA4H = a_b_c_d，官方资料里 c/d 段（cookie 相关）在无 cookie 时可省略，
#          APNIC 官方表格即给出三段式 ge11cn060000_4e59edc1297a_4da5efaf0cbd，
#          所以这里接受 3 段与 4 段两种形态。
JA4_RE = re.compile(r"^[a-z]\d{2}[a-z]\d{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
# a_b_c（3 段，官方/APNIC 表格里 c/d 省略的形态）或 a_b_c_d（4 段，完整形态）
JA4H_RE = re.compile(r"^[a-z]{2}\d{2}[a-z]{2}\d{2}[a-z0-9]{4}_"
                     r"[0-9a-f]{12}(?:_[0-9a-f]{12}){1,2}$")
SPEC_JA4_RE = re.compile(r"^[a-z]\d{2}[a-z]\d{4}[a-z]\d{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
SPEC_JA4H_RE = re.compile(r"^[a-z]{2}\d{2}[a-z-z]{2}\d{6}[a-z]{4}_"
                          r"[0-9a-f]{12}(?:_[0-9a-f]{12}){3}$")

HASH_PATTERNS = {
    "real": {"ja4": JA4_RE, "ja4h": JA4H_RE},
    "spec": {"ja4": SPEC_JA4_RE, "ja4h": SPEC_JA4H_RE},
}

AMBIGUOUS_NOTE = "ambiguous: shared by %d applications"
MAX_NOTE_LEN = 200

ENV_CSV = "VN_JA4DB_CSV"
ENV_OUT = "VN_JA4DB_OUT"
ENV_URL = "VN_URL"
ENV_COOKIE = "VN_COOKIE"
ENV_CSRF = "VN_CSRF"
ENV_EXISTING = "VN_JA4DB_EXISTING"


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

def eprint(*args):
    """统计/告警走 stderr，保证 `--out -` 时 stdout 是纯 JSONL。"""
    print(*args, file=sys.stderr)


def has_keyword(text_lower, keyword):
    """短关键词按单词边界匹配，长关键词按子串匹配。"""
    if len(keyword) <= 3:
        return re.search(r"(?<![0-9a-z])%s(?![0-9a-z])" % re.escape(keyword),
                         text_lower) is not None
    return keyword in text_lower


def clean(value):
    return (value or "").strip()


def truncate(text, limit=MAX_NOTE_LEN):
    text = clean(text).replace("\r", " ").replace("\n", " ")
    if len(text) > limit:
        return text[:limit - 3] + "..."
    return text


def classify_threat(text_lower):
    for keyword in THREAT_KEYWORDS:
        if has_keyword(text_lower, keyword):
            return keyword
    return None


def classify_category(text_lower, threat):
    if not threat:
        return DEFAULT_BENIGN_CATEGORY
    for keyword, category in CATEGORY_RULES:
        if has_keyword(text_lower, keyword):
            return category
    return DEFAULT_THREAT_CATEGORY


def infer_kind(hash_value, patterns):
    """返回 (kind, hash) 或 (None, None)。先按列名判定，再退回形态判定。"""
    for kind, pattern in (("ja4", patterns["ja4"]), ("ja4h", patterns["ja4h"])):
        if pattern.match(hash_value):
            return kind, hash_value
    return None, None


def pattern_kind(hash_value, patterns):
    """判断一段 hash 看起来像 ja4 还是像 ja4h（用于报告为什么非法）。"""
    if "_" in hash_value:
        head = hash_value.split("_", 1)[0]
        if len(head) == 10 and head[:1].isalpha():
            return "ja4"
        if len(head) in (12, 13):
            return "ja4h"
    return "unknown"


# ---------------------------------------------------------------------------
# CSV 读取
# ---------------------------------------------------------------------------

class CsvError(Exception):
    pass


def read_csv(path):
    """打开 CSV，返回 (reader, header_map)。表头按名字（大小写不敏感）映射，
    多余列忽略、缺列补空 —— FoxIO 的表头是固定的，但空列/引号差异不该让工具崩。"""
    try:
        handle = open(path, "r", newline="", encoding="utf-8-sig", errors="replace")
    except IOError as exc:
        raise CsvError("cannot open CSV %s: %s" % (path, exc))
    reader = csv.reader(handle)
    try:
        rows = iter(reader)
        try:
            header = next(rows)
        except StopIteration:
            handle.close()
            raise CsvError("CSV is empty: %s" % path)
        header_map = {}
        for idx, name in enumerate(header):
            key = clean(name).lower()
            if key and key not in header_map:
                header_map[key] = idx
        missing = [c for c in EXPECTED_COLUMNS
                   if c.lower() not in header_map]
        if missing:
            handle.close()
            raise CsvError(
                "CSV header is missing column(s): %s (found: %s)"
                % (", ".join(missing), ", ".join(clean(h) for h in header)))
        # 列数不足的行按空串补齐
        def _padded():
            for row in rows:
                if len(row) < len(header):
                    row = list(row) + [""] * (len(header) - len(row))
                yield row
        return handle, header_map, _padded()
    except Exception:
        handle.close()
        raise


# ---------------------------------------------------------------------------
# 解析 + 归并
# ---------------------------------------------------------------------------

def collect_groups(rows, header_map, stats, patterns, verbose):
    """逐行 → 按 (kind, hash) 归并成组。

    归并规则（防误伤的核心）：
      1. 同一 (kind, hash) 出现在多个 Application 行 → 合成一条，name 用
         "A / B" 合并，description 标注 "ambiguous: shared by N applications"。
      2. 同组内既有威胁行又有良性行 → 整条默认跳过（歧义防护），计数上报。
      3. 只有良性行 → 默认跳过（威胁过滤），--all/--include-benign 才导入。
    """
    groups = {}
    for line_no, row in enumerate(rows, start=2):  # 1 = 表头
        stats["rows_total"] += 1
        if not any(clean(cell) for cell in row):
            stats["rows_blank"] += 1
            continue
        stats["rows_used"] += 1

        def cell(column):
            idx = header_map[column.lower()]
            return clean(row[idx]) if idx < len(row) else ""

        app = cell("Application")
        library = cell("Library")
        device = cell("Device")
        os_name = cell("OS")
        notes = cell("Notes")

        label = app or library or device or os_name or "unknown"
        text_lower = " ".join([app, library, device, os_name, notes]).lower()
        hit = classify_threat(text_lower)
        threat = hit is not None
        stats["rows_threat" if threat else "rows_benign"] += 1

        for column, column_kind in KIND_COLUMNS:
            raw = cell(column)
            if not raw:
                continue
            stats["hash_candidates"] += 1
            value = raw.lower().replace(" ", "")
            kind, normalised = infer_kind(value, patterns)
            if kind is None:
                stats["hash_invalid"] += 1
                if verbose and len(stats["samples_invalid"]) < 10:
                    stats["samples_invalid"].append(
                        "line %d: %s=%s (looks like %s)"
                        % (line_no, column, truncate(raw, 60),
                           pattern_kind(value, patterns)))
                continue
            if column_kind != kind:
                # 列名与形态冲突：以形态为准（CSV 偶尔会放错列）
                stats["kind_mismatch"] += 1
            key = (kind, normalised)
            group = groups.get(key)
            if group is None:
                group = {
                    "kind": kind,
                    "hash": normalised,
                    "labels": [],
                    "libraries": [],
                    "devices": [],
                    "oses": [],
                    "notes": [],
                    "rows": 0,
                    "threat": False,
                    "benign": False,
                    "keyword": hit,
                    "first_line": line_no,
                }
                groups[key] = group
            group["rows"] += 1
            if group["rows"] > 1:
                stats["duplicates"] += 1
            if label not in group["labels"]:
                group["labels"].append(label)
            if library and library not in group["libraries"]:
                group["libraries"].append(library)
            if device and device not in group["devices"]:
                group["devices"].append(device)
            if os_name and os_name not in group["oses"]:
                group["oses"].append(os_name)
            if notes and truncate(notes) not in group["notes"]:
                group["notes"].append(truncate(notes))
            if threat:
                group["threat"] = True
                if hit and not group["keyword"]:
                    group["keyword"] = hit
            else:
                group["benign"] = True

        # 被忽略的列里若出现 ja4/ja4h 形态的值，多半是列错位（例如 Cobalt Strike
        # 那行被写进了 ja4t）。这些值一律不导入（JA4X 是 X.509 证书指纹，JA4T 是
        # 扫描态组合，JA4S 是单次握手摘要 —— 都不是后端支持的 kind，误当 JA4/H
        # 匹配会制造假阳性），但必须报出来，否则运维只会看到“一条都没导入”。
        for column in IGNORED_HASH_COLUMNS:
            raw = cell(column)
            if not raw:
                continue
            value = raw.lower().replace(" ", "")
            if patterns["ja4"].match(value) or patterns["ja4h"].match(value):
                stats["ignored_column_suspects"] += 1
                if verbose and len(stats["samples_ignored"]) < 10:
                    stats["samples_ignored"].append(
                        "line %d: %s=%s (形态像 ja4/ja4h，但该列不在导入范围)"
                        % (line_no, column, truncate(raw, 60)))

    for group in groups.values():
        group["text_lower"] = " ".join(
            group["labels"] + group["libraries"] + group["devices"] +
            group["oses"] + group["notes"]).lower()
        group["ambiguous"] = len(group["labels"]) > 1
        group["mixed"] = group["threat"] and group["benign"]
    return groups


def build_description(group):
    """确定性拼接（不含时间戳/随机值），保证同一 CSV → 同一字节输出。"""
    bits = ["FoxIO %s" % CSV_FILENAME]
    bits.append("application=" + " / ".join(group["labels"]))
    if group["libraries"]:
        bits.append("library=" + "/".join(group["libraries"]))
    if group["devices"]:
        bits.append("device=" + "/".join(group["devices"]))
    if group["oses"]:
        bits.append("os=" + "/".join(group["oses"]))
    if group["notes"]:
        bits.append("notes=" + " | ".join(group["notes"]))
    bits.append("threat=" + ("yes" if group["threat"] else "no"))
    if group["ambiguous"]:
        bits.append(AMBIGUOUS_NOTE % len(group["labels"]))
    if group["mixed"]:
        bits.append("mixed benign/threat sharing this hash")
    return truncate("; ".join(bits), 600)


def select_entries(groups, opts, stats, verbose):
    """按过滤规则挑出要导入的条目。输出顺序按 (kind, hash) 排序，
    与 CSV 行顺序无关 —— 便于 diff 与幂等比对。"""
    entries = []
    for key in sorted(groups.keys()):
        group = groups[key]
        threat = group["threat"]
        if group["mixed"] and not opts.allow_ambiguous:
            stats["skipped_ambiguous"] += 1
            if verbose and len(stats["samples_ambiguous"]) < 20:
                stats["samples_ambiguous"].append(
                    "%s %s  <- %s" % (group["kind"], group["hash"],
                                      " / ".join(group["labels"])))
            continue
        if not threat and not opts.include_benign:
            stats["skipped_benign"] += 1
            continue
        if threat:
            stats["imported_threat"] += 1
        else:
            stats["imported_benign"] += 1

        mode = opts.match_mode
        if mode == "family" and len(group["hash"]) < MIN_FAMILY_HASH_LEN:
            raise CsvError(
                "match_mode=family needs >= %d chars, got %s"
                % (MIN_FAMILY_HASH_LEN, group["hash"]))

        category = opts.category or classify_category(group["text_lower"], threat)
        if group["kind"] == "ja4h" and len(group["hash"].split("_")) == 3:
            # FoxIO 映射表里存在三段式 JA4H（a_b_c，APNIC 表格即如此），但本项目
            # verynginx/resty/ja4h.lua 的 hash 模式恒定输出 a_b_c_d 四段（没有
            # cookie 时 C/D 填 EMPTY_HASH=000000000000）。所以三段式条目在
            # match_mode=exact 下可能永远匹配不上，必须报出来而不是默默入库。
            stats["ja4h_three_segment"] += 1
            if verbose and len(stats["samples_ja4h3"]) < 10:
                stats["samples_ja4h3"].append(group["hash"])
        entries.append({
            "hash": group["hash"],
            "kind": group["kind"],
            "match_mode": mode,
            "name": " / ".join(group["labels"]),
            "category": category,
            "action": opts.action,
            "description": build_description(group),
            "enable": True,
        })
    return entries


# ---------------------------------------------------------------------------
# 输出 / 合并
# ---------------------------------------------------------------------------

def encode_entry(entry):
    """与 config.json entries 一致的单行 JSON 字符串（定序 key、无随机内容）。"""
    return json.dumps(entry, ensure_ascii=False, separators=(",", ":"))


def load_existing(path):
    """读取已有条目（JSONL 或 JSON 数组），返回原始字符串列表（保持原样，
    便于把本工具没碰过的条目原样写回去）。
    兼容两种形态：config.json 的 JSON 字符串数组 / 原生对象数组。"""
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            raw_text = handle.read()
    except IOError as exc:
        raise CsvError("cannot read --existing %s: %s" % (path, exc))
    stripped = raw_text.strip()
    if not stripped:
        return []
    items = []
    if stripped[0] == "[":
        try:
            decoded = json.loads(stripped)
        except ValueError as exc:
            raise CsvError("--existing is not valid JSON array: %s" % exc)
        if not isinstance(decoded, list):
            raise CsvError("--existing JSON array expected, got %s"
                           % type(decoded).__name__)
        items = decoded
    else:
        for line in stripped.splitlines():
            line = line.strip()
            if line:
                items.append(line)
    return items


def entry_key(entry, patterns):
    if not isinstance(entry, dict):
        return None
    raw = entry.get("hash")
    if not isinstance(raw, str) or not raw:
        return None
    value = raw.lower()
    kind = entry.get("kind")
    if kind not in ("ja3", "ja4", "ja4h"):
        kind, _ = infer_kind(value, patterns)
        if kind is None:
            kind = "ja3"
    return "%s:%s" % (kind, value)


def merge_with_existing(existing_items, entries):
    """已存在（同 kind+hash）→ 原地更新；新条目 → 追加到末尾。
    未被本工具触及的条目按原始字符串保留（连同 enabled/enable 键差异）。"""
    merged = list(existing_items)
    replaced = 0
    position = {}
    for idx, item in enumerate(merged):
        obj = item
        if isinstance(item, str):
            try:
                obj = json.loads(item)
            except ValueError:
                continue
        key = entry_key(obj, HASH_PATTERNS["real"]) if isinstance(obj, dict) else None
        if key and key not in position:
            position[key] = idx
    for entry in entries:
        key = entry_key(entry, HASH_PATTERNS["real"])
        encoded = encode_entry(entry)
        if key in position:
            merged[position[key]] = encoded
            replaced += 1
        else:
            position[key] = len(merged)
            merged.append(encoded)
    return merged, replaced


def write_output(items, path, stats):
    """写 JSONL。path == "-" → stdout。"""
    payload = "".join(item + "\n" for item in items)
    if path == "-":
        sys.stdout.write(payload)
        sys.stdout.flush()
        stats["output"] = "stdout"
    else:
        directory = os.path.dirname(os.path.abspath(path))
        if directory and not os.path.isdir(directory):
            raise CsvError("output directory does not exist: %s" % directory)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(payload)
        stats["output"] = path


# ---------------------------------------------------------------------------
# --apply：调用 VeryNginx API
# ---------------------------------------------------------------------------

def post_json(url, payload, cookie, csrf, timeout):
    """POST 一个 JSON body，返回 (status, text)；任何异常都归一化成 (0, 原因文本)。

    为什么不用 urllib.request 发：urllib 在 HTTPHandler.do_open() 里对所有请求头
    做 `.title()`，会把 "X-CSRF-Token" 变成 "X-Csrf-Token"。OpenResty 的
    `ngx.req.get_headers()` 返回的是**线上原始大小写**，而 api/csrf.lua 里写的是
    `get_headers()["X-CSRF-Token"]` —— 大小写对不上就是 403，条目会全部导入失败。
    所以这里直接用 http.client（同样是标准库），它不碰请求头大小写。
    """
    parts = _urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return 0, "invalid url: %s" % url
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
        "Cookie": cookie,
        "X-CSRF-Token": csrf,          # 大小写必须原样
        "User-Agent": "verynginx-import_ja4db/%s" % TOOL_VERSION,
        "Connection": "close",
    }
    connection = None
    try:
        if parts.scheme == "https":
            import ssl  # 仅 https 时引入
            connection = http.client.HTTPSConnection(
                parts.hostname, parts.port, timeout=timeout,
                context=ssl.create_default_context())
        else:
            connection = http.client.HTTPConnection(
                parts.hostname, parts.port, timeout=timeout)
        connection.request("POST", path, body=payload, headers=headers)
        response = connection.getresponse()
        text = response.read().decode("utf-8", "replace")
        return response.status, text
    except OSError as exc:
        # ConnectionRefusedError / socket.timeout / ssl.SSLError 都是 OSError
        name = type(exc).__name__
        if name in ("timeout", "TimeoutError"):
            return 0, "timeout after %.1fs (检查 --url 是否可达、面板是否在本机)" % timeout
        return 0, "network error (%s): %s" % (name, exc)
    except http.client.HTTPException as exc:
        return 0, "http protocol error: %s" % exc
    except Exception as exc:  # 防御性：单条异常不中断整批
        return 0, "unexpected error (%s): %s" % (type(exc).__name__, exc)
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def apply_entries(entries, opts, stats):
    """逐条 POST /verynginx/fingerprints；失败不中断，最后统一报告并以非 0 退出。"""
    url = opts.url.rstrip("/")
    if not url.endswith("/verynginx/fingerprints"):
        url = url + "/verynginx/fingerprints"
    failures = []
    for entry in entries:
        body = json.dumps(entry, ensure_ascii=False).encode("utf-8")
        status, text = post_json(url, body, opts.cookie, opts.csrf, opts.timeout)
        if status == 0:
            failures.append((entry, text))
            continue
        if not 200 <= status < 300:
            failures.append((entry, "HTTP %d %s" % (status, truncate(text, 200))))
            continue
        try:
            decoded = json.loads(text)
        except ValueError:
            failures.append((entry, "non-JSON response: %s" % truncate(text, 200)))
            continue
        if not isinstance(decoded, dict) or decoded.get("ret") != "success":
            failures.append((entry, "ret=%s message=%s"
                             % (decoded.get("ret") if isinstance(decoded, dict) else "?",
                                truncate(decoded.get("message", "")
                                         if isinstance(decoded, dict) else text, 200))))
            continue
        stats["applied_ok"] += 1

    if failures:
        stats["applied_fail"] = len(failures)
        eprint("")
        eprint("=== 导入失败清单 (%d 条) ===" % len(failures))
        for entry, reason in failures:
            eprint("  [%s] %s  (%s)" % (entry["kind"], entry["hash"], reason))
        return 1
    return 0


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------

def print_summary(stats, opts, csv_path):
    eprint("")
    eprint("=== JA4 映射导入摘要 (import_ja4db %s) ===" % TOOL_VERSION)
    eprint("  CSV                    : %s" % csv_path)
    eprint("  过滤模式               : %s" %
           ("全部条目 (--all)" if opts.include_benign else "仅威胁类"))
    eprint("  action                 : %s   match_mode: %s" %
           (opts.action, opts.match_mode))
    eprint("  hash 正则档位          : %s" % opts.hash_pattern)
    eprint("  数据行总数             : %d" % stats["rows_total"])
    eprint("  空行跳过               : %d" % stats["rows_blank"])
    eprint("  有效数据行             : %d" % stats["rows_used"])
    eprint("  威胁行 / 良性行        : %d / %d" %
           (stats["rows_threat"], stats["rows_benign"]))
    eprint("  hash 候选 (ja4/ja4h 列): %d" % stats["hash_candidates"])
    eprint("  非法 hash 跳过         : %d" % stats["hash_invalid"])
    eprint("  列名/形态冲突         : %d" % stats["kind_mismatch"])
    if stats["ignored_column_suspects"]:
        eprint("  被忽略列里的疑似 ja4/h : %d  (ja4s/ja4x/ja4t/ja4tscan 列，"
               "不导入，见 -v)" % stats["ignored_column_suspects"])
    eprint("  归并后 (kind,hash) 数  : %d" % stats["groups"])
    eprint("  重复行折叠             : %d" % stats["duplicates"])
    eprint("  导入条目               : %d (威胁 %d / 良性 %d)" %
           (stats["imported_threat"] + stats["imported_benign"],
            stats["imported_threat"], stats["imported_benign"]))
    if stats["ja4h_three_segment"]:
        eprint("  ⚠️ 三段式 ja4h 条目     : %d  (resty/ja4h.lua 恒输出 4 段，"
               "exact 下可能永不命中)" % stats["ja4h_three_segment"])
    eprint("  跳过·良性(未威胁命中)  : %d" % stats["skipped_benign"])
    eprint("  跳过·歧义(良性+威胁)   : %d" % stats["skipped_ambiguous"])
    if stats.get("updated_existing"):
        eprint("  覆盖已有条目             : %d  (同 kind+hash 原地更新)"
               % stats["updated_existing"])
    if opts.apply:
        eprint("  API 导入成功 / 失败    : %d / %d" %
               (stats["applied_ok"], stats["applied_fail"]))
    if stats.get("output"):
        eprint("  输出                   : %s (%d 行)" %
               (stats["output"], stats["imported_threat"] + stats["imported_benign"]))
    if stats["samples_invalid"]:
        eprint("")
        eprint("  非法 hash 样例:")
        for line in stats["samples_invalid"]:
            eprint("    - %s" % line)
    if stats["samples_ambiguous"]:
        eprint("")
        eprint("  歧义跳过样例 (良性+威胁共用同一 hash，用 --allow-ambiguous 强制导入):")
        for line in stats["samples_ambiguous"]:
            eprint("    - %s" % line)
    if stats["samples_ignored"]:
        eprint("")
        eprint("  可疑列错位样例 (值不在 ja4/ja4h 列，未导入):")
        for line in stats["samples_ignored"]:
            eprint("    - %s" % line)
    if stats["samples_ja4h3"]:
        eprint("")
        eprint("  三段式 ja4h 样例 (确认本机 ja4h 输出形态后再决定是否保留):")
        for line in stats["samples_ja4h3"]:
            eprint("    - %s" % line)


def print_dry_run(entries, opts):
    limit = max(0, opts.dry_run_limit)
    shown = entries[:limit] if limit else entries
    print("=== --dry-run：将导入 %d 条 (不写文件、不发请求) ===" % len(entries))
    for entry in shown:
        print("  [%-4s] %-40s action=%-8s cat=%-10s mode=%-6s name=%s"
              % (entry["kind"], entry["hash"], entry["action"],
                 entry["category"], entry["match_mode"], entry["name"]))
    if len(shown) < len(entries):
        print("  ... 其余 %d 条省略（用 --dry-run-limit 调整）"
              % (len(entries) - len(shown)))
    if opts.action != "log":
        print("  ⚠️  action=%s：批量处置未经本机流量观测验证，"
              "请先 --dry-run 复核并在灰度中观察" % opts.action)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="import_ja4db.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="把 FoxIO ja4plus-mapping.csv 转成 VeryNginx 指纹库条目"
                    "（默认 action=log，默认只导入威胁类，歧义条目默认跳过）。",
        epilog="示例:\n"
               "  # 1) 只看统计\n"
               "  import_ja4db.py ja4plus-mapping.csv\n"
               "  # 2) 生成 JSONL（可离线审阅后再落 config.json）\n"
               "  import_ja4db.py ja4plus-mapping.csv --out /tmp/ja4.jsonl\n"
               "  # 3) 试运行\n"
               "  import_ja4db.py ja4plus-mapping.csv --dry-run\n"
               "  # 4) 通过 API 导入（cookie/csrf 建议走环境变量，避免进 shell history）\n"
               "  VN_URL=https://host VN_COOKIE='verynginx_session=...' \\\n"
               "  VN_CSRF=... ./import_ja4db.py ja4plus-mapping.csv --apply\n")
    parser.add_argument("csv", nargs="?", default=None,
                        help="本地 ja4plus-mapping.csv 路径（默认取环境变量 %s）"
                             % ENV_CSV)
    parser.add_argument("--out", default=None,
                        help="JSONL 输出路径（每行一个 entry 的 JSON 字符串，"
                             "形态同 config.json entries）。'-' 表示 stdout，"
                             "默认取环境变量 %s，不设则 '-'。默认：-" % ENV_OUT)
    parser.add_argument("--action", choices=VALID_ACTIONS, default="log",
                        help="条目 action，默认 log。覆盖为 block/challenge "
                             "属于未经验证的批量处置（会打印告警）")
    parser.add_argument("--match-mode", choices=VALID_MATCH_MODES, default="exact",
                        help="匹配模式，默认 exact。family 只适用于 ja4/ja4h 且 "
                             "hash ≥ %d 字符（JA4_a 段）" % MIN_FAMILY_HASH_LEN)
    parser.add_argument("--category", default=None,
                        help="强制覆盖所有条目 category（默认按关键词自动判定，"
                             "威胁默认 %s，良性默认 %s）"
                             % (DEFAULT_THREAT_CATEGORY, DEFAULT_BENIGN_CATEGORY))
    parser.add_argument("--all", "--include-benign", dest="include_benign",
                        action="store_true",
                        help="导入全部条目（含浏览器/正常客户端/IoT）。"
                             "注意：--all 不会解除歧义跳过，"
                             "需要再给 --allow-ambiguous")
    parser.add_argument("--allow-ambiguous", action="store_true",
                        help="强制导入“良性+威胁共用同一 hash”的条目"
                             "（默认跳过，这是防误伤的关键闸门）")
    parser.add_argument("--existing", default=None,
                        help="已有条目文件（JSONL 或 JSON 数组），同 kind+hash "
                             "原地更新而非追加，默认取环境变量 %s" % ENV_EXISTING)
    parser.add_argument("--hash-pattern", choices=sorted(HASH_PATTERNS.keys()),
                        default="real",
                        help="hash 校验正则档位：real=按官方规范还原（默认）；"
                             "spec=任务书字面正则（对官方 CSV 会大量判非法，仅供对照）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只打印将要导入的条目摘要，不写文件、不发请求")
    parser.add_argument("--dry-run-limit", type=int, default=30,
                        help="--dry-run 最多打印多少条（0 = 不限），默认 30")
    parser.add_argument("--apply", action="store_true",
                        help="逐条 POST 到 VeryNginx 指纹 API（需 --url/--cookie/--csrf，"
                             "三个都必须提供；也可用环境变量 %s/%s/%s）"
                             % (ENV_URL, ENV_COOKIE, ENV_CSRF))
    parser.add_argument("--url", default=None,
                        help="VeryNginx 基地址或完整 URL（如 https://host 或 "
                             "https://host/verynginx/fingerprints）；默认取 %s" % ENV_URL)
    parser.add_argument("--cookie", default=None,
                         help="会话 Cookie 请求头完整值（如 "
                              "'verynginx_session=...'）；默认取 %s" % ENV_COOKIE)
    parser.add_argument("--csrf", default=None,
                         help="X-CSRF-Token 值（GET /verynginx/csrf 获取）；默认取 %s"
                              % ENV_CSRF)
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="单次 HTTP 超时秒数，默认 10")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="在摘要里附非法 hash / 歧义跳过样例")
    parser.add_argument("--version", action="version",
                        version="import_ja4db %s (CSV source: %s)"
                                % (TOOL_VERSION, CSV_SOURCE_URL))
    return parser


def new_stats():
    return {
        "rows_total": 0, "rows_blank": 0, "rows_used": 0,
        "rows_threat": 0, "rows_benign": 0,
        "hash_candidates": 0, "hash_invalid": 0, "kind_mismatch": 0,
        "ignored_column_suspects": 0,
        "groups": 0, "duplicates": 0,
        "imported_threat": 0, "imported_benign": 0,
        "skipped_benign": 0, "skipped_ambiguous": 0,
        "updated_existing": 0, "ja4h_three_segment": 0,
        "applied_ok": 0, "applied_fail": 0,
        "samples_invalid": [], "samples_ambiguous": [], "samples_ignored": [],
        "samples_ja4h3": [],
        "output": None,
    }


def resolve(args):
    """补齐环境变量默认值 + 必填校验，返回 (ok, exit_code)。"""
    if not args.csv:
        args.csv = os.environ.get(ENV_CSV)
    if not args.csv:
        eprint("FATAL: missing CSV path (positional arg or $%s)" % ENV_CSV)
        return False, 2
    if not os.path.isfile(args.csv):
        eprint("FATAL: CSV not found: %s" % args.csv)
        return False, 2
    if args.out is None:
        args.out = os.environ.get(ENV_OUT, "-")
    if args.existing is None:
        args.existing = os.environ.get(ENV_EXISTING)
    if args.apply:
        args.url = args.url or os.environ.get(ENV_URL)
        args.cookie = args.cookie or os.environ.get(ENV_COOKIE)
        args.csrf = args.csrf or os.environ.get(ENV_CSRF)
        missing = [name for name, value in (("--url", args.url),
                                            ("--cookie", args.cookie),
                                            ("--csrf", args.csrf)) if not value]
        if missing:
            eprint("FATAL: --apply requires %s (and their env fallbacks)"
                   % ", ".join(missing))
            return False, 2
    if args.action != "log":
        eprint("⚠️  WARNING: --action=%s applies an unverified mass action."
               % args.action)
        eprint("⚠️  ja4plus-mapping.csv 是识别库不是黑名单；curl/Python/Go/浏览器"
               "都是常见客户端。批量 block/challenge 极易误伤，")
        eprint("⚠️  请先用 --dry-run 复核，并在自己流量上观测后再灰度启用。")
    if args.include_benign and not args.allow_ambiguous:
        eprint("NOTE: --all/--include-benign 不会解除歧义跳过；"
               "需要一并导入共用 hash 的条目请加 --allow-ambiguous。")
    return True, 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    ok, code = resolve(args)
    if not ok:
        return code

    stats = new_stats()
    patterns = HASH_PATTERNS[args.hash_pattern]
    handle = None
    try:
        handle, header_map, rows = read_csv(args.csv)
        groups = collect_groups(rows, header_map, stats, patterns, args.verbose)
    except CsvError as exc:
        eprint("FATAL: %s" % exc)
        return 2
    finally:
        if handle is not None:
            handle.close()

    stats["groups"] = len(groups)
    try:
        entries = select_entries(groups, args, stats, args.verbose)
    except CsvError as exc:
        eprint("FATAL: %s" % exc)
        return 2

    exit_code = 0
    if args.dry_run:
        print_dry_run(entries, args)
        stats["output"] = "(dry-run: 未写文件)"
    else:
        items = [encode_entry(entry) for entry in entries]
        if args.existing:
            try:
                existing_items = load_existing(args.existing)
                merged, replaced = merge_with_existing(
                    existing_items, entries)
                items = merged
                stats["updated_existing"] = replaced
            except CsvError as exc:
                eprint("FATAL: %s" % exc)
                return 2
        try:
            write_output(items, args.out, stats)
        except (CsvError, IOError) as exc:
            eprint("FATAL: write output failed: %s" % exc)
            return 2
        if args.apply:
            exit_code = apply_entries(entries, args, stats)

    print_summary(stats, args, args.csv)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
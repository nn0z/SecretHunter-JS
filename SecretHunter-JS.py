import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, unquote
import os
import re
import math
import json
import time
import base64
import hashlib
import ipaddress
import socket
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore, Lock
from collections import Counter, deque
import urllib3
import html as html_lib
import datetime
import webbrowser
from pathlib import Path
from functools import lru_cache
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from wordlists import (
    KEYWORDS, ADVANCED_PATTERNS, GRAPHQL_PATTERNS, SEVERITY,
    IGNORE_VALUES, COMMON_ENGLISH_WORDS, COMMON_PATHS,
    CLOUD_PATTERNS, TARGET_EXTENSIONS, EXT_REGEX_STR,
    COMMON_SUBDOMAINS, VULNERABLE_LIBS, HIGH_RISK_KEYWORDS,
)

try:
    import jsbeautifier
    HAS_JSBEAUTIFIER = True
except ImportError:
    HAS_JSBEAUTIFIER = False

try:
    import lxml  # noqa
    HTML_PARSER = 'lxml'
except ImportError:
    HTML_PARSER = 'html.parser'

try:
    import diskcache
    HAS_DISKCACHE = True
except ImportError:
    HAS_DISKCACHE = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERIFY_SSL = os.getenv("SECRETHUNTER_VERIFY_SSL", "false").lower() == "true"
VALIDATE_SECRETS = os.getenv("SECRETHUNTER_VALIDATE_SECRETS", "false").lower() == "true"

RATE_LIMIT = Semaphore(20)
_seen_hashes = set()
_seen_lock = Lock()
_graphql_checked_domains = set()
_graphql_lock = Lock()

PATH_PATTERN = r"[\"']\/(?:[a-zA-Z0-9\-_./]+)[\"']"
KEYWORD_PATTERN = re.compile('|'.join(KEYWORDS), re.IGNORECASE) if KEYWORDS else None
PATH_RE = re.compile(PATH_PATTERN)

RESULTS_DIR = Path("results")
CACHE_DIR = Path(".secrethunter_cache")
MAX_DECODE_CHUNKS = 50
MAX_DECODE_TOTAL = 500_000
MAX_HEAVY_SCAN_SIZE = 2 * 1024 * 1024
MAX_BEAUTIFY_SIZE = 2 * 1024 * 1024

BLOCKED_HOSTS = {'localhost', 'metadata.google.internal', 'metadata', 'instance-data'}
BLOCKED_NETS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
]

KNOWN_FP = {
    'true', 'false', 'null', 'undefined', 'function', 'return',
    'string', 'number', 'object', 'boolean', 'array', 'symbol',
    'application/json', 'text/html', 'text/plain', 'utf-8',
    'getelementbyid', 'addeventlistener', 'queryselector',
    'console.log', 'console.error', 'console.warn',
}

LIVE = {
    "site_key": None,
    "target_url": None,
    "scan_number": 1,
    "started_at": None,
    "finished_at": None,
    "status": "idle",
    "files": [],
    "findings": [],
    "endpoints": [],
}


class TokenBucket:
    def __init__(self, rate=5.0, capacity=10):
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last = time.monotonic()
        self.lock = Lock()

    def consume(self, n=1):
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= n:
                    self.tokens -= n
                    return
                wait = (n - self.tokens) / self.rate
            time.sleep(wait)


BUCKET = TokenBucket(rate=5.0, capacity=10)


def make_session():
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    return s


SESSION = make_session()

if HAS_DISKCACHE:
    CACHE = diskcache.Cache(str(CACHE_DIR), size_limit=500 * 1024 * 1024)
else:
    CACHE = None


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = r"""
    ███████╗███████╗ ██████╗██████╗ ███████╗████████╗      ██╗███████╗
    ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝      ██║██╔════╝
    ███████╗█████╗  ██║     ██████╔╝█████╗     ██║         ██║███████╗
    ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║    ██   ██║╚════██║
    ███████║███████╗╚██████╗██║  ██║███████╗   ██║    ╚█████╔╝███████╗
    ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝     ╚════╝ ╚══════╝
       [ SecretHunter-JS - Advanced Recon for Sensitive Files ]
    """
    print("\033[1;36m" + banner + "\033[0m")
    print("\033[1;30m" + "=" * 95 + "\033[0m")


def extract_site_key(url):
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    host = host.split(":")[0]
    parts = host.split(".")
    while len(parts) > 2 and parts[0] in COMMON_SUBDOMAINS:
        parts = parts[1:]
    site_key = parts[0] if parts else "unknown"
    site_key = re.sub(r'[^a-zA-Z0-9_\-]', '_', site_key)
    site_key = site_key.strip('._-')[:64] or "unknown"
    reserved = {'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'LPT1', 'LPT2'}
    if site_key.upper() in reserved:
        site_key = f"_{site_key}"
    return site_key


@lru_cache(maxsize=50000)
def esc(s):
    return html_lib.escape(str(s))


def make_clickable(value, base_url=None):
    v = str(value).strip()
    if v.startswith(("http://", "https://")):
        return f'<a href="{esc(v)}" target="_blank" rel="noopener">{esc(v)}</a>'
    if v.startswith("/") and base_url:
        full = base_url.rstrip("/") + v
        return f'<a href="{esc(full)}" target="_blank" rel="noopener">{esc(v)}</a>'
    if v.startswith("/"):
        return f'<a href="{esc(v)}" target="_blank" rel="noopener">{esc(v)}</a>'
    return esc(v)


def is_false_positive(value):
    if not value:
        return True
    v = str(value).strip()
    vl = v.lower()
    if len(v) < 6:
        return True
    if vl in IGNORE_VALUES or vl in KNOWN_FP:
        return True
    if re.match(r'^[\$\{\}<%]', v):
        return True
    if re.fullmatch(r'[xX\*\.\-_\s]+', v):
        return True
    if re.fullmatch(r'(.)\1{5,}', v):
        return True
    if re.match(r'^\d{4}-\d{2}-\d{2}', v):
        return True
    if vl.endswith(('.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                    '.woff', '.woff2', '.ttf', '.ico', '.webp', '.mp4', '.webm')):
        return True
    if re.match(r'^(?:your|my|the|some|any|example|test|demo|sample|placeholder|dummy|fake|mock)[_\-]', vl):
        return True
    if re.match(r'^[a-zA-Z_]+$', v) and vl in COMMON_ENGLISH_WORDS:
        return True
    return False


def get_severity(finding_type):
    return SEVERITY.get(finding_type, 'low')


def load_exclusions():
    exclusions = []
    excl_file = Path("exclude.txt")
    if excl_file.exists():
        try:
            for line in excl_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    exclusions.append(line)
        except Exception:
            pass
    return exclusions


EXCLUSIONS = load_exclusions()


def is_excluded(url):
    if not EXCLUSIONS:
        return False
    for ex in EXCLUSIONS:
        if ex in url:
            return True
    return False


def is_safe_url(url):
    try:
        p = urlparse(url)
        if p.scheme not in ('http', 'https'):
            return False
        host = p.hostname
        if not host or host.lower() in BLOCKED_HOSTS:
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            try:
                ip = ipaddress.ip_address(socket.gethostbyname(host))
            except Exception:
                return True
        return not any(ip in net for net in BLOCKED_NETS)
    except Exception:
        return False


def content_hash(text):
    return hashlib.md5(text.encode('utf-8', 'ignore')).hexdigest()


def decode_obfuscated(content):
    decoded_chunks = []
    total = 0

    for m in re.finditer(r'atob\(["\']([A-Za-z0-9+/=]{16,})["\']\)', content):
        if len(decoded_chunks) >= MAX_DECODE_CHUNKS or total >= MAX_DECODE_TOTAL:
            break
        try:
            d = base64.b64decode(m.group(1)).decode('utf-8', 'ignore')
            decoded_chunks.append(d)
            total += len(d)
        except Exception:
            pass

    for m in re.finditer(r'(?:\\x[0-9a-fA-F]{2}){4,}', content):
        if len(decoded_chunks) >= MAX_DECODE_CHUNKS or total >= MAX_DECODE_TOTAL:
            break
        try:
            d = bytes.fromhex(m.group().replace('\\x', '')).decode('utf-8', 'ignore')
            decoded_chunks.append(d)
            total += len(d)
        except Exception:
            pass

    for m in re.finditer(r'(?:\\u[0-9a-fA-F]{4}){4,}', content):
        if len(decoded_chunks) >= MAX_DECODE_CHUNKS or total >= MAX_DECODE_TOTAL:
            break
        try:
            d = m.group().encode().decode('unicode_escape')
            decoded_chunks.append(d)
            total += len(d)
        except Exception:
            pass

    for m in re.finditer(r'(?:%[0-9a-fA-F]{2}){4,}', content):
        if len(decoded_chunks) >= MAX_DECODE_CHUNKS or total >= MAX_DECODE_TOTAL:
            break
        try:
            d = unquote(m.group())
            decoded_chunks.append(d)
            total += len(d)
        except Exception:
            pass

    return "\n".join(decoded_chunks)


def fetch_with_backoff(url, retries=3, timeout=10, stream=False, max_size=5 * 1024 * 1024):
    if is_excluded(url):
        return None
    if not is_safe_url(url):
        return None

    cache_key = None
    if CACHE is not None and not stream:
        cache_key = hashlib.sha256(url.encode()).hexdigest()
        cached = CACHE.get(cache_key)
        if cached:
            try:
                text, status, headers = cached
                r = requests.models.Response()
                r.status_code = status
                r._content = text.encode('utf-8', 'ignore')
                r.headers.update(headers)
                r.url = url
                return r
            except Exception:
                pass

    for i in range(retries):
        BUCKET.consume()
        try:
            with RATE_LIMIT:
                r = SESSION.get(
                    url,
                    headers={'User-Agent': random.choice(USER_AGENTS)},
                    timeout=timeout,
                    verify=VERIFY_SSL,
                    stream=stream,
                )
            if stream and r.headers.get('Content-Length'):
                try:
                    if int(r.headers['Content-Length']) > max_size:
                        r.close()
                        return None
                except Exception:
                    pass
            if r.status_code == 429:
                retry_after = r.headers.get('Retry-After')
                wait = int(retry_after) if (retry_after and retry_after.isdigit()) else (2 ** i)
                time.sleep(wait)
                continue
            if cache_key and r.status_code == 200 and not stream:
                try:
                    CACHE.set(cache_key, (r.text, r.status_code, dict(r.headers)), expire=3600)
                except Exception:
                    pass
            return r
        except Exception:
            if i == retries - 1:
                return None
            time.sleep(1)
    return None


def init_live(site_key, target_url):
    LIVE["site_key"] = site_key
    LIVE["target_url"] = target_url
    LIVE["started_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    LIVE["finished_at"] = None
    LIVE["status"] = "running"
    LIVE["files"] = []
    LIVE["findings"] = []
    LIVE["endpoints"] = []
    site_dir = RESULTS_DIR / site_key
    site_dir.mkdir(parents=True, exist_ok=True)
    max_num = 0
    for rf in site_dir.glob("run_*.json"):
        try:
            n = int(rf.stem.split("_")[1])
            if n > max_num:
                max_num = n
        except Exception:
            pass
    LIVE["scan_number"] = max_num + 1


def add_finding(finding_type, value, file_url="", context=""):
    if LIVE["status"] != "running":
        return
    raw_types = (
        'endpoint_status', 'path', 'js_endpoint', 'exposed_path',
        'graphql_endpoint', 'graphql_query', 'cors_critical',
        'cors_reflected', 'firebase_db', 'supabase_url',
        'auth0_domain', 'okta_domain', 'firebase_project',
        'jwt_hmac', 'high_risk_endpoint', 'vulnerable_lib',
        'postmessage_origin', 'localstorage_secret',
        'sessionstorage_secret', 'document_cookie',
    )
    if finding_type not in raw_types:
        if is_false_positive(value) and is_false_positive(context):
            return
    severity = get_severity(finding_type)
    LIVE["findings"].append({
        "type": finding_type,
        "value": str(value),
        "file": file_url,
        "context": context,
        "severity": severity,
    })


def add_file(file_url):
    if LIVE["status"] != "running":
        return
    if file_url not in LIVE["files"]:
        LIVE["files"].append(file_url)


def add_endpoint(endpoint):
    if LIVE["status"] != "running":
        return
    if endpoint not in LIVE["endpoints"]:
        LIVE["endpoints"].append(endpoint)


HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Consolas', 'Courier New', monospace; background:#0d1117;
         color:#c9d1d9; padding:20px; margin:0; }}
  h1 {{ color:#58a6ff; border-bottom:2px solid #30363d; padding-bottom:10px; }}
  h2 {{ color:#79c0ff; margin-top:30px; }}
  h3 {{ color:#f0883e; margin-top:20px; }}
  a {{ color:#58a6ff; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .badge {{ padding:3px 10px; border-radius:6px; font-size:0.85em; }}
  .running {{ background:#d29922; color:#000; }}
  .completed {{ background:#238636; color:#fff; }}
  .sev-critical {{ background:#f85149; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.75em; font-weight:bold; }}
  .sev-high {{ background:#db6d28; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.75em; font-weight:bold; }}
  .sev-medium {{ background:#d29922; color:#000; padding:2px 8px; border-radius:4px; font-size:0.75em; font-weight:bold; }}
  .sev-low {{ background:#1f6feb; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.75em; font-weight:bold; }}
  .sev-info {{ background:#6e7681; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.75em; font-weight:bold; }}
  .section {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
             padding:15px; margin:15px 0; }}
  .finding {{ border-bottom:1px solid #21262d; padding:10px 0; }}
  .finding:last-child {{ border-bottom:none; }}
  .finding .type {{ color:#f0883e; font-weight:bold; margin-right:6px; }}
  .finding .file {{ color:#8b949e; font-size:0.85em; margin-top:4px; word-break:break-all; }}
  .finding .value {{ color:#7ee787; word-break:break-all; }}
  .finding .context {{ color:#6e7681; font-size:0.85em; margin-top:4px; word-break:break-all; }}
  .meta {{ color:#8b949e; font-size:0.9em; }}
  .count {{ color:#f0883e; font-weight:bold; }}
  .empty {{ color:#6e7681; font-style:italic; }}
  .top-nav {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
             padding:10px 15px; margin-bottom:20px; display:flex;
             justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; }}
  .run-block {{ background:#0f141a; border:2px solid #30363d; border-radius:10px;
                padding:20px; margin:25px 0; }}
  .run-header {{ display:flex; justify-content:space-between; align-items:center;
                 flex-wrap:wrap; gap:10px; border-bottom:1px solid #30363d;
                 padding-bottom:10px; margin-bottom:15px; }}
  .toc {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
         padding:15px; margin:15px 0; }}
  .toc a {{ display:inline-block; background:#21262d; padding:6px 12px;
           border-radius:6px; margin:4px; border:1px solid #30363d; }}
  .toc a:hover {{ background:#1f6feb; }}
  .stats {{ display:flex; gap:15px; flex-wrap:wrap; margin:10px 0; }}
  .stat-box {{ background:#21262d; border:1px solid #30363d; border-radius:6px; padding:8px 14px; }}
  .stat-box .num {{ font-weight:bold; font-size:1.2em; }}
  .stat-critical .num {{ color:#f85149; }}
  .stat-high .num {{ color:#db6d28; }}
  .stat-medium .num {{ color:#d29922; }}
  .stat-low .num {{ color:#1f6feb; }}
</style>
</head>
<body>
"""

HTML_FOOT = """
</body>
</html>
"""


def render_run_section(scan, site_key, include_anchor=True):
    num = scan["scan_number"]
    anchor = f'<a id="run-{num}"></a>' if include_anchor else ""
    status = scan["status"]
    badge = ('<span class="badge running">Running</span>'
             if status == "running"
             else '<span class="badge completed">Completed</span>')
    base_url = scan.get("target_url", "")

    parts = [f'<div class="run-block" id="run-{num}-block">']
    if include_anchor:
        parts.append(anchor)
    parts.append('<div class="run-header">')
    parts.append(f'<h2 style="margin:0;">{esc(site_key)} — Run {num} {badge}</h2>')
    parts.append('</div>')

    parts.append(f'<p class="meta"><b>Target:</b> {esc(scan["target_url"])}</p>')
    parts.append(f'<p class="meta"><b>Started:</b> {esc(scan["started_at"])}</p>')
    if scan.get("finished_at"):
        parts.append(f'<p class="meta"><b>Finished:</b> {esc(scan["finished_at"])}</p>')

    findings = scan.get("findings", [])
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in sev_counts:
            sev_counts[sev] += 1

    parts.append('<div class="stats">')
    parts.append(f'<div class="stat-box stat-critical"><div class="num">{sev_counts["critical"]}</div><div>Critical</div></div>')
    parts.append(f'<div class="stat-box stat-high"><div class="num">{sev_counts["high"]}</div><div>High</div></div>')
    parts.append(f'<div class="stat-box stat-medium"><div class="num">{sev_counts["medium"]}</div><div>Medium</div></div>')
    parts.append(f'<div class="stat-box stat-low"><div class="num">{sev_counts["low"]}</div><div>Low</div></div>')
    parts.append('</div>')

    parts.append('<div class="section">')
    parts.append(f'<h3>📁 Files discovered (<span class="count">{len(scan["files"])}</span>)</h3>')
    if scan["files"]:
        for f in scan["files"]:
            parts.append(f'<div class="finding"><span class="value">{make_clickable(f, base_url)}</span></div>')
    else:
        parts.append('<div class="empty">No files found yet...</div>')
    parts.append('</div>')

    parts.append('<div class="section">')
    parts.append(f'<h3>⚠️ Findings (<span class="count">{len(findings)}</span>)</h3>')
    if findings:
        sev_order = ["critical", "high", "medium", "low", "info"]
        sorted_findings = sorted(findings, key=lambda x: sev_order.index(x.get("severity", "low")))
        for f in sorted_findings:
            sev = f.get("severity", "low")
            parts.append('<div class="finding">')
            parts.append(f'<span class="sev-{sev}">{sev.upper()}</span> ')
            parts.append(f'<span class="type">[{esc(f["type"])}]</span>')
            parts.append(f'<span class="value">{make_clickable(f["value"], base_url)}</span>')
            if f.get("file"):
                parts.append(f'<div class="file">📄 {make_clickable(f["file"], base_url)}</div>')
            if f.get("context"):
                parts.append(f'<div class="context">{esc(f["context"])}</div>')
            parts.append('</div>')
    else:
        parts.append('<div class="empty">No findings yet...</div>')
    parts.append('</div>')

    parts.append('<div class="section">')
    parts.append(f'<h3>🔗 Endpoints (<span class="count">{len(scan["endpoints"])}</span>)</h3>')
    if scan["endpoints"]:
        for e in scan["endpoints"]:
            parts.append(f'<div class="finding"><span class="value">{make_clickable(e, base_url)}</span></div>')
    else:
        parts.append('<div class="empty">No endpoints yet...</div>')
    parts.append('</div>')

    parts.append('</div>')
    return "\n".join(parts)


def save_run_json(site_key, scan_data):
    site_dir = RESULTS_DIR / site_key
    site_dir.mkdir(parents=True, exist_ok=True)
    run_file = site_dir / f"run_{scan_data['scan_number']}.json"
    with open(run_file, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2, ensure_ascii=False)


def load_all_runs(site_key):
    site_dir = RESULTS_DIR / site_key
    if not site_dir.exists():
        return []
    runs = []
    for rf in sorted(site_dir.glob("run_*.json")):
        try:
            with open(rf, encoding="utf-8") as f:
                runs.append(json.load(f))
        except Exception:
            pass
    return runs


def build_site_html_from_json(site_key, runs):
    parts = [HTML_HEAD.format(title=f"Secret-JS - {esc(site_key)}")]
    parts.append('<a id="top"></a>')
    parts.append('<div class="top-nav">')
    parts.append(f'<h1 style="margin:0;">📑 Secret-JS - {esc(site_key)}</h1>')
    parts.append('</div>')

    if runs:
        parts.append('<div class="toc">')
        parts.append(f'<b>Runs of {esc(site_key)}:</b><br>')
        for run in runs:
            n = run["scan_number"]
            parts.append(f'<a href="#run-{n}">{esc(site_key)} — Run {n}</a>')
        parts.append('</div>')

    for run in runs:
        parts.append(render_run_section(run, site_key, include_anchor=True))

    parts.append(HTML_FOOT)
    return "\n".join(parts)


def save_site_files():
    if LIVE["site_key"] is None:
        return
    site_key = LIVE["site_key"]
    site_dir = RESULTS_DIR / site_key
    site_dir.mkdir(parents=True, exist_ok=True)

    current_scan = {
        "scan_number": LIVE["scan_number"],
        "target_url": LIVE["target_url"],
        "started_at": LIVE["started_at"],
        "finished_at": LIVE["finished_at"],
        "status": LIVE["status"],
        "files": list(LIVE["files"]),
        "findings": list(LIVE["findings"]),
        "endpoints": list(LIVE["endpoints"]),
    }

    save_run_json(site_key, current_scan)
    runs = load_all_runs(site_key)

    html_content = build_site_html_from_json(site_key, runs)
    site_file = site_dir / f"{site_key}.html"
    with open(site_file, "w", encoding="utf-8") as f:
        f.write(html_content)


def export_json():
    if LIVE["site_key"] is None:
        print("[-] No active scan.")
        return
    site_key = LIVE["site_key"]
    site_dir = RESULTS_DIR / site_key
    site_dir.mkdir(parents=True, exist_ok=True)
    json_file = site_dir / f"{site_key}_run{LIVE['scan_number']}.json"
    data = {
        "site_key": site_key,
        "scan_number": LIVE["scan_number"],
        "target_url": LIVE["target_url"],
        "started_at": LIVE["started_at"],
        "finished_at": LIVE["finished_at"],
        "status": LIVE["status"],
        "files": LIVE["files"],
        "findings": LIVE["findings"],
        "endpoints": LIVE["endpoints"],
    }
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON exported: {json_file}")


def export_txt():
    if LIVE["site_key"] is None:
        print("[-] No active scan.")
        return
    site_key = LIVE["site_key"]
    site_dir = RESULTS_DIR / site_key
    site_dir.mkdir(parents=True, exist_ok=True)
    txt_file = site_dir / f"{site_key}_run{LIVE['scan_number']}.txt"
    sev_order = ["critical", "high", "medium", "low", "info"]
    with open(txt_file, "w", encoding="utf-8") as f:
        f.write("SecretHunter-JS Report\n")
        f.write(f"Site Key: {site_key}\n")
        f.write(f"Run: {LIVE['scan_number']}\n")
        f.write(f"Target: {LIVE['target_url']}\n")
        f.write(f"Started: {LIVE['started_at']}\n")
        f.write(f"Finished: {LIVE['finished_at']}\n")
        f.write(f"Status: {LIVE['status']}\n\n")
        f.write(f"=== FILES ({len(LIVE['files'])}) ===\n")
        for fl in LIVE["files"]:
            f.write(f"{fl}\n")
        f.write(f"\n=== FINDINGS ({len(LIVE['findings'])}) ===\n")
        for fd in sorted(LIVE["findings"], key=lambda x: sev_order.index(x.get("severity", "low"))):
            f.write(f"[{fd['severity'].upper()}] [{fd['type']}] {fd['value']}\n")
            if fd.get("file"):
                f.write(f"    File: {fd['file']}\n")
            if fd.get("context"):
                f.write(f"    Context: {fd['context']}\n")
        f.write(f"\n=== ENDPOINTS ({len(LIVE['endpoints'])}) ===\n")
        for ep in LIVE["endpoints"]:
            f.write(f"{ep}\n")
    print(f"[+] TXT exported: {txt_file}")


def finalize_live():
    if LIVE["status"] != "running":
        return
    LIVE["status"] = "completed"
    LIVE["finished_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_site_files()
    export_json()


def calculate_entropy(data):
    if not data:
        return 0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@lru_cache(maxsize=10000)
def calculate_entropy_cached(data):
    return calculate_entropy(data)


def scan_binary_content(content, file_url):
    if file_url.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico')):
        try:
            text_matches = re.findall(rb'[\x20-\x7E]{4,}', content)
            for match in text_matches:
                try:
                    text = match.decode('utf-8', errors='ignore')
                    if any(kw.replace(r'\\', '').lower() in text.lower() for kw in KEYWORDS):
                        print(f"  [FOUND IN IMAGE] {text[:100]}...")
                        add_finding("image_text", text[:200], file_url)
                except Exception:
                    pass
        except Exception:
            pass


def beautify_js(content):
    if len(content) > MAX_BEAUTIFY_SIZE:
        return content
    if HAS_JSBEAUTIFIER:
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            return jsbeautifier.beautify(content, opts)
        except Exception:
            pass
    if len(content) > 5000 and content[:100000].count('\n') < 50:
        content = re.sub(r'([;{}])', r'\1\n', content)
    return content


def find_source_maps(content, file_url):
    matches = re.findall(r'//[#@]\s*sourceMappingURL=(\S+)', content)
    for sm in matches:
        sm_url = urljoin(file_url, sm)
        if not is_safe_url(sm_url):
            continue
        print(f"  [SOURCE MAP] {sm_url}")
        add_finding("source_map", sm_url, file_url, "Source map may expose original code")
        try:
            r = fetch_with_backoff(sm_url, retries=2, timeout=10)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    sources = data.get("sources", [])
                    contents = data.get("sourcesContent", [])
                    print(f"    [+] {len(sources)} original sources exposed")
                    for i, src in enumerate(sources[:10]):
                        if i < len(contents) and contents[i]:
                            scan_content(contents[i], f"{sm_url}#{src}")
                        add_finding("source_map_source", src, sm_url)
                except Exception:
                    pass
            elif r and r.status_code == 404:
                for sg in ['/src/', '/app/', '/js/', '/source/', '/sources/']:
                    test_url = urljoin(file_url, sg)
                    if not is_safe_url(test_url):
                        continue
                    rr = fetch_with_backoff(test_url, retries=1, timeout=5)
                    if rr and rr.status_code == 200:
                        print(f"    [+] Source dir guess accessible: {test_url}")
                        add_endpoint(test_url)
        except Exception:
            pass


def try_source_map_variants(js_url):
    candidates = []
    if js_url.endswith(".js"):
        candidates.append(js_url[:-3] + ".js.map")
        candidates.append(js_url + ".map")
    else:
        candidates.append(js_url + ".map")
    candidates = list(dict.fromkeys(candidates))
    for sm_url in candidates:
        if is_excluded(sm_url) or not is_safe_url(sm_url):
            continue
        r = fetch_with_backoff(sm_url, retries=1, timeout=8)
        if r and r.status_code == 200 and r.text.strip().startswith("{"):
            try:
                data = r.json()
                sources = data.get("sources", [])
                contents = data.get("sourcesContent", [])
                print(f"  [SOURCE MAP VARIANT] {sm_url} ({len(sources)} sources)")
                add_finding("source_map", sm_url, js_url, "Source map exposed via variant")
                for i, src in enumerate(sources[:10]):
                    if i < len(contents) and contents[i]:
                        scan_content(contents[i], f"{sm_url}#{src}")
                    add_finding("source_map_source", src, sm_url)
                return True
            except Exception:
                pass
    return False


def analyze_jwt_token(token, source_url=""):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return
        header_b64 = parts[0] + '=' * (-len(parts[0]) % 4)
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        header_data = json.loads(base64.urlsafe_b64decode(header_b64).decode('utf-8', errors='ignore'))
        payload_data = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8', errors='ignore'))

        alg = str(header_data.get('alg', '')).lower()
        if alg == 'none':
            print(f"  [JWT ALG=NONE] {token[:40]}...")
            add_finding("jwt_alg_none", token[:80], source_url, "JWT with alg=none - CRITICAL")
        elif alg.startswith('hs'):
            add_finding("jwt_hmac", token[:80], source_url,
                        f"JWT uses {header_data.get('alg')} (HMAC)")

        sensitive_keys = ['password', 'ssn', 'credit_card', 'api_key', 'secret',
                          'private', 'token', 'pwd', 'pin']
        for key in payload_data:
            if any(s in str(key).lower() for s in sensitive_keys):
                add_finding("jwt_sensitive_data",
                            f"{key}={str(payload_data[key])[:60]}",
                            source_url,
                            f"Sensitive claim in JWT: {key}")
    except Exception:
        pass


def check_firebase_exposure(content, source_url):
    for m in re.finditer(ADVANCED_PATTERNS['firebase_db'], content, re.IGNORECASE):
        db_url = m.group(0)
        if is_false_positive(db_url):
            continue
        print(f"  [FIREBASE DB] {db_url}")
        add_finding("firebase_db", db_url, source_url,
                    "Firebase database URL detected — verify rules manually")

    for m in re.finditer(ADVANCED_PATTERNS['firebase_storage'], content, re.IGNORECASE):
        add_finding("firebase_storage", m.group(0), source_url,
                    "Firebase Storage bucket reference")

    for m in re.finditer(ADVANCED_PATTERNS['firebase_project'], content, re.IGNORECASE):
        add_finding("firebase_project", m.group(1), source_url,
                    "Firebase project ID exposed")

    supabase_urls = set()
    for m in re.finditer(ADVANCED_PATTERNS['supabase_url'], content, re.IGNORECASE):
        su = m.group(0)
        if su in supabase_urls:
            continue
        supabase_urls.add(su)
        add_finding("supabase_url", su, source_url, "Supabase project URL detected")


def check_cors(target_url):
    try:
        r = SESSION.get(target_url,
                        headers={'Origin': 'https://evil-attacker.com',
                                 'User-Agent': random.choice(USER_AGENTS)},
                        timeout=8, verify=VERIFY_SSL)
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        acac = r.headers.get('Access-Control-Allow-Credentials', '')
        if acao == '*' and acac.lower() == 'true':
            add_finding("cors_critical", target_url, "",
                        "Access-Control-Allow-Origin: * with credentials=true")
        elif 'evil-attacker.com' in acao:
            add_finding("cors_reflected", target_url, "",
                        f"Origin reflected: {acao}")
    except Exception:
        pass


def check_security_headers(target_url, response):
    if not response:
        return
    csp = response.headers.get('Content-Security-Policy', '')
    if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
        add_finding("cors_critical", target_url, "", "Weak CSP: unsafe-inline/eval present")
    if 'Strict-Transport-Security' not in response.headers and target_url.startswith('https'):
        add_finding("vulnerable_lib", "HSTS missing", target_url, "Missing HSTS header")
    xfo = response.headers.get('X-Frame-Options', '')
    if not xfo:
        add_finding("vulnerable_lib", "X-Frame-Options missing", target_url, "Clickjacking risk")


def check_graphql_introspection(base_url, content=""):
    domain = urlparse(base_url).netloc
    with _graphql_lock:
        if domain in _graphql_checked_domains:
            return
        _graphql_checked_domains.add(domain)

    candidates = set()
    for m in re.finditer(GRAPHQL_PATTERNS['graphql_endpoint'], content):
        candidates.add(urljoin(base_url, m.group(1)))
    for p in ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"]:
        candidates.add(urljoin(base_url, p))

    for gql_url in candidates:
        if is_excluded(gql_url) or not is_safe_url(gql_url):
            continue
        try:
            r = SESSION.post(gql_url,
                             json={"query": "{__schema{types{name}}}"},
                             timeout=6, verify=VERIFY_SSL,
                             headers={'Content-Type': 'application/json',
                                      'User-Agent': random.choice(USER_AGENTS)})
            if r.status_code == 200 and '__schema' in r.text:
                add_finding("graphql_introspection_enabled", gql_url, "",
                            "GraphQL introspection is enabled - full schema exposed")
                add_endpoint(gql_url)
            elif r.status_code in (200, 400, 401, 403):
                add_finding("graphql_endpoint", gql_url, "",
                            f"GraphQL endpoint detected (status {r.status_code})")
                add_endpoint(gql_url)
        except Exception:
            pass


def detect_vulnerable_libs(content, file_url):
    for lib, (pattern, vulns) in VULNERABLE_LIBS.items():
        for m in re.finditer(pattern, content, re.IGNORECASE):
            version = m.group(1)
            try:
                ver_parts = tuple(int(x) for x in version.split('.')[:3])
            except Exception:
                continue
            for vuln_ver, cve in vulns.items():
                try:
                    vuln_parts = tuple(int(x) for x in vuln_ver.split('.')[:3])
                except Exception:
                    continue
                if ver_parts < vuln_parts:
                    add_finding("vulnerable_lib", f"{lib} {version}",
                                file_url, f"Vulnerable version - {cve}")
                    break


def classify_endpoint_risk(ep):
    ep_lower = ep.lower()
    for hr in HIGH_RISK_KEYWORDS:
        if hr in ep_lower:
            return True
    return False


def validate_secret(finding_type, value):
    if not VALIDATE_SECRETS:
        return None
    try:
        if finding_type == 'github_token':
            r = SESSION.get('https://api.github.com/user',
                            headers={'Authorization': f'token {value}'},
                            timeout=5, verify=VERIFY_SSL)
            return r.status_code == 200
        if finding_type == 'slack_token':
            r = SESSION.post('https://slack.com/api/auth.test',
                             headers={'Authorization': f'Bearer {value}'},
                             timeout=5, verify=VERIFY_SSL)
            return r.status_code == 200 and r.json().get('ok', False)
        if finding_type == 'openai_key':
            r = SESSION.get('https://api.openai.com/v1/models',
                            headers={'Authorization': f'Bearer {value}'},
                            timeout=5, verify=VERIFY_SSL)
            return r.status_code == 200
        if finding_type == 'stripe_live':
            r = SESSION.get('https://api.stripe.com/v1/charges',
                            headers={'Authorization': f'Bearer {value}'},
                            timeout=5, verify=VERIFY_SSL)
            return r.status_code in (200, 403) and 'api_key' not in r.text.lower()
        if finding_type == 'google_api':
            r = SESSION.get(f'https://maps.googleapis.com/maps/api/geocode/json?address=test&key={value}',
                            timeout=5, verify=VERIFY_SSL)
            return r.status_code == 200 and 'error_message' not in r.text.lower()
        if finding_type == 'npm_token':
            r = SESSION.get('https://registry.npmjs.org/-/whoami',
                            headers={'Authorization': f'Bearer {value}'},
                            timeout=5, verify=VERIFY_SSL)
            return r.status_code == 200
        if finding_type == 'digitalocean_token':
            r = SESSION.get('https://api.digitalocean.com/v2/account',
                            headers={'Authorization': f'Bearer {value}'},
                            timeout=5, verify=VERIFY_SSL)
            return r.status_code == 200
        if finding_type == 'huggingface_token':
            r = SESSION.get('https://huggingface.co/api/whoami-v2',
                            headers={'Authorization': f'Bearer {value}'},
                            timeout=5, verify=VERIFY_SSL)
            return r.status_code == 200
        if finding_type == 'mapbox_token':
            r = SESSION.get(f'https://api.mapbox.com/tokens/v2?access_token={value}',
                            timeout=5, verify=VERIFY_SSL)
            return r.status_code == 200
        if finding_type == 'replicate_token':
            r = SESSION.get('https://api.replicate.com/v1/account',
                            headers={'Authorization': f'Token {value}'},
                            timeout=5, verify=VERIFY_SSL)
            return r.status_code == 200
    except Exception:
        return False
    return None


def extract_bundler_chunks(content, file_url):
    chunks = set()
    chunks.update(re.findall(r'\.p\s*\+\s*["\']([^"\']+\.js)["\']', content))
    chunks.update(re.findall(r'__webpack_require__\.p\s*\+\s*["\']([^"\']+\.js)["\']', content))
    chunks.update(re.findall(r'["\']/assets/([a-zA-Z0-9_\-]+\.js)["\']', content))
    chunks.update(re.findall(r'["\']\./([a-zA-Z0-9_\-/]+\.js)["\']', content))
    for c in chunks:
        full = urljoin(file_url, c)
        add_endpoint(full)
    return chunks


def analyze_javascript(file_url, content=None):
    try:
        if content is None:
            res = fetch_with_backoff(file_url, retries=2, timeout=10)
            if not res or res.status_code != 200:
                return None
            content = res.text

        find_source_maps(content, file_url)
        pretty = beautify_js(content)

        endpoints = re.findall(r'["\'](/api/[a-zA-Z0-9/_-]+)["\']', pretty)
        endpoints += re.findall(r'["\'](/v[0-9]+/[a-zA-Z0-9/_-]+)["\']', pretty)
        unique_endpoints = list(set(endpoints))

        functions = re.findall(r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(', pretty)
        functions += re.findall(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function\s*\(', pretty)
        functions += re.findall(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*function\s*\(', pretty)

        variables = re.findall(r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=', pretty)
        long_strings = re.findall(r'["\']([a-zA-Z0-9+/=]{40,})["\']', pretty)

        print(f"\n[!] Analyzing JavaScript: {file_url}")
        print(f"  [+] Endpoints found: {len(unique_endpoints)}")
        print(f"  [+] Functions found: {len(functions)}")
        print(f"  [+] Variables found: {len(variables)}")
        print(f"  [+] Long strings found: {len(long_strings)}")

        if unique_endpoints:
            print(f"  Sample endpoints: {unique_endpoints[:5]}")
            for ep in unique_endpoints:
                add_endpoint(ep)
                add_finding("js_endpoint", ep, file_url)
                if classify_endpoint_risk(ep):
                    add_finding("high_risk_endpoint", ep, file_url,
                                "High-risk endpoint detected in JS")
        if functions:
            print(f"  Sample functions: {functions[:5]}")
        if long_strings:
            for s in long_strings[:3]:
                if calculate_entropy_cached(s) > 4.5:
                    print(f"  [HIGH ENTROPY STRING] {s[:50]}...")
                    add_finding("high_entropy_js", s[:120], file_url,
                                f"Entropy: {calculate_entropy_cached(s):.2f}")

        chunks = extract_bundler_chunks(pretty, file_url)
        for c in chunks:
            full = urljoin(file_url, c)
            if is_excluded(full) or not is_safe_url(full):
                continue
            r = fetch_with_backoff(full, retries=1, timeout=8)
            if r and r.status_code == 200:
                scan_content(r.text, full)

        try_source_map_variants(file_url)
        detect_vulnerable_libs(pretty, file_url)
        check_firebase_exposure(pretty, file_url)

        for m in re.finditer(ADVANCED_PATTERNS['jwt_token'], pretty):
            analyze_jwt_token(m.group(), file_url)

        return {
            'endpoints': unique_endpoints,
            'functions': functions,
            'variables': variables,
            'long_strings': long_strings
        }
    except Exception as e:
        print(f"[-] Could not analyze JS: {e}")
    return None


def scan_content(content, file_url):
    h = content_hash(content)
    with _seen_lock:
        if h in _seen_hashes:
            return
        _seen_hashes.add(h)

    decoded = decode_obfuscated(content)
    if decoded:
        content = content + "\n" + decoded

    print(f"\n[!] Scanning: {file_url}")
    found = False

    if KEYWORD_PATTERN is not None:
        for match in KEYWORD_PATTERN.finditer(content):
            start = max(0, match.start() - 60)
            end = min(len(content), match.end() + 60)
            snippet = f"...{content[start:end]}..."
            if is_false_positive(snippet):
                continue
            found = True
            print(f"  [FOUND KEYWORD] '{match.group()}' at: {snippet}")
            add_finding("keyword", match.group(), file_url, snippet)

    for pattern_name, pattern in ADVANCED_PATTERNS.items():
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            val = match.group()
            if is_false_positive(val):
                continue
            found = True
            print(f"  [FOUND {pattern_name.upper()}] {val}")
            add_finding(pattern_name, val, file_url)

            if pattern_name in ('github_token', 'slack_token', 'openai_key', 'stripe_live',
                                'google_api', 'npm_token', 'digitalocean_token',
                                'huggingface_token', 'mapbox_token', 'replicate_token'):
                if validate_secret(pattern_name, val):
                    add_finding("validated_secret", val, file_url,
                                f"LIVE {pattern_name} - validated against API")

            if pattern_name == 'jwt_token':
                analyze_jwt_token(val, file_url)

    for pattern in CLOUD_PATTERNS:
        for match in re.finditer(pattern, content):
            val = match.group()
            if is_false_positive(val):
                continue
            found = True
            print(f"  [FOUND CLOUD STORAGE] {val}")
            add_finding("cloud_storage", val, file_url)

    for gql_name, gql_pat in GRAPHQL_PATTERNS.items():
        for match in re.finditer(gql_pat, content):
            if gql_name == 'graphql_endpoint':
                add_finding("graphql_endpoint", match.group(1), file_url)
                add_endpoint(match.group(1))
            elif gql_name == 'graphql_query':
                add_finding("graphql_query", match.group()[:80], file_url)
            elif gql_name == 'graphql_introspection':
                add_finding("graphql_introspection", match.group(), file_url,
                            "Introspection query in code")

    check_firebase_exposure(content, file_url)

    if len(content) < MAX_HEAVY_SCAN_SIZE:
        for m in re.finditer(r'[\"\']([a-zA-Z0-9\-_/+=]{16,})[\"\']', content):
            word = m.group(1)
            if is_false_positive(word):
                continue
            ent = calculate_entropy_cached(word)
            if ent > 4.5:
                found = True
                print(f"  [HIGH ENTROPY SECRET] '{word}' (Entropy: {ent:.2f})")
                add_finding("high_entropy", word, file_url, f"Entropy: {ent:.2f}")

    unique_paths = set()
    for match in PATH_RE.finditer(content):
        raw_path = match.group().strip('"\'')
        if "//" in raw_path or raw_path == "/":
            continue
        unique_paths.add(raw_path)

    for path in unique_paths:
        found = True
        print(f"  [FOUND PATH] {path}")
        add_finding("path", path, file_url)
        add_endpoint(path)
        if classify_endpoint_risk(path):
            add_finding("high_risk_endpoint", path, file_url,
                        "High-risk path detected")

    if not found:
        print("  [+] No sensitive info or paths found.")


def scan_inline_scripts(soup, page_url):
    inline_count = 0
    for script in soup.find_all("script", src=False):
        if script.string and len(script.string.strip()) > 20:
            inline_count += 1
            scan_content(script.string, f"{page_url}#inline-script-{inline_count}")
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            if attr.startswith("data-") and isinstance(val, str) and len(val) > 20:
                for pattern_name, pattern in ADVANCED_PATTERNS.items():
                    for match in re.finditer(pattern, val, re.IGNORECASE):
                        add_finding(pattern_name, match.group(), page_url,
                                    f"data-attr: {attr}")
    comments = soup.find_all(string=lambda text: isinstance(text, str) and "<!--" in text)
    for c in comments:
        for pattern_name, pattern in ADVANCED_PATTERNS.items():
            for match in re.finditer(pattern, c, re.IGNORECASE):
                add_finding(pattern_name, match.group(), page_url, "HTML comment")


def scan_html_file(content, file_url):
    print(f"\n[!] Scanning HTML: {file_url}")
    soup = BeautifulSoup(content, HTML_PARSER)
    scan_content(content, file_url)
    inline_count = 0
    for script in soup.find_all("script", src=False):
        if script.string and len(script.string.strip()) > 20:
            inline_count += 1
            scan_content(script.string, f"{file_url}#inline-script-{inline_count}")
    for style in soup.find_all("style"):
        if style.string and len(style.string.strip()) > 20:
            scan_content(style.string, f"{file_url}#inline-style")
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            if attr.startswith("data-") and isinstance(val, str) and len(val) > 20:
                for pattern_name, pattern in ADVANCED_PATTERNS.items():
                    for match in re.finditer(pattern, val, re.IGNORECASE):
                        add_finding(pattern_name, match.group(), file_url,
                                    f"data-attr: {attr}")
    comments = soup.find_all(string=lambda text: isinstance(text, str) and "<!--" in text)
    for c in comments:
        for pattern_name, pattern in ADVANCED_PATTERNS.items():
            for match in re.finditer(pattern, c, re.IGNORECASE):
                add_finding(pattern_name, match.group(), file_url, "HTML comment")


def run_initial_analysis(target_url, target_files):
    res = fetch_with_backoff(target_url, retries=2, timeout=10)
    if res and res.status_code == 200:
        soup = BeautifulSoup(res.text, HTML_PARSER)
        scan_inline_scripts(soup, target_url)
        check_cors(target_url)
        check_graphql_introspection(target_url, res.text)
        check_security_headers(target_url, res)
    save_site_files()


def check_common_paths(base_url):
    print(f"\n[+] Checking common sensitive paths on {base_url}...")

    def check_one_path(p):
        url = urljoin(base_url, p)
        if is_excluded(url) or not is_safe_url(url):
            return None
        try:
            BUCKET.consume()
            with RATE_LIMIT:
                r = SESSION.head(url,
                                 headers={'User-Agent': random.choice(USER_AGENTS)},
                                 timeout=3, allow_redirects=True, verify=VERIFY_SSL)
            if r.status_code in (400, 403, 405, 501):
                BUCKET.consume()
                with RATE_LIMIT:
                    r = SESSION.get(url,
                                    headers={'User-Agent': random.choice(USER_AGENTS)},
                                    timeout=3, allow_redirects=True,
                                    stream=True, verify=VERIFY_SSL)
                r.close()
            if r.status_code in (200, 301, 302, 401, 403):
                return (r.status_code, url, r.url)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_one_path, COMMON_PATHS)
        for result in results:
            if result:
                status_code, url, final_url = result
                print(f"  [EXPOSED] [{status_code}] {url}")
                add_finding("exposed_path", url, "", f"Status {status_code}")
                add_endpoint(url)
                if final_url != url:
                    add_endpoint(final_url)
                    add_file(final_url)


def extract_file_refs(text, base_url):
    refs = set()
    for m in re.finditer(rf"[\"']([a-zA-Z0-9\-_./]+\.{EXT_REGEX_STR})[\"']", text, re.IGNORECASE):
        refs.add(urljoin(base_url, m.group(1)))
    return refs


def crawl_bfs(seeds, max_depth=2, max_files=500, batch=20):
    seen = set(seeds)
    queue = deque((s, 0) for s in seeds)
    results = set(seeds)

    def fetch_text(u):
        try:
            r = fetch_with_backoff(u, retries=1, timeout=6)
            if r and r.status_code == 200:
                return r.text
        except Exception:
            pass
        return None

    while queue and len(results) < max_files:
        level = []
        while queue and len(level) < batch:
            url, depth = queue.popleft()
            if depth < max_depth:
                level.append((url, depth))
        if not level:
            break

        with ThreadPoolExecutor(max_workers=min(batch, 15)) as ex:
            futures = {ex.submit(fetch_text, u): (u, d) for u, d in level}
            for fut in as_completed(futures):
                url, depth = futures[fut]
                try:
                    text = fut.result()
                except Exception:
                    text = None
                if not text:
                    continue
                for sub in extract_file_refs(text, url):
                    if sub in seen or len(results) >= max_files:
                        continue
                    if '.css' in sub.lower() or is_excluded(sub):
                        continue
                    seen.add(sub)
                    results.add(sub)
                    queue.append((sub, depth + 1))
    return list(results)


def get_target_files(target_url):
    try:
        response = fetch_with_backoff(target_url, retries=2, timeout=10)
        if not response or response.status_code != 200:
            print("[-] Failed to connect.")
            return []
        soup = BeautifulSoup(response.text, HTML_PARSER)
        target_files = set()

        for tag in soup.find_all(['script', 'link', 'a', 'iframe']):
            for attr in ['src', 'href', 'data-src', 'data-url']:
                val = tag.get(attr)
                if val:
                    val_lower = val.lower()
                    if val_lower.endswith(TARGET_EXTENSIONS) or any(
                            ext in val_lower for ext in ['.js?', '.php?', '.json?', '.html?', '.htm?']):
                        if '.css' not in val_lower:
                            full_url = urljoin(target_url, val)
                            if not is_excluded(full_url):
                                target_files.add(full_url)

        for p in re.findall(rf"[\"']([a-zA-Z0-9\-_./]+\.{EXT_REGEX_STR})[\"']",
                            response.text, re.IGNORECASE):
            full = urljoin(target_url, p)
            if not is_excluded(full):
                target_files.add(full)

        crawled = crawl_bfs(list(target_files), max_depth=2, max_files=500)
        target_files.update(crawled)

        if target_url not in target_files:
            target_files.add(target_url)

        file_list = list(target_files)
        for f in file_list:
            add_file(f)

        check_common_paths(target_url)

        print(f"\n[+] Found {len(file_list)} target files:\n")
        for i, f in enumerate(file_list, 1):
            print(f"[{i}] {f}")
        return file_list
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        return []


def analyze_single_file(file_list):
    if not file_list:
        print("[-] No target files available.")
        return
    print()
    for i, f in enumerate(file_list, 1):
        print(f"[{i}] {f}")
    print()
    try:
        choice = int(input("Enter the number of the file: "))
        if 1 <= choice <= len(file_list):
            target_file = file_list[choice - 1]
            print(f"\n[+] Fetching: {target_file}")
            res = fetch_with_backoff(target_file, retries=2, timeout=10)
            if res and res.status_code == 200:
                lower = target_file.lower()
                ctype = res.headers.get('Content-Type', '').lower()
                if lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico')):
                    scan_binary_content(res.content, target_file)
                elif lower.endswith(('.html', '.htm')) or 'text/html' in ctype:
                    scan_html_file(res.text, target_file)
                else:
                    scan_content(res.text, target_file)
                if lower.endswith('.js'):
                    analyze_javascript(target_file, content=res.text)
                save_site_files()
            else:
                print("[-] Failed to fetch file.")
        else:
            print("[-] Invalid selection.")
    except Exception as e:
        print(f"[-] Error: {e}")


def advanced_search(file_list):
    if not file_list:
        print("[-] No target files available.")
        return
    custom_input = input("Enter custom keywords (comma separated): ").strip()
    if not custom_input:
        print("[-] No keywords entered.")
        return
    custom_keywords = [kw.strip() for kw in custom_input.split(',') if kw.strip()]
    print(f"\n[+] Searching for: {', '.join(custom_keywords)}")
    results = {}
    total_checked = 0

    def scan_one(file_url):
        res = fetch_with_backoff(file_url, retries=1, timeout=6)
        local = []
        if res and res.status_code == 200:
            for line_num, line in enumerate(res.text.splitlines(), 1):
                line_lower = line.lower()
                found_kw = [kw for kw in custom_keywords if kw.lower() in line_lower]
                if found_kw:
                    clean_line = line.strip()[:100]
                    if len(line.strip()) > 100:
                        clean_line += "..."
                    local.append({
                        'keywords': found_kw,
                        'line_number': line_num,
                        'content': clean_line,
                    })
                    print(f"  [FOUND] {file_url} -> Line {line_num}: {clean_line}")
                    print(f"    Keywords: {', '.join(found_kw)}")
                    add_finding("custom_search", ", ".join(found_kw), file_url,
                                f"Line {line_num}: {clean_line}")
        return file_url, local

    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = [ex.submit(scan_one, f) for f in file_list]
        for fut in as_completed(futures):
            total_checked += 1
            try:
                url, matches = fut.result()
                if matches:
                    results[url] = matches
            except Exception:
                pass

    print(f"\n[+] Scanned {total_checked} files, found matches in {len(results)} files.")
    if not results:
        print("[-] No matches found.")
    save_site_files()
    return results


def analyze_all_files_optimized(file_list):
    if not file_list:
        print("[-] No target files available.")
        return
    print(f"\n[+] Starting optimized deep scan for {len(file_list)} files...")
    results = {}

    def fetch_and_scan(f_url):
        res = fetch_with_backoff(f_url, retries=2, timeout=10)
        if not res or res.status_code != 200:
            return f_url, []
        findings = []
        print(f"\n[!] Scanning: {f_url}")
        decoded = decode_obfuscated(res.text)
        text = res.text + ("\n" + decoded if decoded else "")

        if KEYWORD_PATTERN is not None:
            for match in KEYWORD_PATTERN.finditer(text):
                start = max(0, match.start() - 60)
                end = min(len(text), match.end() + 60)
                snippet = f"...{text[start:end]}..."
                if is_false_positive(snippet):
                    continue
                print(f"  [FOUND KEYWORD] '{match.group()}' at: {snippet}")
                findings.append(f"keyword: {match.group()}")
                add_finding("keyword", match.group(), f_url, snippet)

        for pattern_name, pattern in ADVANCED_PATTERNS.items():
            for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
                val = match.group()
                if is_false_positive(val):
                    continue
                print(f"  [FOUND {pattern_name.upper()}] {val}")
                findings.append(f"{pattern_name}: {val}")
                add_finding(pattern_name, val, f_url)

                if pattern_name in ('github_token', 'slack_token', 'openai_key', 'stripe_live',
                                    'google_api', 'npm_token', 'digitalocean_token',
                                    'huggingface_token', 'mapbox_token', 'replicate_token'):
                    if validate_secret(pattern_name, val):
                        add_finding("validated_secret", val, f_url,
                                    f"LIVE {pattern_name} - validated")

                if pattern_name == 'jwt_token':
                    analyze_jwt_token(val, f_url)

        for gql_name, gql_pat in GRAPHQL_PATTERNS.items():
            for match in re.finditer(gql_pat, text):
                if gql_name == 'graphql_endpoint':
                    add_finding("graphql_endpoint", match.group(1), f_url)
                    add_endpoint(match.group(1))
                elif gql_name == 'graphql_query':
                    add_finding("graphql_query", match.group()[:80], f_url)
                elif gql_name == 'graphql_introspection':
                    add_finding("graphql_introspection", match.group(), f_url)

        check_firebase_exposure(text, f_url)
        detect_vulnerable_libs(text, f_url)

        lower = f_url.lower()
        ctype = res.headers.get('Content-Type', '').lower()
        if lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico')):
            scan_binary_content(res.content, f_url)
        elif lower.endswith(('.html', '.htm')) or 'text/html' in ctype:
            scan_html_file(res.text, f_url)

        if lower.endswith('.js'):
            js_results = analyze_javascript(f_url, content=res.text)
            if js_results:
                findings.append(f"JS analysis: {len(js_results['functions'])} functions")
                chunks = extract_bundler_chunks(res.text, f_url)
                for c in chunks:
                    full = urljoin(f_url, c)
                    if is_excluded(full) or not is_safe_url(full):
                        continue
                    rr = fetch_with_backoff(full, retries=1, timeout=8)
                    if rr and rr.status_code == 200:
                        scan_content(rr.text, full)
                try_source_map_variants(f_url)
        return f_url, findings

    workers = min(15, max(5, len(file_list)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_url = {executor.submit(fetch_and_scan, f): f for f in file_list}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                _, findings = future.result()
                if findings:
                    results[url] = findings
            except Exception as e:
                print(f"[-] Error processing {url}: {e}")

    print(f"\n[+] Batch scan completed. Found issues in {len(results)} files.")
    save_site_files()
    return results


def show_paths(target_url, file_list):
    print("\n[+] Extracting internal endpoints from index page and target files...")
    unique_full_paths = set()
    parsed_base = urlparse(target_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    index_res = fetch_with_backoff(target_url, retries=2, timeout=5)
    if index_res and index_res.status_code == 200:
        for match in PATH_RE.finditer(index_res.text):
            raw_path = match.group().strip('"\'')
            if "//" in raw_path or raw_path == "/":
                continue
            unique_full_paths.add(urljoin(base_origin, raw_path))

    def extract_paths(f_url):
        local = set()
        res = fetch_with_backoff(f_url, retries=1, timeout=5)
        if res and res.status_code == 200:
            for match in PATH_RE.finditer(res.text):
                raw_path = match.group().strip('"\'')
                if "//" in raw_path or raw_path == "/":
                    continue
                local.add(urljoin(base_origin, raw_path))
        return local

    if file_list:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(extract_paths, f) for f in file_list]
            for future in as_completed(futures):
                try:
                    unique_full_paths.update(future.result())
                except Exception:
                    pass

    if unique_full_paths:
        print(f"\n[+] Checking status codes for {len(unique_full_paths)} extracted endpoints:\n")

        def check_status(path):
            try:
                BUCKET.consume()
                with RATE_LIMIT:
                    response = SESSION.head(path,
                                            headers={'User-Agent': random.choice(USER_AGENTS)},
                                            timeout=5, allow_redirects=True,
                                            verify=VERIFY_SSL)
                status_code = response.status_code
                if status_code in (400, 403, 405, 501):
                    BUCKET.consume()
                    with RATE_LIMIT:
                        response = SESSION.get(path,
                                               headers={'User-Agent': random.choice(USER_AGENTS)},
                                               timeout=5, stream=True,
                                               verify=VERIFY_SSL)
                    status_code = response.status_code
                    response.close()
                return status_code, path
            except Exception:
                return "ERR", path

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_status, sorted(unique_full_paths))
            for status_code, path in results:
                if status_code == 200:
                    colored_status = f"\033[92m[{status_code}]\033[0m"
                elif status_code == 302:
                    colored_status = f"\033[90m[{status_code}]\033[0m"
                elif status_code in [400, 403, 405]:
                    colored_status = f"\033[93m[{status_code}]\033[0m"
                elif status_code == 404:
                    colored_status = f"\033[91m[{status_code}]\033[0m"
                elif status_code in [500, 503]:
                    colored_status = f"\033[94m[{status_code}]\033[0m"
                else:
                    colored_status = f"[{status_code}]"
                print(f"{colored_status} {path}")
                add_endpoint(path)
                add_finding("endpoint_status", f"{status_code} - {path}", "")
                if classify_endpoint_risk(path) and status_code == 200:
                    add_finding("high_risk_endpoint", path, "",
                                f"High-risk endpoint accessible ({status_code})")
    else:
        print("  [+] No valid paths found.")
    save_site_files()


def open_results_in_browser():
    if LIVE["site_key"] is None:
        print("[-] No active scan.")
        return
    save_site_files()
    site_key = LIVE["site_key"]
    scan_num = LIVE["scan_number"]
    site_file = (RESULTS_DIR / site_key / f"{site_key}.html").resolve()
    if not site_file.exists():
        print("[-] Results file not found.")
        return
    url = site_file.as_uri() + f"#run-{scan_num}"
    print(f"[+] Opening: {url}")
    webbrowser.open(url)


def results_menu():
    while True:
        print("\n----------- Results -----------")
        print("[1] Open in Browser")
        print("[2] Export JSON")
        print("[3] Export TXT")
        print("[4] Back")
        sub = input("Choose an option :").strip()
        if sub == '1':
            open_results_in_browser()
        elif sub == '2':
            export_json()
        elif sub == '3':
            export_txt()
        elif sub == '4':
            break
        else:
            print("[-] Invalid choice.")


if __name__ == "__main__":
    clear_screen()
    print_banner()
    url = input("Enter target URL : ").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not is_safe_url(url):
        print("[-] Target URL is blocked (SSRF protection).")
        raise SystemExit(1)

    site_key = extract_site_key(url)

    init_live(site_key, url)
    target_files = get_target_files(url)
    if not target_files:
        res = fetch_with_backoff(url, retries=2, timeout=10)
        if res and res.status_code == 200:
            scan_html_file(res.text, url)
            add_file(url)

    run_initial_analysis(url, target_files)

    save_site_files()

    while True:
        print("\n----------- Options -----------")
        print("[1] Analyze a single file")
        print("[2] Analyze all files")
        print("[3] Advanced custom search")
        print("[4] Endpoint extraction")
        print("[5] Results")
        print("[6] Exit")
        choice = input("Choose an option :").strip()

        if choice == '1':
            if not target_files:
                print("[-] No target files available.")
            else:
                analyze_single_file(target_files)
        elif choice == '2':
            if not target_files:
                print("[-] No target files available.")
            else:
                analyze_all_files_optimized(target_files)
        elif choice == '3':
            if not target_files:
                print("[-] No target files available.")
            else:
                advanced_search(target_files)
        elif choice == '4':
            show_paths(url, target_files)
        elif choice == '5':
            results_menu()
        elif choice == '6':
            finalize_live()
            print("[>] Good luck, Hunter.")
            break
        else:
            print("[-] Invalid choice.")

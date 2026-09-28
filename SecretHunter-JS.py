# SecretHunter-JS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import re
import math
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore
import urllib3
import html as html_lib
import datetime
import webbrowser
from pathlib import Path

try:
    import jsbeautifier
    HAS_JSBEAUTIFIER = True
except ImportError:
    HAS_JSBEAUTIFIER = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERIFY_SSL = os.getenv("SECRETHUNTER_VERIFY_SSL", "false").lower() == "true"
RATE_LIMIT = Semaphore(5)

KEYWORDS = [
    r"api_key", r"password", r"secret", r"access_token", r"auth_token", r"bearer", r"jwt",
    r"refresh_token", r"client_secret", r"api_secret", r"password_hash", r"passwd", r"credential",
    r"aws_access_key", r"aws_secret_key", r"aws_account_id", r"azure_storage_key",
    r"firebase_config", r"gcp_api_key", r"s3_bucket", r"do_token", r"digitalocean_token",
    r"docker_hub", r"kubernetes", r"k8s", r"root_password", r"ssh_private_key",
    r"db_password", r"db_username", r"db_url", r"connection_string", r"mysql_uri",
    r"mongodb_uri", r"mysql_password", r"postgres_url", r"redis_url", r"sql_connection",
    r"/admin", r"/config", r"/env", r"/backup", r"/debug", r"/phpinfo", r"/.git",
    r"internal_api", r"dev_mode", r"staging_url", r"/wp-config", r"/cpanel",
    r"stripe_key", r"stripe_secret", r"paypal_client_id", r"braintree_key",
    r"google_maps_api", r"maps_api_key", r"sendgrid_key", r"mailgun_key",
    r"private_key", r"ssh_key", r"public_key",
    r"credit_card", r"token_type", r"session_id",
    r"slack_token", r"slack_webhook", r"discord_webhook", r"telegram_bot_token",
    r"oauth_token", r"oauth_secret", r"consumer_key", r"consumer_secret",
    r"encryption_key", r"cipher_key", r"auth_key", r"license_key",
    r"ftp_password", r"ftp_username", r"smtp_password", r"smtp_username",
    r"php_mailer", r"auth_domain"
]

ADVANCED_PATTERNS = {
    'github_token': r'ghp_[a-zA-Z0-9]{36}',
    'github_old': r'\b[a-f0-9]{40}\b',
    'aws_key': r'AKIA[0-9A-Z]{16}',
    'google_api': r'AIza[0-9A-Za-z-_]{35}',
    'slack_token': r'xox[baprs]-[0-9a-zA-Z-]{10,}',
    'jwt_token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'mongodb_uri': r'mongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@',
    'mysql_uri': r'mysql://[a-zA-Z0-9_]+:[^@\s]+@',
    'postgres_uri': r'postgresql://[a-zA-Z0-9_]+:[^@\s]+@',
    'redis_uri': r'redis://:[^@\s]+@',
    'openai_key': r'sk-[a-zA-Z0-9]{48}',
    'anthropic_key': r'sk-ant-[a-zA-Z0-9\-_]{95}',
    'stripe_live': r'sk_live_[0-9a-zA-Z]{24}',
    'twilio_sid': r'AC[a-f0-9]{32}',
    'heroku_api': r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b',
    'npm_token': r'npm_[a-zA-Z0-9]{36}',
}

SEVERITY = {
    'private_key': 'critical',
    'aws_key': 'critical',
    'github_token': 'critical',
    'mongodb_uri': 'critical',
    'mysql_uri': 'critical',
    'postgres_uri': 'critical',
    'redis_uri': 'critical',
    'openai_key': 'critical',
    'anthropic_key': 'critical',
    'stripe_live': 'critical',
    'twilio_sid': 'high',
    'heroku_api': 'high',
    'npm_token': 'high',
    'google_api': 'high',
    'slack_token': 'high',
    'jwt_token': 'high',
    'github_old': 'medium',
    'source_map': 'medium',
    'source_map_source': 'medium',
    'high_entropy': 'medium',
    'high_entropy_js': 'medium',
    'cloud_storage': 'medium',
    'exposed_path': 'high',
    'endpoint_status': 'info',
    'path': 'info',
    'keyword': 'low',
    'js_endpoint': 'info',
    'custom_search': 'low',
    'image_text': 'low',
}

IGNORE_VALUES = {
    "undefined", "null", "true", "false", "example", "test", "demo",
    "your_key_here", "xxx", "changeme", "placeholder", "todo", "sample",
    "password", "secret", "apikey", "api_key", "token", "your_api_key",
    "your_token_here", "insert_key_here", "enter_key_here", "n/a", "na",
    "none", "empty", "default", "dummy", "fake", "mock", "foobar",
    "lorem", "ipsum", "1234", "abcd", "aaaa", "0000", "username", "user_name",
    "userName", "user_id", "userId", "email", "salt", "SALT"
}

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/.git/config", "/.git/HEAD", "/.env", "/.DS_Store",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/server-status", "/phpinfo.php", "/info.php", "/test.php",
    "/config.php", "/wp-config.php", "/.htaccess", "/web.config",
    "/package.json", "/composer.json", "/.svn/entries",
    "/.well-known/openid-configuration", "/crossdomain.xml",
    "/clientaccesspolicy.xml", "/api/swagger.json", "/swagger.json",
    "/openapi.json", "/api-docs", "/graphql", "/graphiql"
]

PATH_PATTERN = r"[\"']\/(?:[a-zA-Z0-9\-_./]+)[\"']"
CLOUD_PATTERNS = [
    r"[a-zA-Z0-9\-_.]+\.s3\.amazonaws\.com",
    r"[a-zA-Z0-9\-_.]+\.blob\.core\.windows\.net",
    r"storage\.googleapis\.com\/[a-zA-Z0-9\-_.]+"
]

TARGET_EXTENSIONS = ('.js', '.php', '.json', '.xml', '.config', '.yml', '.yaml', '.asp', '.aspx', '.jsp', '.env',
                     '.sql', '.log', '.bak', '.properties', '.ini', '.conf', '.map', '.html', '.htm')

EXT_REGEX_STR = r"(?:js|php|json|xml|config|yml|yaml|asp|aspx|jsp|env|sql|log|bak|properties|ini|conf|map|html|htm)"

RESULTS_DIR = Path("results")

COMMON_SUBDOMAINS = {
    "www", "main", "api", "app", "admin", "dev", "staging", "test", "testing",
    "portal", "dashboard", "my", "web", "mobile", "m", "beta", "demo", "support",
    "help", "blog", "shop", "store", "secure", "login", "auth", "cdn", "static",
    "assets", "media", "files", "download", "downloads", "upload", "uploads",
    "mail", "smtp", "ftp", "vpn", "proxy", "gateway", "edge", "node", "server",
    "cloud", "host", "hosting", "ns", "ns1", "ns2", "dns", "mx", "pop", "imap",
    "sandbox", "preview", "prod", "production", "qa", "uat", "stage", "local",
    "internal", "intranet", "extranet", "partner", "partners", "client", "clients",
    "customer", "customers", "user", "users", "member", "members", "account",
    "accounts", "payment", "payments", "billing", "invoice", "orders", "order",
    "cart", "checkout", "docs", "doc", "wiki", "forum", "community", "news",
    "events", "jobs", "careers", "about", "contact", "info", "go", "link", "links",
    "url", "redirect", "track", "tracking", "analytics", "stats", "status", "monitor",
    "graphql", "rest", "ws", "socket", "realtime", "live", "stream", "video", "audio",
    "img", "images", "image", "css", "js", "fonts", "font", "lib", "libs", "pkg",
    "packages", "npm", "git", "gitlab", "github", "bitbucket", "jenkins", "ci", "cd",
    "build", "deploy", "k8s", "kubernetes", "docker", "registry", "repo", "repos",
    "backup", "backups", "db", "database", "sql", "mysql", "postgres", "mongo",
    "redis", "cache", "queue", "worker", "workers", "task", "tasks", "cron", "job",
    "jobs", "logs", "log", "metrics", "grafana", "kibana", "prometheus", "sentry",
    "new", "old", "v1", "v2", "v3", "ver1", "ver2", "legacy", "archive", "archived"
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


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = r"""
    ███████╗███████╗ ██████╗██████╗ ███████╗████████╗      ██╗███████╗
    ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝      ██║██╔════╝
    ███████╗█████╗  ██║     ██████╔╝█████╗     ██║         ██║███████╗
    ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║    ██   ██║╚════██║
    ███████║███████╗╚██████╗██║  ██║███████╗   ██║    ╚█████╔╝███████║
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
    return site_key or "unknown"


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
    if len(v) < 8:
        return True
    vl = v.lower()
    if vl in IGNORE_VALUES:
        return True
    if re.match(r'^[\$\{\}<%]', v):
        return True
    if re.match(r'^(?:your|my|the|some|any|example|test|demo|sample|placeholder|dummy|fake|mock)[_\-]', vl):
        return True
    if re.match(r'^[xX]+$', v):
        return True
    if len(set(v)) <= 2:
        return True
    if re.match(r'^[A-Z_]{2,20}$', v):
        return True
    if re.match(r'^[a-zA-Z]+$', v) and len(v) < 15:
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


def fetch_with_backoff(url, retries=3, timeout=10, stream=False):
    for i in range(retries):
        if is_excluded(url):
            return None
        try:
            with RATE_LIMIT:
                r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'},
                                 timeout=timeout, verify=VERIFY_SSL, stream=stream)
            if r.status_code == 429:
                time.sleep(2 ** i)
                continue
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
    site_file = site_dir / f"{site_key}.html"
    if site_file.exists():
        try:
            content = site_file.read_text(encoding="utf-8")
            nums = re.findall(r'id="run-(\d+)"', content)
            LIVE["scan_number"] = (max(int(n) for n in nums) + 1) if nums else 1
        except Exception:
            LIVE["scan_number"] = 1
    else:
        LIVE["scan_number"] = 1


def add_finding(finding_type, value, file_url="", context=""):
    if LIVE["status"] != "running":
        return
    if finding_type not in ('endpoint_status', 'path', 'js_endpoint', 'exposed_path'):
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
        sorted_findings = sorted(findings, key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.get("severity", "low")))
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


def extract_old_run_blocks(site_file, current_num):
    if not site_file.exists():
        return []
    try:
        content = site_file.read_text(encoding="utf-8")
    except Exception:
        return []
    pattern = re.compile(r'<div class="run-block" id="run-(\d+)-block">', re.DOTALL)
    matches = list(pattern.finditer(content))
    blocks = []
    for i, m in enumerate(matches):
        num = int(m.group(1))
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else content.find("</body>", start)
        if end == -1:
            end = len(content)
        block = content[start:end].rstrip()
        if num == current_num:
            continue
        blocks.append((num, block))
    return blocks


def build_site_html_with_history(site_key, current_block, current_num, base_url):
    site_dir = RESULTS_DIR / site_key
    site_file = site_dir / f"{site_key}.html"
    old_blocks = extract_old_run_blocks(site_file, current_num)
    all_nums = sorted(set([n for n, _ in old_blocks] + [current_num]))

    parts = [HTML_HEAD.format(title=f"Secret-JS - {esc(site_key)}")]
    parts.append('<a id="top"></a>')
    parts.append('<div class="top-nav">')
    parts.append(f'<h1 style="margin:0;">📑 Secret-JS - {esc(site_key)}</h1>')
    parts.append('</div>')

    if len(all_nums) >= 1:
        parts.append('<div class="toc">')
        parts.append(f'<b>Runs of {esc(site_key)}:</b><br>')
        for n in all_nums:
            parts.append(f'<a href="#run-{n}">{esc(site_key)} — Run {n}</a>')
        parts.append('</div>')

    for n, block in sorted(old_blocks, key=lambda x: x[0]):
        parts.append(block)
    parts.append(current_block)
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
    current_block = render_run_section(current_scan, site_key, include_anchor=True)
    html_content = build_site_html_with_history(
        site_key, current_block, LIVE["scan_number"], LIVE["target_url"]
    )
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
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


def scan_binary_content(content, file_url):
    if file_url.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico')):
        try:
            text_matches = re.findall(rb'[\x20-\x7E]{4,}', content)
            for match in text_matches:
                try:
                    text = match.decode('utf-8', errors='ignore')
                    if any(keyword.replace(r'\\', '').lower() in text.lower() for keyword in KEYWORDS):
                        print(f"  [FOUND IN IMAGE] {text[:100]}...")
                        add_finding("image_text", text[:200], file_url)
                except Exception:
                    pass
        except Exception:
            pass


def beautify_js(content):
    if not HAS_JSBEAUTIFIER:
        return content
    try:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        return jsbeautifier.beautify(content, opts)
    except Exception:
        return content


def find_source_maps(content, file_url):
    matches = re.findall(r'//[#@]\s*sourceMappingURL=(\S+)', content)
    for sm in matches:
        sm_url = urljoin(file_url, sm)
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
        except Exception:
            pass


def analyze_javascript(file_url):
    try:
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
        if functions:
            print(f"  Sample functions: {functions[:5]}")
        if long_strings:
            for s in long_strings[:3]:
                if calculate_entropy(s) > 4.5:
                    print(f"  [HIGH ENTROPY STRING] {s[:50]}...")
                    add_finding("high_entropy_js", s[:120], file_url,
                                f"Entropy: {calculate_entropy(s):.2f}")
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
    print(f"\n[!] Scanning: {file_url}")
    found = False
    keyword_pattern = re.compile('|'.join(KEYWORDS), re.IGNORECASE)
    for match in re.finditer(keyword_pattern, content):
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

    for pattern in CLOUD_PATTERNS:
        for match in re.finditer(pattern, content):
            val = match.group()
            if is_false_positive(val):
                continue
            found = True
            print(f"  [FOUND CLOUD STORAGE] {val}")
            add_finding("cloud_storage", val, file_url)

    words = re.findall(r'[\"\']([a-zA-Z0-9\-_/+=]{16,})[\"\']', content)
    for word in words:
        if is_false_positive(word):
            continue
        ent = calculate_entropy(word)
        if ent > 4.5:
            found = True
            print(f"  [HIGH ENTROPY SECRET] '{word}' (Entropy: {ent:.2f})")
            add_finding("high_entropy", word, file_url, f"Entropy: {ent:.2f}")

    path_matches = re.finditer(PATH_PATTERN, content)
    unique_paths = set()
    for match in path_matches:
        raw_path = match.group().strip('"\'')
        if "//" in raw_path or raw_path == "/":
            continue
        unique_paths.add(raw_path)

    for path in unique_paths:
        found = True
        print(f"  [FOUND PATH] {path}")
        add_finding("path", path, file_url)
        add_endpoint(path)

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
    soup = BeautifulSoup(content, 'html.parser')
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


def analyze_inline_scripts(target_url):
    print(f"\n[+] Fetching {target_url} for inline script analysis...")
    res = fetch_with_backoff(target_url, retries=2, timeout=10)
    if not res or res.status_code != 200:
        print("[-] Failed to fetch target page.")
        return
    soup = BeautifulSoup(res.text, 'html.parser')
    scan_inline_scripts(soup, target_url)
    save_site_files()
    print("[+] Inline scripts scan complete.")


def check_common_paths(base_url):
    print(f"\n[+] Checking common sensitive paths on {base_url}...")
    for p in COMMON_PATHS:
        url = urljoin(base_url, p)
        if is_excluded(url):
            continue
        try:
            with RATE_LIMIT:
                r = requests.head(url, headers={'User-Agent': 'Mozilla/5.0'},
                                  timeout=5, allow_redirects=False, verify=VERIFY_SSL)
            if r.status_code in (200, 301, 302, 401, 403):
                print(f"  [EXPOSED] [{r.status_code}] {url}")
                add_finding("exposed_path", url, "", f"Status {r.status_code}")
                add_endpoint(url)
        except Exception:
            pass


def get_target_files(target_url):
    try:
        response = fetch_with_backoff(target_url, retries=2, timeout=10)
        if not response or response.status_code != 200:
            print(f"[-] Failed to connect.")
            return []
        soup = BeautifulSoup(response.text, 'html.parser')
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

        text_content = response.text
        potential_paths = re.findall(rf"[\"']([a-zA-Z0-9\-_./]+\.{EXT_REGEX_STR})[\"']",
                                     text_content, re.IGNORECASE)
        for p in potential_paths:
            full = urljoin(target_url, p)
            if not is_excluded(full):
                target_files.add(full)

        def crawl_recursive(file_url, depth=1):
            if depth > 2:
                return
            res = fetch_with_backoff(file_url, retries=1, timeout=5)
            if res and res.status_code == 200:
                sub_matches = re.findall(
                    rf"[\"']([a-zA-Z0-9\-_./]+\.{EXT_REGEX_STR})[\"']",
                    res.text, re.IGNORECASE)
                parsed_base = urlparse(file_url)
                base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
                for sub_file in sub_matches:
                    full_sub_url = urljoin(base_origin, sub_file)
                    if full_sub_url not in target_files and '.css' not in full_sub_url.lower() and not is_excluded(full_sub_url):
                        target_files.add(full_sub_url)
                        crawl_recursive(full_sub_url, depth + 1)

        for initial_file in list(target_files):
            crawl_recursive(initial_file)

        if target_url not in target_files:
            target_files.add(target_url)

        file_list = list(target_files)
        for f in file_list:
            add_file(f)

        check_common_paths(target_url)

        print(f"\n[+] Found {len(file_list)} target files (Scripts, HTML, Configs, Logs, Backups, etc.):\n")
        for i, f in enumerate(file_list, 1):
            print(f"[{i}] {f}")
        return file_list
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        return []


def save_to_file(file_list):
    if not file_list:
        print("[-] No target files to save.")
        return
    filename = input("Enter filename: ").strip()
    if not filename:
        print("[-] Filename cannot be empty.")
        return
    try:
        new_data = "\n".join(file_list)
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                existing_content = f.read().strip()
            with open(filename, 'w', encoding='utf-8') as f:
                if existing_content:
                    f.write(existing_content + "\n\n\n" + new_data + "\n")
                else:
                    f.write(new_data + "\n")
        else:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(new_data + "\n")
        print(f"[+] Successfully saved to {filename}")
    except Exception as e:
        print(f"[-] Error saving file: {e}")


def analyze_single_file(file_list):
    if not file_list:
        print("[-] No target files available.")
        return
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
                    analyze_javascript(target_file)
                save_site_files()
            else:
                print(f"[-] Failed to fetch file.")
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
    custom_keywords = [kw.strip() for kw in custom_input.split(',')]
    print(f"\n[+] Searching for: {', '.join(custom_keywords)}")
    results = {}
    total_checked = 0
    for file_url in file_list:
        res = fetch_with_backoff(file_url, retries=1, timeout=5)
        total_checked += 1
        if res and res.status_code == 200:
            lines = res.text.splitlines()
            found_matches = []
            for line_num, line in enumerate(lines, 1):
                line_lower = line.lower()
                found_keywords = [kw for kw in custom_keywords if kw.lower() in line_lower]
                if found_keywords:
                    clean_line = line.strip()[:100]
                    if len(line.strip()) > 100:
                        clean_line += "..."
                    found_matches.append({
                        'keywords': found_keywords,
                        'line_number': line_num,
                        'content': clean_line
                    })
                    print(f"  [FOUND] {file_url} -> Line {line_num}: {clean_line}")
                    print(f"    Keywords: {', '.join(found_keywords)}")
                    add_finding("custom_search", ", ".join(found_keywords), file_url,
                                f"Line {line_num}: {clean_line}")
            if found_matches:
                results[file_url] = found_matches
        else:
            print(f"  [!] Could not fetch: {file_url}")
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

    def fetch_and_scan_with_retry(f_url, retries=2):
        res = fetch_with_backoff(f_url, retries=retries, timeout=10)
        if res and res.status_code == 200:
            findings = []
            print(f"\n[!] Scanning: {f_url}")
            keyword_pattern = re.compile('|'.join(KEYWORDS), re.IGNORECASE)
            for match in re.finditer(keyword_pattern, res.text):
                start = max(0, match.start() - 60)
                end = min(len(res.text), match.end() + 60)
                snippet = f"...{res.text[start:end]}..."
                if is_false_positive(snippet):
                    continue
                print(f"  [FOUND KEYWORD] '{match.group()}' at: {snippet}")
                findings.append(f"keyword: {match.group()}")
                add_finding("keyword", match.group(), f_url, snippet)

            for pattern_name, pattern in ADVANCED_PATTERNS.items():
                for match in re.finditer(pattern, res.text, re.IGNORECASE | re.MULTILINE):
                    val = match.group()
                    if is_false_positive(val):
                        continue
                    print(f"  [FOUND {pattern_name.upper()}] {val}")
                    findings.append(f"{pattern_name}: {val}")
                    add_finding(pattern_name, val, f_url)

            lower = f_url.lower()
            ctype = res.headers.get('Content-Type', '').lower()
            if lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico')):
                scan_binary_content(res.content, f_url)
            elif lower.endswith(('.html', '.htm')) or 'text/html' in ctype:
                scan_html_file(res.text, f_url)

            if lower.endswith('.js'):
                js_results = analyze_javascript(f_url)
                if js_results:
                    findings.append(f"JS analysis: {len(js_results['functions'])} functions")
            return f_url, findings
        return f_url, []

    with ThreadPoolExecutor(max_workers=15) as executor:
        future_to_url = {executor.submit(fetch_and_scan_with_retry, f): f for f in file_list}
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
    print(f"\n[+] Extracting internal endpoints from index page and target files...")
    unique_full_paths = set()
    parsed_base = urlparse(target_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    index_res = fetch_with_backoff(target_url, retries=2, timeout=5)
    if index_res and index_res.status_code == 200:
        for match in re.finditer(PATH_PATTERN, index_res.text):
            raw_path = match.group().strip('"\'')
            if "//" in raw_path or raw_path == "/":
                continue
            unique_full_paths.add(urljoin(base_origin, raw_path))

    def extract_paths(f_url):
        local_paths = set()
        res = fetch_with_backoff(f_url, retries=1, timeout=5)
        if res and res.status_code == 200:
            for match in re.finditer(PATH_PATTERN, res.text):
                raw_path = match.group().strip('"\'')
                if "//" in raw_path or raw_path == "/":
                    continue
                local_paths.add(urljoin(base_origin, raw_path))
        return local_paths

    if file_list:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(extract_paths, f) for f in file_list]
            for future in as_completed(futures):
                unique_full_paths.update(future.result())

    if unique_full_paths:
        print(f"\n[+] Checking status codes for {len(unique_full_paths)} extracted endpoints:\n")

        def check_status(path):
            try:
                with RATE_LIMIT:
                    response = requests.head(path, headers={'User-Agent': 'Mozilla/5.0'},
                                             timeout=5, allow_redirects=True, verify=VERIFY_SSL)
                status_code = response.status_code
                if status_code in (405, 403):
                    with RATE_LIMIT:
                        response = requests.get(path, headers={'User-Agent': 'Mozilla/5.0'},
                                                timeout=5, stream=True, verify=VERIFY_SSL)
                    status_code = response.status_code
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


if __name__ == "__main__":
    clear_screen()
    print_banner()
    url = input("Enter target URL : ").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    site_key = extract_site_key(url)

    init_live(site_key, url)
    target_files = get_target_files(url)
    if not target_files:
        print("\n[+] No external files found. Scanning index page directly...")
        res = fetch_with_backoff(url, retries=2, timeout=10)
        if res and res.status_code == 200:
            scan_html_file(res.text, url)
            add_file(url)
        else:
            print("[-] Could not fetch index page.")
    save_site_files()

    while True:
        print("\n----------- Options -----------")
        print("[1] Analyze a single file")
        print("[2] Analyze all files (Optimized)")
        print("[3] Advanced custom search")
        print("[4] Endpoint extraction")
        print("[5] Analyze inline scripts (HTML + data-attrs + comments)")
        print("[6] Open Current Scan Results in Browser")
        print("[7] Export JSON")
        print("[8] Save to txt file")
        print("[9] Exit")
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
            analyze_inline_scripts(url)
        elif choice == '6':
            open_results_in_browser()
        elif choice == '7':
            export_json()
        elif choice == '8':
            if not target_files:
                print("[-] No target files available.")
            else:
                save_to_file(target_files)
        elif choice == '9':
            finalize_live()
            print("[>] Good luck, Hunter.")
            break
        else:
            print("[-] Invalid choice.")

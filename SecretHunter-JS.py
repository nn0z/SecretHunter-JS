# SecretHunter-JS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import re
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import html as html_lib
import datetime
import webbrowser
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    r"private_key", r"ssh_key", r"public_key", r"username", r"admin_user",
    r"email", r"credit_card", r"token_type", r"session_id", r"user_id",
    r"slack_token", r"slack_webhook", r"discord_webhook", r"telegram_bot_token",
    r"oauth_token", r"oauth_secret", r"consumer_key", r"consumer_secret",
    r"encryption_key", r"cipher_key", r"salt", r"auth_key", r"license_key",
    r"ftp_password", r"ftp_username", r"smtp_password", r"smtp_username",
    r"graphql", r"swagger", r"openapi", r"php_mailer", r"auth_domain"
]

ADVANCED_PATTERNS = {
    'github_token': r'ghp_[a-zA-Z0-9]{36}',
    'github_old': r'[a-f0-9]{40}',
    'aws_key': r'AKIA[0-9A-Z]{16}',
    'google_api': r'AIza[0-9A-Za-z-_]{35}',
    'slack_token': r'xox[baprs]-[0-9a-zA-Z-]+',
    'jwt_token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'mongodb_uri': r'mongodb(?:\+srv)?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@',
    'mysql_uri': r'mysql://[a-zA-Z0-9]+:[a-zA-Z0-9]+@',
    'postgres_uri': r'postgresql://[a-zA-Z0-9]+:[a-zA-Z0-9]+@',
    'redis_uri': r'redis://:[a-zA-Z0-9]+@',
}

PATH_PATTERN = r"[\"']\/(?:[a-zA-Z0-9\-_./]+)[\"']"
CLOUD_PATTERNS = [
    r"[a-zA-Z0-9\-_.]+\.s3\.amazonaws\.com",
    r"[a-zA-Z0-9\-_.]+\.blob\.core\.windows\.net",
    r"storage\.googleapis\.com\/[a-zA-Z0-9\-_.]+"
]

TARGET_EXTENSIONS = ('.js', '.php', '.json', '.xml', '.config', '.yml', '.yaml', '.asp', '.aspx', '.jsp', '.env',
                     '.sql', '.log', '.bak', '.properties', '.ini', '.conf')
EXT_REGEX_STR = r"(?:js|php|json|xml|config|yml|yaml|asp|aspx|jsp|env|sql|log|bak|properties|ini|conf)"

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
    LIVE["findings"].append({
        "type": finding_type,
        "value": str(value),
        "file": file_url,
        "context": context,
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

    parts.append('<div class="section">')
    parts.append(f'<h3>📁 Files discovered (<span class="count">{len(scan["files"])}</span>)</h3>')
    if scan["files"]:
        for f in scan["files"]:
            parts.append(f'<div class="finding"><span class="value">{make_clickable(f, base_url)}</span></div>')
    else:
        parts.append('<div class="empty">No files found yet...</div>')
    parts.append('</div>')

    parts.append('<div class="section">')
    parts.append(f'<h3>⚠️ Findings (<span class="count">{len(scan["findings"])}</span>)</h3>')
    if scan["findings"]:
        for f in scan["findings"]:
            parts.append('<div class="finding">')
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


def finalize_live():
    if LIVE["status"] != "running":
        return
    LIVE["status"] = "completed"
    LIVE["finished_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_site_files()


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


def analyze_javascript(file_url):
    try:
        res = requests.get(file_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10, verify=False)
        if res.status_code == 200:
            content = res.text
            endpoints = re.findall(r'["\'](/api/[a-zA-Z0-9/_-]+)["\']', content)
            endpoints += re.findall(r'["\'](/v[0-9]+/[a-zA-Z0-9/_-]+)["\']', content)
            unique_endpoints = list(set(endpoints))
            functions = re.findall(r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(', content)
            functions += re.findall(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function\s*\(', content)
            functions += re.findall(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*function\s*\(', content)
            variables = re.findall(r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=', content)
            long_strings = re.findall(r'["\']([a-zA-Z0-9+/=]{40,})["\']', content)

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
        found = True
        start = max(0, match.start() - 30)
        end = min(len(content), match.end() + 30)
        snippet = f"...{content[start:end]}..."
        print(f"  [FOUND KEYWORD] '{match.group()}' at: {snippet}")
        add_finding("keyword", match.group(), file_url, snippet)

    for pattern_name, pattern in ADVANCED_PATTERNS.items():
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            found = True
            print(f"  [FOUND {pattern_name.upper()}] {match.group()}")
            add_finding(pattern_name, match.group(), file_url)

    for pattern in CLOUD_PATTERNS:
        for match in re.finditer(pattern, content):
            found = True
            print(f"  [FOUND CLOUD STORAGE] {match.group()}")
            add_finding("cloud_storage", match.group(), file_url)

    words = re.findall(r'[\"\']([a-zA-Z0-9\-_/+=]{16,})[\"\']', content)
    for word in words:
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


def get_target_files(target_url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(target_url, headers=headers, timeout=10, verify=False)
        if response.status_code != 200:
            print(f"[-] Failed to connect. Status code: {response.status_code}")
            return []
        soup = BeautifulSoup(response.text, 'html.parser')
        target_files = set()
        for tag in soup.find_all(['script', 'link', 'a', 'iframe']):
            for attr in ['src', 'href', 'data-src', 'data-url']:
                val = tag.get(attr)
                if val:
                    val_lower = val.lower()
                    if val_lower.endswith(TARGET_EXTENSIONS) or any(
                            ext in val_lower for ext in ['.js?', '.php?', '.json?']):
                        if '.css' not in val_lower:
                            full_url = urljoin(target_url, val)
                            target_files.add(full_url)

        text_content = response.text
        potential_paths = re.findall(rf"[\"']([a-zA-Z0-9\-_./]+\.{EXT_REGEX_STR})[\"']",
                                     text_content, re.IGNORECASE)
        for p in potential_paths:
            target_files.add(urljoin(target_url, p))

        def crawl_recursive(file_url, depth=1):
            if depth > 2:
                return
            try:
                res = requests.get(file_url, headers={'User-Agent': 'Mozilla/5.0'},
                                   timeout=5, verify=False)
                if res.status_code == 200:
                    sub_matches = re.findall(
                        rf"[\"']([a-zA-Z0-9\-_./]+\.{EXT_REGEX_STR})[\"']",
                        res.text, re.IGNORECASE)
                    parsed_base = urlparse(file_url)
                    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
                    for sub_file in sub_matches:
                        full_sub_url = urljoin(base_origin, sub_file)
                        if full_sub_url not in target_files and '.css' not in full_sub_url.lower():
                            target_files.add(full_sub_url)
                            crawl_recursive(full_sub_url, depth + 1)
            except Exception:
                pass

        for initial_file in list(target_files):
            crawl_recursive(initial_file)

        file_list = list(target_files)
        for f in file_list:
            add_file(f)

        print(f"\n[+] Found {len(file_list)} target files (Scripts, Configs, Logs, Backups, etc.):\n")
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
            res = requests.get(target_file, headers={'User-Agent': 'Mozilla/5.0'},
                               timeout=10, verify=False)
            if res.status_code == 200:
                if target_file.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico')):
                    scan_binary_content(res.content, target_file)
                else:
                    scan_content(res.text, target_file)
                if target_file.endswith('.js'):
                    analyze_javascript(target_file)
                save_site_files()
            else:
                print(f"[-] Failed to fetch file. Status code: {res.status_code}")
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
        try:
            res = requests.get(file_url, headers={'User-Agent': 'Mozilla/5.0'},
                               timeout=5, verify=False)
            total_checked += 1
            if res.status_code == 200:
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
                print(f"  [!] Could not fetch: {file_url} (Status: {res.status_code})")
        except Exception as e:
            print(f"  [-] Error processing {file_url}: {e}")
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
        for attempt in range(retries):
            try:
                res = requests.get(f_url, headers={'User-Agent': 'Mozilla/5.0'},
                                   timeout=10, verify=False)
                if res.status_code == 200:
                    findings = []
                    print(f"\n[!] Scanning: {f_url}")
                    keyword_pattern = re.compile('|'.join(KEYWORDS), re.IGNORECASE)
                    for match in re.finditer(keyword_pattern, res.text):
                        start = max(0, match.start() - 30)
                        end = min(len(res.text), match.end() + 30)
                        snippet = f"...{res.text[start:end]}..."
                        print(f"  [FOUND KEYWORD] '{match.group()}' at: {snippet}")
                        findings.append(f"keyword: {match.group()}")
                        add_finding("keyword", match.group(), f_url, snippet)

                    for pattern_name, pattern in ADVANCED_PATTERNS.items():
                        for match in re.finditer(pattern, res.text, re.IGNORECASE | re.MULTILINE):
                            print(f"  [FOUND {pattern_name.upper()}] {match.group()}")
                            findings.append(f"{pattern_name}: {match.group()}")
                            add_finding(pattern_name, match.group(), f_url)

                    if f_url.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico')):
                        scan_binary_content(res.content, f_url)

                    if f_url.endswith('.js'):
                        js_results = analyze_javascript(f_url)
                        if js_results:
                            findings.append(f"JS analysis: {len(js_results['functions'])} functions")
                    return f_url, findings
                else:
                    if attempt < retries - 1:
                        print(f"  [!] Retry {attempt + 1}/{retries} for {f_url}")
            except Exception as e:
                if attempt == retries - 1:
                    print(f"[-] Failed after {retries} retries: {f_url} - {e}")
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

    try:
        index_res = requests.get(target_url, headers={'User-Agent': 'Mozilla/5.0'},
                                 timeout=5, verify=False)
        if index_res.status_code == 200:
            for match in re.finditer(PATH_PATTERN, index_res.text):
                raw_path = match.group().strip('"\'')
                if "//" in raw_path or raw_path == "/":
                    continue
                unique_full_paths.add(urljoin(base_origin, raw_path))
    except Exception:
        pass

    def extract_paths(f_url):
        local_paths = set()
        try:
            res = requests.get(f_url, headers={'User-Agent': 'Mozilla/5.0'},
                               timeout=5, verify=False)
            if res.status_code == 200:
                for match in re.finditer(PATH_PATTERN, res.text):
                    raw_path = match.group().strip('"\'')
                    if "//" in raw_path or raw_path == "/":
                        continue
                    local_paths.add(urljoin(base_origin, raw_path))
        except Exception:
            pass
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
                response = requests.head(path, headers={'User-Agent': 'Mozilla/5.0'},
                                         timeout=5, allow_redirects=True, verify=False)
                status_code = response.status_code
                if status_code == 405 or status_code == 403:
                    response = requests.get(path, headers={'User-Agent': 'Mozilla/5.0'},
                                            timeout=5, stream=True, verify=False)
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
    save_site_files()

    if target_files:
        while True:
            print("\n----------- Options -----------")
            print("[1] Analyze a single file")
            print("[2] Analyze all files (Optimized)")
            print("[3] Advanced custom search")
            print("[4] Endpoint extraction")
            print("[5] Open Current Scan Results in Browser")
            print("[6] Save to txt file")
            print("[7] Exit")
            choice = input("Choose an option :").strip()

            if choice == '1':
                analyze_single_file(target_files)
            elif choice == '2':
                analyze_all_files_optimized(target_files)
            elif choice == '3':
                advanced_search(target_files)
            elif choice == '4':
                show_paths(url, target_files)
            elif choice == '5':
                open_results_in_browser()
            elif choice == '6':
                save_to_file(target_files)
            elif choice == '7':
                finalize_live()
                print("[>] Good luck, Hunter.")
                break
            else:
                print("[-] Invalid choice.")
    else:
        finalize_live()

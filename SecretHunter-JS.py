# SecretHunter-JS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import re
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
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

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
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
                except:
                    pass
        except:
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
            if functions:
                print(f"  Sample functions: {functions[:5]}")
            if long_strings:
                for s in long_strings[:3]:
                    if calculate_entropy(s) > 4.5:
                        print(f"  [HIGH ENTROPY STRING] {s[:50]}...")
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
        print(f"  [FOUND KEYWORD] '{match.group()}' at: ...{content[start:end]}...")
    for pattern_name, pattern in ADVANCED_PATTERNS.items():
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            found = True
            print(f"  [FOUND {pattern_name.upper()}] {match.group()}")
    for pattern in CLOUD_PATTERNS:
        cloud_matches = re.finditer(pattern, content)
        for match in cloud_matches:
            found = True
            print(f"  [FOUND CLOUD STORAGE] {match.group()}")
    words = re.findall(r'[\"\']([a-zA-Z0-9\-_/+=]{16,})[\"\']', content)
    for word in words:
        if calculate_entropy(word) > 4.5:
            found = True
            print(f"  [HIGH ENTROPY SECRET] '{word}' (Entropy: {calculate_entropy(word):.2f})")
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
        potential_paths = re.findall(rf"[\"']([a-zA-Z0-9\-_./]+\.{EXT_REGEX_STR})[\"']", text_content, re.IGNORECASE)
        for p in potential_paths:
            full_url = urljoin(target_url, p)
            target_files.add(full_url)

        def crawl_recursive(file_url, depth=1):
            if depth > 2:
                return
            try:
                res = requests.get(file_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, verify=False)
                if res.status_code == 200:
                    sub_matches = re.findall(rf"[\"']([a-zA-Z0-9\-_./]+\.{EXT_REGEX_STR})[\"']", res.text,
                                             re.IGNORECASE)
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
            res = requests.get(target_file, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10, verify=False)
            if res.status_code == 200:
                if target_file.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico')):
                    scan_binary_content(res.content, target_file)
                else:
                    scan_content(res.text, target_file)
                if target_file.endswith('.js'):
                    analyze_javascript(target_file)
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
            res = requests.get(file_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, verify=False)
            total_checked += 1
            if res.status_code == 200:
                lines = res.text.splitlines()
                found_matches = []
                for line_num, line in enumerate(lines, 1):
                    line_lower = line.lower()
                    found_keywords = []
                    for kw in custom_keywords:
                        if kw.lower() in line_lower:
                            found_keywords.append(kw)
                    if found_keywords:
                        clean_line = line.strip()[:100]
                        if len(line.strip()) > 100:
                            clean_line += "..."
                        match_info = {
                            'keywords': found_keywords,
                            'line_number': line_num,
                            'content': clean_line
                        }
                        found_matches.append(match_info)
                        print(f"  [FOUND] {file_url} -> Line {line_num}: {clean_line}")
                        print(f"    Keywords: {', '.join(found_keywords)}")
                if found_matches:
                    results[file_url] = found_matches
            else:
                print(f"  [!] Could not fetch: {file_url} (Status: {res.status_code})")
        except Exception as e:
            print(f"  [-] Error processing {file_url}: {e}")
    print(f"\n[+] Scanned {total_checked} files, found matches in {len(results)} files.")
    if not results:
        print("[-] No matches found.")
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
                res = requests.get(f_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10, verify=False)
                if res.status_code == 200:
                    findings = []
                    print(f"\n[!] Scanning: {f_url}")
                    keyword_pattern = re.compile('|'.join(KEYWORDS), re.IGNORECASE)
                    for match in re.finditer(keyword_pattern, res.text):
                        start = max(0, match.start() - 30)
                        end = min(len(res.text), match.end() + 30)
                        print(f"  [FOUND KEYWORD] '{match.group()}' at: ...{res.text[start:end]}...")
                        findings.append(f"keyword: {match.group()}")
                    for pattern_name, pattern in ADVANCED_PATTERNS.items():
                        matches = re.finditer(pattern, res.text, re.IGNORECASE | re.MULTILINE)
                        for match in matches:
                            print(f"  [FOUND {pattern_name.upper()}] {match.group()}")
                            findings.append(f"{pattern_name}: {match.group()}")
                    if f_url.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico')):
                        scan_binary_content(res.content, f_url)
                    if f_url.endswith('.js'):
                        js_results = analyze_javascript(f_url)
                        if js_results:
                            findings.append(f"JS analysis: {len(js_results['functions'])} functions")
                    return f_url, findings
                else:
                    if attempt < retries - 1:
                        print(f"  [!] Retry {attempt+1}/{retries} for {f_url}")
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
    return results


def show_paths(target_url, file_list):
    print(f"\n[+] Extracting internal endpoints from index page and target files...")
    unique_full_paths = set()
    parsed_base = urlparse(target_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    try:
        index_res = requests.get(target_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, verify=False)
        if index_res.status_code == 200:
            index_matches = re.finditer(PATH_PATTERN, index_res.text)
            for match in index_matches:
                raw_path = match.group().strip('"\'')
                if "//" in raw_path or raw_path == "/":
                    continue
                full_path = urljoin(base_origin, raw_path)
                unique_full_paths.add(full_path)
    except Exception:
        pass

    def extract_paths(f_url):
        local_paths = set()
        try:
            res = requests.get(f_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, verify=False)
            if res.status_code == 200:
                path_matches = re.finditer(PATH_PATTERN, res.text)
                for match in path_matches:
                    raw_path = match.group().strip('"\'')
                    if "//" in raw_path or raw_path == "/":
                        continue
                    full_path = urljoin(base_origin, raw_path)
                    local_paths.add(full_path)
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
                response = requests.head(path, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, allow_redirects=True, verify=False)
                status_code = response.status_code
                if status_code == 405 or status_code == 403:
                    response = requests.get(path, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, stream=True, verify=False)
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
    else:
        print("  [+] No valid paths found.")


if __name__ == "__main__":
    clear_screen()
    print_banner()
    url = input("Enter target URL : ")
    target_files = get_target_files(url)
    if target_files:
        while True:
            print("\n----------- Options -----------")
            print("[1] Analyze a single file")
            print("[2] Analyze all files (Optimized)")
            print("[3] Advanced custom search")
            print("[4] Endpoint extraction")
            print("[5] Save to txt file")
            print("[6] Exit")
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
                save_to_file(target_files)
            elif choice == '6':
                print("[>] Good luck, Hunter.")
                break
            else:
                print("[-] Invalid choice.")

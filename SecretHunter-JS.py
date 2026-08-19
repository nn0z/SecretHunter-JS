#SecretHunter-JS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import re
import math
from concurrent.futures import ThreadPoolExecutor, as_completed

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

PATH_PATTERN = r"[\"']\/(?:[a-zA-Z0-9\-_./]+)[\"']"
CLOUD_PATTERNS = [
    r"[a-zA-Z0-9\-_.]+\.s3\.amazonaws\.com",
    r"[a-zA-Z0-9\-_.]+\.blob\.core\.windows\.net",
    r"storage\.googleapis\.com\/[a-zA-Z0-9\-_.]+"
]

TARGET_EXTENSIONS = ('.js', '.php', '.json', '.xml', '.config', '.yml', '.yaml', '.asp', '.aspx', '.jsp', '.env',
                     '.sql', '.log', '.bak', '.properties', '.ini', '.conf')
EXT_REGEX_STR = r"(?:js|php|json|xml|config|yml|yaml|asp|aspx|jsp|env|sql|log|bak|properties|ini|conf)"


def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def scan_content(content, file_url):
    print(f"\n[!] Scanning: {file_url}")
    found = False

    keyword_pattern = re.compile('|'.join(KEYWORDS), re.IGNORECASE)
    for match in re.finditer(keyword_pattern, content):
        found = True
        start = max(0, match.start() - 30)
        end = min(len(content), match.end() + 30)
        print(f"  [FOUND KEYWORD] '{match.group()}' at: ...{content[start:end]}...")

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
        response = requests.get(target_url, headers=headers, timeout=10)

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
                res = requests.get(file_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
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
            res = requests.get(target_file, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if res.status_code == 200:
                scan_content(res.text, target_file)
            else:
                print(f"[-] Failed to fetch file. Status code: {res.status_code}")
        else:
            print("[-] Invalid selection.")
    except Exception as e:
        print(f"[-] Error: {e}")


def analyze_all_files(file_list):
    if not file_list:
        print("[-] No target files available.")
        return
    print(f"\n[+] Starting deep scan for {len(file_list)} files...")

    def fetch_and_scan(f_url):
        try:
            res = requests.get(f_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
            if res.status_code == 200:
                scan_content(res.text, f_url)
        except Exception:
            print(f"[-] Could not fetch {f_url}")

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(fetch_and_scan, file_list)

    print("[+] Batch scan completed.")


def show_paths(target_url, file_list):
    print(f"\n[+] Extracting internal endpoints from index page and target files...")
    unique_full_paths = set()
    parsed_base = urlparse(target_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    try:
        index_res = requests.get(target_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
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
            res = requests.get(f_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
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
                response = requests.head(path, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, allow_redirects=True)
                status_code = response.status_code
                if status_code == 405 or status_code == 403:
                    response = requests.get(path, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, stream=True)
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
    print("========================================")
    print("             SecretHunter-JS            ")
    print("    Advanced Recon for Sensitive Files  ")
    print("========================================")
    url = input("Enter target URL :")
    target_files = get_target_files(url)

    if target_files:
        while True:
            print("\n----------- Options -----------")
            print("[1] Analyze a single file")
            print("[2] Analyze all files")
            print("[3] Endpoint extraction")
            print("[4] Save to txt file")
            print("[5] Exit")

            choice = input("Choose an option :").strip()

            if choice == '1':
                analyze_single_file(target_files)
            elif choice == '2':
                analyze_all_files(target_files)
            elif choice == '3':
                show_paths(url, target_files)
            elif choice == '4':
                save_to_file(target_files)
            elif choice == '5':
                print("[>] Good luck, Hunter.")
                break
            else:
                print("[-] Invalid choice.")

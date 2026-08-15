#SecretHunter-JS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import re

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


def scan_content(content, js_url):
    print(f"\n[!] Scanning: {js_url}")
    found = False

    keyword_pattern = re.compile('|'.join(KEYWORDS), re.IGNORECASE)
    for match in re.finditer(keyword_pattern, content):
        found = True
        start = max(0, match.start() - 30)
        end = min(len(content), match.end() + 30)
        print(f"  [FOUND KEYWORD] '{match.group()}' at: ...{content[start:end]}...")

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


def get_js_files(target_url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(target_url, headers=headers, timeout=10)

        if response.status_code != 200:
            print(f"[-] Failed to connect. Status code: {response.status_code}")
            return []

        soup = BeautifulSoup(response.text, 'html.parser')
        js_files = set()

        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                full_url = urljoin(target_url, src)
                js_files.add(full_url)

        js_list = list(js_files)
        print(f"\n[+] Found {len(js_list)} JavaScript files:\n")
        for i, js in enumerate(js_list, 1):
            print(f"[{i}] {js}")

        return js_list

    except Exception as e:
        print(f"[-] An error occurred: {e}")
        return []


def save_to_file(js_list):
    if not js_list:
        print("[-] No JavaScript files to save.")
        return
    filename = input("Enter filename: ").strip()
    if not filename:
        print("[-] Filename cannot be empty.")
        return
    try:
        new_data = "\n".join(js_list)
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


def analyze_single_file(js_list):
    if not js_list:
        print("[-] No JavaScript files available.")
        return
    try:
        choice = int(input("Enter the number of the file: "))
        if 1 <= choice <= len(js_list):
            target_js = js_list[choice - 1]
            print(f"\n[+] Fetching: {target_js}")
            res = requests.get(target_js, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if res.status_code == 200:
                scan_content(res.text, target_js)
            else:
                print(f"[-] Failed to fetch file. Status code: {res.status_code}")
        else:
            print("[-] Invalid selection.")
    except Exception as e:
        print(f"[-] Error: {e}")


def analyze_all_files(js_list):
    if not js_list:
        print("[-] No JavaScript files available.")
        return
    print(f"\n[+] Starting deep scan for {len(js_list)} files...")
    for js in js_list:
        try:
            res = requests.get(js, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
            if res.status_code == 200:
                scan_content(res.text, js)
        except Exception:
            print(f"[-] Could not fetch {js}")
    print("[+] Batch scan completed.")


def show_paths(target_url, js_list):
    if not js_list:
        print("[-] No JavaScript files available.")
        return
    print(f"\n[+] Extracting, resolving, and checking status codes from {len(js_list)} files...")
    unique_full_paths = set()
    parsed_base = urlparse(target_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    for js in js_list:
        try:
            res = requests.get(js, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
            if res.status_code == 200:
                path_matches = re.finditer(PATH_PATTERN, res.text)
                for match in path_matches:
                    raw_path = match.group().strip('"\'')
                    if "//" in raw_path or raw_path == "/":
                        continue
                    full_path = urljoin(base_origin, raw_path)
                    unique_full_paths.add(full_path)
        except Exception:
            pass

    if unique_full_paths:
        print(f"\n[+] Found {len(unique_full_paths)} unique resolved paths:\n")
        for path in sorted(unique_full_paths):
            try:
                response = requests.head(path, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, allow_redirects=True)
                status_code = response.status_code
            except Exception:
                try:
                    response = requests.get(path, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
                    status_code = response.status_code
                except Exception:
                    status_code = "ERR"

            print(f"[{status_code}] {path}")
    else:
        print("  [+] No valid paths found.")


if __name__ == "__main__":
    print("========================================")
    print("             SecretHunter-JS            ")
    print("      Deep Recon for JS Vulnerability   ")
    print("========================================")
    url = input("Enter target URL : ")
    js_files = get_js_files(url)

    if js_files:
        while True:
            print("\n----------- Options -----------")
            print("[1] Analyze a single file")
            print("[2] Analyze all files")
            print("[3] Endpoint extraction")
            print("[4] Save to txt file")
            print("[5] Exit")

            choice = input("Choose an option :").strip()

            if choice == '1':
                analyze_single_file(js_files)
            elif choice == '2':
                analyze_all_files(js_files)
            elif choice == '3':
                show_paths(url, js_files)
            elif choice == '4':
                save_to_file(js_files)
            elif choice == '5':
                print("[>] Good luck, Hunter.")
                break
            else:
                print("[-] Invalid choice.")

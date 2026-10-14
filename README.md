# SecretHunter-JS

A Python security reconnaissance tool to discover JavaScript files, sensitive secrets, and API endpoints in web applications.

---

## 🚀 New Features & Updates (v3.1)

* **Obfuscation Decoder:** Automatically decodes Base64, Hex, Unicode, and URL-encoded payloads to uncover hidden secrets.
* **Live Secret Validation:** Validates discovered API keys against real APIs (GitHub, Slack, OpenAI, Stripe, Google, npm, DigitalOcean, HuggingFace, Mapbox, Replicate) to distinguish real leaks from false positives.
* **Context-Aware Patterns:** Regex patterns require context (e.g. `api_key = "..."`) instead of matching bare strings — drastically reducing false positives.
* **Extended Secret Coverage:** Added patterns for AWS Secret Keys, Facebook tokens, Google OAuth client IDs, SSH private keys, `postMessage` wildcards, `localStorage`/`sessionStorage` secrets, and `document.cookie` assignments.
* **Security Headers Audit:** Automatically checks `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), and `X-Frame-Options` for weaknesses.
* **Source Map Recovery:** When a `.map` file is missing (404), the tool tries common source directories to recover original code.
* **Full Webpack Chunk Scanning:** Discovered webpack chunks are now fully fetched and scanned instead of just listed as endpoints.
* **Smart False-Positive Filter:** Filters dictionary words, date strings, asset extensions, and known placeholder values.
* **Content Hash Cache:** Prevents re-scanning identical content across runs — faster and lighter on targets.
* **Download Size Guard:** Refuses to fetch responses larger than 5MB to avoid memory exhaustion.
* **Redirect-Aware Discovery:** `check_common_paths` now follows redirects and adds final URLs to the findings.
* **Live HTML Reports:** Every scan is saved as a browsable, self-contained HTML report — no external server or JSON needed.
* **Per-Target Reports:** Each target gets its own file named after the site (e.g. `results/test/test.html`).
* **Merged Runs:** Running the tool twice on the same target merges both runs into one file with a built-in table of contents.
* **Smart Site Key Extraction:** Automatically ignores common subdomains (`www`, `main`, `api`, `app`, `admin`, ...) to extract the real site name.
* **Clickable Findings:** All discovered files, endpoints, and paths are rendered as live, clickable links in the HTML report.
* **Binary File Scan:** Inspect images and binary files to extract hidden texts and search for sensitive keywords.
* **Advanced JavaScript Deep Analysis:** Parse JS files to extract endpoints, functions, variables, and high entropy strings/tokens.
* **Optimized Multi-threaded Batch Scanning:** Fast concurrent scanning using `ThreadPoolExecutor` (up to 15 workers) with automatic retries.
* **Advanced Custom Search:** Search for custom multi-keywords across all targeted files with precise line numbers and snippet tracking.
* **Enhanced Endpoint & Path Extraction:** Extract internal paths and verify live HTTP status codes.
* **Persistent Results Saving:** Export and append discovered target files and findings cleanly to text files.

---

## 🛠️ Features Overview

* **JavaScript & Asset Discovery:** Locate and crawl JS, PHP, JSON, Config, and backup files from target web apps.
* **Secret & Pattern Scanner:** Scan files for exposed API keys, credentials, tokens, cloud storage buckets, and regex-based patterns (AWS, GitHub, JWT, Slack, Database URIs, Firebase, Supabase, Stripe, Twilio, Heroku, npm, HuggingFace, DigitalOcean, Mapbox, and more).
* **Obfuscated Code Analysis:** Decode Base64, Hex, Unicode, and URL-encoded strings embedded in JavaScript.
* **Live API Validation:** Confirm leaked secrets are still active by testing them against their provider's API.
* **Entropy Analysis:** Calculate Shannon entropy to detect hidden high-entropy random strings or hardcoded secrets.
* **Security Header Audit:** Detect weak CSP, missing HSTS, and missing `X-Frame-Options`.
* **Vulnerable Library Detection:** Identify outdated versions of jQuery, Lodash, Angular, and Bootstrap with known CVEs.
* **CORS Misconfiguration Check:** Detect wildcard-with-credentials and reflected-origin CORS issues.
* **GraphQL Introspection Test:** Check if GraphQL endpoints expose their full schema.
* **JWT Analyzer:** Detects `alg=none`, HMAC algorithms, and sensitive claims inside decoded tokens.
* **Firebase Exposure Check:** Detects publicly readable Firebase Realtime Databases.
* **Source Map Parser:** Extracts and scans original source code from exposed `.map` files.
* **Lightweight & Fast:** Built with clean, minimalist, and efficient Python code.

---
## Prerequisites
Ensure you have Python installed on your system. The tool requires the following Python libraries:
* `requests`
* `beautifulsoup4`
* `urllib3`

**Optional but recommended:**
* `jsbeautifier` — for better JavaScript formatting (falls back to internal formatter if missing)

## Disclaimer
This tool is created for educational purposes, authorized security assessments, and Bug Bounty programs only.
The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
Use responsibly and only on targets you have explicit permission to test.

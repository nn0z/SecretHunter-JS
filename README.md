# SecretHunter-JS

A Python security reconnaissance tool to discover JavaScript files, sensitive secrets, and API endpoints in web applications.

---

## 🚀 New Features & Updates (v3.0)

* **Live HTML Reports:** Every scan is saved as a browsable, self-contained HTML report — no external server or JSON needed.
* **Per-Target Reports:** Each target gets its own file named after the site (e.g. `results/test/test.html`).
* **Merged Runs:** Running the tool twice on the same target merges both runs into one file (`Run 1`, `Run 2`, ...) with a built-in table of contents.
* **Smart Site Key Extraction:** Automatically ignores common subdomains (`www`, `main`, `api`, `app`, `admin`, ...) to extract the real site name.
* **Clickable Findings:** All discovered files, endpoints, and paths are rendered as live, clickable links in the HTML report.
* **Binary File Scan:** Inspect images and binary files (`.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`) to extract hidden texts and search for sensitive keywords.
* **Advanced JavaScript Deep Analysis:** Parse JS files to extract endpoints, functions, variables, and high entropy strings/tokens.
* **Optimized Multi-threaded Batch Scanning:** Fast concurrent scanning using `ThreadPoolExecutor` (up to 15 workers) with automatic retries.
* **Advanced Custom Search:** Search for custom multi-keywords across all targeted files with precise line numbers and snippet tracking.
* **Enhanced Endpoint & Path Extraction:** Extract internal paths and verify live HTTP status codes (`200`, `302`, `403`, `404`, etc.).
* **Persistent Results Saving:** Export and append discovered target files and findings cleanly to text files.

---

## 🛠️ Features Overview

* **JavaScript & Asset Discovery:** Locate and crawl JS, PHP, JSON, Config, and backup files from target web apps.
* **Secret & Pattern Scanner:** Scan files for exposed API keys, credentials, tokens, cloud storage buckets, and regex-based patterns (AWS, GitHub, JWT, Slack, Database URIs, etc.).
* **Entropy Analysis:** Calculate Shannon entropy to detect hidden high-entropy random strings or hardcoded secrets.
* **Lightweight & Fast:** Built with clean, minimalist, and efficient Python code.

---
## Prerequisites
Ensure you have Python installed on your system. The tool requires the following Python libraries:
* `requests`
* `beautifulsoup4`
* `urllib3`


## Disclaimer
This tool is created for educational purposes, authorized security assessments, and Bug Bounty programs only.
The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
Use responsibly and only on targets you have explicit permission to test.

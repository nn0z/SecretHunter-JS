## SecretHunter-JS
A Python security reconnaissance tool to discover JavaScript files, sensitive secrets, and API endpoints in web applications.


## 🚀 New Features & Updates (v2.0)
* **Binary File Scan:** Inspect images and binary files (`.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.ico`) to extract hidden texts and search for sensitive keywords.
* **Advanced JavaScript Deep Analysis:** Parse JS files to extract Endpoints, Functions, Variables, and High Entropy Strings/Tokens.
* **Optimized Multi-threaded Batch Scanning:** Fast concurrent scanning using `ThreadPoolExecutor` (up to 15 workers) equipped with automatic retries for robust performance.
* **Advanced Custom Search:** Search for custom multi-keywords across all targeted files with precise line numbers and snippet tracking.
* **Enhanced Endpoint & Path Extraction:** Extract internal paths and verify live HTTP status codes (`200`, `302`, `403`, `404`, etc.) with colored terminal outputs.
* **Persistent Results Saving:** Export and append discovered target files and findings cleanly to text files.

---

## 🛠️ Features Overview
* **JavaScript & Asset Discovery:** Locate and crawl JS, PHP, JSON, Config, and backup files from target web apps.
* **Secret & Pattern Scanner:** Scan files for exposed API keys, credentials, tokens, cloud storage buckets, and regex-based patterns (AWS, GitHub, JWT, Slack, Database URIs, etc.).
* **Entropy Analysis:** Calculate Shannon entropy to detect hidden high-entropy random strings or hardcoded secrets.
* **Lightweight & Fast:** Built with clean, minimalist, and efficient Python code.

## Prerequisites
Ensure you have Python installed on your system. The tool requires the following Python libraries:
* `requests`
* `beautifulsoup4`
* `urllib3`


## Disclaimer
This tool is created for educational purposes, authorized security assessments, and Bug Bounty programs only.
The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
Use responsibly and only on targets you have explicit permission to test.

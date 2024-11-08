
# web_scanner.py - Core Scanning Script for Web App Security Tool

import json
import requests
from bs4 import BeautifulSoup

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Example function to scan for JavaScript vulnerabilities
def scan_javascript_security(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Check for inline scripts and CSP headers
        scripts = soup.find_all("script")
        if scripts:
            print(f"[INFO] JavaScript elements found on {url}: {len(scripts)} scripts detected.")
        else:
            print(f"[INFO] No JavaScript elements detected on {url}.")
        
        # Content Security Policy (CSP) evaluation
        if config["javascript_security"]["csp_evaluation"]:
            csp = response.headers.get("Content-Security-Policy", None)
            if csp:
                print(f"[INFO] CSP found on {url}: {csp}")
            else:
                print(f"[WARNING] No Content-Security-Policy header found on {url}.")

    except Exception as e:
        print(f"[ERROR] Failed to scan JavaScript security on {url}: {e}")

# Example function to perform input validation checks
def scan_input_validation(url):
    for check_type, enabled in config["input_validation_checks"].items():
        if enabled:
            # Placeholder: Implement actual injection testing per vulnerability type
            print(f"[INFO] Performing {check_type} check on {url}")

# Example function to perform API security tests
def scan_api_security(endpoint):
    if config["api_security"]["auth_validation"]:
        print(f"[INFO] Checking authentication on API endpoint: {endpoint}")
    if config["api_security"]["rate_limiting"]:
        print(f"[INFO] Checking rate limiting on API endpoint: {endpoint}")

# Run all scans
def run_web_security_scans():
    for url in config["target_urls"]:
        print(f"[INFO] Starting scan for {url}")
        scan_javascript_security(url)
        scan_input_validation(url)

    for endpoint in config["api_endpoints"]:
        scan_api_security(endpoint)

if __name__ == "__main__":
    print("[INFO] Starting web application security scans...")
    run_web_security_scans()

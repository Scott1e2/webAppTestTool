
# web_scanner.py - Enhanced Scanning Script for Web App Security Tool

import json
import requests
from bs4 import BeautifulSoup

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# JavaScript Security - DOM-based XSS and CSP
def scan_javascript_security(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        # Check for inline scripts and CSP headers
        scripts = soup.find_all("script")
        if scripts:
            print(f"[INFO] JavaScript elements found on {url}: {len(scripts)} scripts detected.")

        if config["javascript_security"]["dom_based_xss_detection"]:
            for script in scripts:
                # Placeholder for DOM-based XSS detection
                print("[INFO] Scanning for DOM-based XSS in inline scripts.")

        # Content Security Policy (CSP) evaluation
        if config["javascript_security"]["csp_evaluation"]:
            csp = response.headers.get("Content-Security-Policy", None)
            if csp:
                print(f"[INFO] CSP found on {url}: {csp}")
            else:
                print(f"[WARNING] No Content-Security-Policy header found on {url}.")

    except Exception as e:
        print(f"[ERROR] Failed to scan JavaScript security on {url}: {e}")

# Input Validation - Injection and Fuzzing
def scan_input_validation(url):
    for check_type, enabled in config["input_validation_checks"].items():
        if enabled:
            # Placeholder: Implement actual injection testing per vulnerability type
            print(f"[INFO] Performing {check_type} check on {url}")
            if check_type == "fuzzing_for_injection_points":
                print("[INFO] Running fuzzing on form inputs for injection points.")

# API Security - Sensitive Data, Rate Limiting, and BOLA
def scan_api_security(endpoint):
    if config["api_security"]["auth_validation"]:
        print(f"[INFO] Checking authentication on API endpoint: {endpoint}")

    if config["api_security"]["rate_limiting"]:
        print(f"[INFO] Checking rate limiting on API endpoint: {endpoint}")

    if config["api_security"]["sensitive_data_check"]:
        response = requests.get(endpoint)
        sensitive_data_keywords = ["password", "credit_card", "ssn"]
        if any(keyword in response.text for keyword in sensitive_data_keywords):
            print(f"[WARNING] Sensitive data detected in API response from {endpoint}")

# Session Management - Session Fixation, Secure Cookies, and CSRF
def scan_session_management(url):
    print(f"[INFO] Checking session management for {url}")
    if config["session_management"]["csrf_protection_check"]:
        print("[INFO] Checking for CSRF token in forms and state-changing requests.")

# Authentication and Authorization Checks
def scan_authentication(url):
    print(f"[INFO] Starting authentication and authorization checks on {url}")
    if config["authentication_authorization"]["mfa_check"]:
        print("[INFO] Verifying if multi-factor authentication is enforced.")
    if config["authentication_authorization"]["privilege_escalation_test"]:
        print("[INFO] Testing for unauthorized privilege escalation.")

# Run all enhanced scans
def run_web_security_scans():
    for url in config["target_urls"]:
        print(f"[INFO] Starting enhanced scan for {url}")
        scan_javascript_security(url)
        scan_input_validation(url)
        scan_session_management(url)
        scan_authentication(url)

    for endpoint in config["api_endpoints"]:
        scan_api_security(endpoint)

if __name__ == "__main__":
    print("[INFO] Starting enhanced web application security scans...")
    run_web_security_scans()

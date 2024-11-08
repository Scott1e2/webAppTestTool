# webAppTestTool
trying to put my Sec522 training into practice



#Functionality of the Web App Security Testing Tool

## Overview
This tool is designed to comprehensively test web applications for security vulnerabilities, focusing on JavaScript-based security issues, input validation, API security, session management, and compliance with OWASP Top 10 and CWE standards.

## Features
- **JavaScript Vulnerability Scanning**: Detects DOM-based XSS, insecure JavaScript libraries, and evaluates Content Security Policy (CSP) headers.
- **Input Validation Checks**: Tests for SQL Injection, XSS, Command Injection, and other vulnerabilities using automated fuzzing techniques.
- **API Security Testing**: Inspects API endpoints for Broken Object Level Authorization (BOLA), rate limiting, authentication issues, and sensitive data exposure.
- **Session and Authentication Security**: Verifies secure cookie attributes, CSRF token presence, session timeout policies, and MFA enforcement.
- **Compliance Mapping**: Maps findings to OWASP Top 10 and CWE standards, providing prioritized remediation guidance.

## Requirements
- **Python 3.8+**
- Install dependencies using `requirements.txt`:
    ```bash
    pip install -r requirements.txt
    ```

## Installation
1. **Clone the Repository**:
    ```bash
    git clone https://github.com/your-repository/web-app-security-testing-tool.git
    cd web-app-security-testing-tool
    ```

2. **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Configure Settings**:
    - Open `config.json` to set target URLs, API endpoints, enable specific security checks, and set alert thresholds.

## Usage
1. **Run Web Security Scans**:
    ```bash
    python web_scanner.py
    ```
   - The script will perform scans for JavaScript security, input validation, API security, and session management on specified URLs.

2. **Generate Vulnerability Report**:
    ```bash
    python report_generator.py
    ```
   - Generates a report with risk scores, OWASP Top 10 and CWE compliance mappings, and remediation guidance in `web_security_report.txt` (plaintext) and `web_security_report.json` (JSON).

## Configuration
- **config.json**: Stores configuration for target URLs, API endpoints, security checks, compliance mappings, and alert thresholds.
    - **target_urls**: List of URLs for JavaScript and input validation testing.
    - **api_endpoints**: List of API endpoints for testing.
    - **javascript_security**: Settings for CSP, DOM-based XSS detection, and library security checks.
    - **session_management**: Enables checks for secure cookies, CSRF tokens, and session timeout policies.
    - **authentication_authorization**: Enables MFA checks, privilege escalation tests, and session hijacking prevention.
    - **continuous_monitoring**: Schedule recurring scans, enable real-time anomaly detection, and integration with alerting tools.

## Advanced Features
1. **Compliance Mapping with OWASP and CWE Standards**:
   - Each vulnerability includes mappings to OWASP Top 10 categories and CWE identifiers for compliance purposes.

2. **Prioritized Risk Scoring**:
   - Vulnerabilities are scored based on severity and exploitability, with critical issues prioritized for immediate remediation.

3. **Real-Time Anomaly Detection and Alerts**:
   - Allows scheduling scans, anomaly detection, and integration with alerts (e.g., Slack, email) for real-time notifications.

## Example Configuration and Sample Output
- **config.json** (Example):
    ```json
    {
        "target_urls": ["https://example.com"],
        "api_endpoints": ["https://example.com/api/v1/users"],
        "javascript_security": {
            "scan_for_xss": true,
            "scan_for_insecure_libraries": true,
            "csp_evaluation": true
        },
        "input_validation_checks": {
            "sql_injection": true,
            "xss": true,
            "command_injection": true
        },
        "session_management": {
            "csrf_protection_check": true,
            "secure_cookies": true
        }
    }
    ```

- **Sample Output (web_security_report.txt)**:
    ```
    Web Application Security Report
    ===============================
    Total Vulnerabilities: 3
    Total Risk Score: 22

    Description: SQL Injection vulnerability detected in login form.
    Severity: Critical
    Risk Score: 30
    OWASP Compliance: A1 - Injection
    CWE Compliance: CWE-89 - SQL Injection
    Recommendation: Use parameterized queries to prevent SQL Injection.
    ```

## License
This project is licensed under the MIT License.

## Support
For issues or support, please open an issue on the GitHub repository.

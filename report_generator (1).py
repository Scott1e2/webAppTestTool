
# report_generator.py - Enhanced Vulnerability Reporting and Compliance Mapping for Web App Security Tool

import json

# Define scoring criteria for vulnerabilities and expanded compliance mappings
SEVERITY_SCORES = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 2,
}
COMPLIANCE_MAPPING = {
    "sql_injection": {
        "owasp": "OWASP A1: Injection",
        "cwe": "CWE-89: SQL Injection"
    },
    "xss": {
        "owasp": "OWASP A7: Cross-Site Scripting (XSS)",
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
    },
    "csrf": {
        "owasp": "OWASP A8: Cross-Site Request Forgery (CSRF)",
        "cwe": "CWE-352: Cross-Site Request Forgery (CSRF)"
    },
    "auth_bypass": {
        "owasp": "OWASP A2: Broken Authentication",
        "cwe": "CWE-287: Improper Authentication"
    },
    "csp_missing": {
        "owasp": "OWASP A6: Security Misconfiguration",
        "cwe": "CWE-16: Configuration"
    }
}

# Calculate risk score based on severity and exploitability
def calculate_risk_score(vulnerabilities):
    total_score = 0
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low")
        exploitability = vuln.get("exploitability", 1)
        score = SEVERITY_SCORES.get(severity, 2) * exploitability
        vuln["risk_score"] = score
        vuln["compliance_mapping"] = COMPLIANCE_MAPPING.get(vuln.get("type"), {"owasp": "Unknown", "cwe": "Unknown"})
        total_score += score
    return total_score

# Generate report with risk scores, compliance mappings, and remediation guidance
def generate_report(vulnerabilities, output_format="text"):
    report_data = {
        "total_vulnerabilities": len(vulnerabilities),
        "total_risk_score": calculate_risk_score(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }
    
    if output_format == "text":
        with open("web_security_report.txt", "w") as report_file:
            report_file.write("Web Application Security Report\n")
            report_file.write("===============================\n")
            report_file.write(f"Total Vulnerabilities: {report_data['total_vulnerabilities']}\n")
            report_file.write(f"Total Risk Score: {report_data['total_risk_score']}\n\n")
            
            for vuln in vulnerabilities:
                report_file.write(f"Description: {vuln['description']}\n")
                report_file.write(f"Severity: {vuln['severity']}\n")
                report_file.write(f"Risk Score: {vuln['risk_score']}\n")
                report_file.write(f"OWASP Compliance: {vuln['compliance_mapping']['owasp']}\n")
                report_file.write(f"CWE Compliance: {vuln['compliance_mapping']['cwe']}\n")
                report_file.write(f"Recommendation: {vuln['remediation']}\n\n")
    
    elif output_format == "json":
        with open("web_security_report.json", "w") as report_file:
            json.dump(report_data, report_file, indent=4)

# Example vulnerability data for testing
vulnerabilities = [
    {
        "description": "SQL Injection vulnerability detected in login form.",
        "severity": "critical",
        "exploitability": 3,
        "type": "sql_injection",
        "remediation": "Use parameterized queries to prevent SQL Injection."
    },
    {
        "description": "No CSP header found, making application susceptible to XSS.",
        "severity": "medium",
        "exploitability": 2,
        "type": "csp_missing",
        "remediation": "Implement a strong Content Security Policy header."
    }
]

# Generate example report
if __name__ == "__main__":
    generate_report(vulnerabilities, output_format="text")
    generate_report(vulnerabilities, output_format="json")

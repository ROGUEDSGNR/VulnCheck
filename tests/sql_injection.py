# tests/sql_injection.py

import requests
from tests.firewall_detection import check_for_firewall

def test_sql_injection(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    url = f"https://{domain}"
    payload = "' OR '1'='1"
    params = {'id': payload}  # Adjust parameter

    try:
        response = requests.get(url, params=params, timeout=5)

        # Check for firewall detection
        firewall_detected, firewall_details = check_for_firewall(response)
        if firewall_detected:
            result['status'] = False
            result['details'] = f"Test blocked by firewall. {firewall_details}"
            result['remediation'] = "Adjust firewall rules or whitelist this tool during testing."
            return result

        if "error" in response.text.lower() or "syntax" in response.text.lower():
            result['status'] = False
            result['details'] = "Potential SQL Injection vulnerability detected."
            result['remediation'] = "Use parameterized queries or prepared statements to prevent SQL injection."
        else:
            result['details'] = "No SQL injection vulnerabilities detected."

    except Exception as e:
        result['status'] = False
        result['details'] = f"SQL Injection test failed: {str(e)}"
        result['remediation'] = "Ensure proper error handling and input sanitization."

    return result

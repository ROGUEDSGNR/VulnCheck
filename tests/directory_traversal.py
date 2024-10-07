# tests/directory_traversal.py

import requests
from tests.firewall_detection import check_for_firewall

def test_directory_traversal(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    url = f"https://{domain}"

    payloads = [
        '../etc/passwd',
        '../../etc/passwd',
        '../../../etc/passwd',
        '..././..././..././etc/passwd',
    ]

    try:
        for payload in payloads:
            params = {'file': payload}
            response = requests.get(url, params=params, timeout=5)

            # Check for firewall detection
            firewall_detected, firewall_details = check_for_firewall(response)
            if firewall_detected:
                result['status'] = False
                result['details'] = f"Test blocked by firewall. {firewall_details}"
                result['remediation'] = "Ensure that your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
                return result

            if 'root:x:' in response.text:
                result['status'] = False
                result['details'] = f"Directory traversal vulnerability detected with payload: {payload}"
                result['remediation'] = "Validate and sanitize user inputs to prevent directory traversal attacks."
                return result

        result['details'] = "No directory traversal vulnerabilities detected."

    except Exception as e:
        result['status'] = False
        result['details'] = f"Directory traversal test failed: {str(e)}"
        result['remediation'] = "Ensure proper input validation in your application."

    return result

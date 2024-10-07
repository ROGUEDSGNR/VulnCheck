# tests/sensitive_data_exposure.py

import requests
from tests.firewall_detection import check_for_firewall

def check_sensitive_data_exposure(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    http_url = f"http://{domain}"
    https_url = f"https://{domain}"

    try:
        http_response = requests.get(http_url, timeout=5)

        # Check for firewall detection
        firewall_detected, firewall_details = check_for_firewall(http_response)
        if firewall_detected:
            result['status'] = False
            result['details'] = f"Test blocked by firewall. {firewall_details}"
            result['remediation'] = "Ensure that your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
            return result

        if http_response.history and http_response.url == https_url:
            pass  # Redirected to HTTPS
        else:
            result['status'] = False
            result['details'] = "Website accessible over HTTP. SSL/TLS not enforced."
            result['remediation'] = "Enforce HTTPS by redirecting all HTTP traffic to HTTPS."

        response = requests.get(https_url, timeout=5)
        sensitive_patterns = ['SSN', 'Credit Card Number', 'Password']

        for pattern in sensitive_patterns:
            if pattern.lower() in response.text.lower():
                result['status'] = False
                result['details'] = f"Sensitive data '{pattern}' found in response."
                result['remediation'] = "Ensure that sensitive data is not exposed in responses."
                return result

        result['details'] = "No sensitive data exposure detected."

    except Exception as e:
        result['status'] = False
        result['details'] = f"Sensitive data exposure check failed: {str(e)}"
        result['remediation'] = "Ensure proper data handling and encryption in your application."

    return result

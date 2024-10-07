# tests/xss.py

import requests
from tests.firewall_detection import check_for_firewall

def test_xss(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    url = f"https://{domain}"

    payload = "<script>alert('XSS')</script>"
    params = {'q': payload}  # Adjust the parameter based on your application

    try:
        response = requests.get(url, params=params, timeout=5)

        # Check for firewall detection
        firewall_detected, firewall_details = check_for_firewall(response)
        if firewall_detected:
            result['status'] = False
            result['details'] = f"Test blocked by firewall. {firewall_details}"
            result['remediation'] = "Ensure that your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
            return result

        if payload in response.text:
            result['status'] = False
            result['details'] = "Reflected XSS vulnerability detected."
            result['remediation'] = "Implement proper input validation and output encoding to prevent XSS attacks."
        else:
            result['details'] = "No XSS vulnerabilities detected."

    except Exception as e:
        result['status'] = False
        result['details'] = f"XSS test failed: {str(e)}"
        result['remediation'] = "Review your application's input handling and ensure it is robust against XSS attacks."

    return result

# tests/unvalidated_redirects.py

import requests
from tests.firewall_detection import check_for_firewall

def test_unvalidated_redirects(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    url = f"https://{domain}/redirect"  # Adjust the endpoint accordingly

    payload = 'http://malicious.com'
    params = {'url': payload}

    try:
        response = requests.get(url, params=params, allow_redirects=False, timeout=5)

        # Check for firewall detection
        firewall_detected, firewall_details = check_for_firewall(response)
        if firewall_detected:
            result['status'] = False
            result['details'] = f"Test blocked by firewall. {firewall_details}"
            result['remediation'] = "Ensure that your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
            return result

        if response.status_code in [301, 302] and response.headers.get('Location') == payload:
            result['status'] = False
            result['details'] = "Unvalidated redirect vulnerability detected."
            result['remediation'] = "Validate and sanitize all redirect URLs to prevent unvalidated redirect attacks."
        else:
            result['details'] = "No unvalidated redirects detected."

    except Exception as e:
        result['status'] = False
        result['details'] = f"Unvalidated redirects test failed: {str(e)}"
        result['remediation'] = "Ensure that redirect URLs are validated before performing redirects."

    return result

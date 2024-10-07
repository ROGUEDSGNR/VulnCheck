# tests/clickjacking.py

import requests
from tests.firewall_detection import check_for_firewall

def test_clickjacking(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    url = f"https://{domain}"

    try:
        response = requests.get(url, timeout=5)

        # Check for firewall detection
        firewall_detected, firewall_details = check_for_firewall(response)
        if firewall_detected:
            result['status'] = False
            result['details'] = f"Test blocked by firewall. {firewall_details}"
            result['remediation'] = "Ensure that your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
            return result

        headers = response.headers

        if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
            result['status'] = False
            result['details'] = "X-Frame-Options or Content-Security-Policy headers not set to prevent framing."
            result['remediation'] = (
                "Add the 'X-Frame-Options' header with value 'DENY' or 'SAMEORIGIN', "
                "or use the 'Content-Security-Policy' header with 'frame-ancestors' directive "
                "to prevent clickjacking attacks."
            )
        else:
            result['details'] = "Clickjacking protections are in place."

    except Exception as e:
        result['status'] = False
        result['details'] = f"Clickjacking test failed: {str(e)}"
        result['remediation'] = "Ensure your server includes appropriate headers to prevent framing."

    return result

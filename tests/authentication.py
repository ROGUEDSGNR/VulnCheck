# tests/authentication.py

import requests
from tests.firewall_detection import check_for_firewall

def test_authentication(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    url = f"https://{domain}/login"  # Adjust the endpoint accordingly

    try:
        session = requests.Session()
        response = session.get(url, timeout=5)

        # Check for firewall detection
        firewall_detected, firewall_details = check_for_firewall(response)
        if firewall_detected:
            result['status'] = False
            result['details'] = f"Test blocked by firewall. {firewall_details}"
            result['remediation'] = "Ensure that your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
            return result

        cookies = response.cookies
        issues = []

        for cookie in cookies:
            if not cookie.secure:
                issues.append(f"Cookie '{cookie.name}' missing 'Secure' flag.")
            if 'httponly' not in cookie._rest.keys():
                issues.append(f"Cookie '{cookie.name}' missing 'HttpOnly' flag.")

        if issues:
            result['status'] = False
            result['details'] = '; '.join(issues)
            result['remediation'] = "Ensure that session cookies are set with 'Secure' and 'HttpOnly' flags."
        else:
            result['details'] = "Session cookies have appropriate security flags."

    except Exception as e:
        result['status'] = False
        result['details'] = f"Authentication test failed: {str(e)}"
        result['remediation'] = "Ensure that your authentication and session management mechanisms are secure."

    return result

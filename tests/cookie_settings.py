# tests/cookie_settings.py

import requests
from tests.firewall_detection import check_for_firewall

def check_cookie_settings(domain):
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

        cookies = response.cookies
        issues = []

        for cookie in cookies:
            if not cookie.secure:
                issues.append(f"Cookie '{cookie.name}' missing 'Secure' flag.")
            if 'httponly' not in cookie._rest.keys():
                issues.append(f"Cookie '{cookie.name}' missing 'HttpOnly' flag.")
            if 'samesite' not in cookie._rest.keys():
                issues.append(f"Cookie '{cookie.name}' missing 'SameSite' attribute.")

        if issues:
            result['status'] = False
            result['details'] = '; '.join(issues)
            result['remediation'] = "Ensure that cookies have appropriate security attributes ('Secure', 'HttpOnly', 'SameSite')."
        else:
            result['details'] = "All cookies have appropriate security attributes."

    except Exception as e:
        result['status'] = False
        result['details'] = f"Cookie settings check failed: {str(e)}"
        result['remediation'] = "Ensure that your application sets cookies with secure attributes."

    return result

# tests/idor.py

import requests
from tests.firewall_detection import check_for_firewall

def test_idor(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    url = f"https://{domain}/user/profile"

    try:
        # Assuming user IDs are numeric and sequential
        for user_id in range(1, 5):
            params = {'id': user_id}
            response = requests.get(url, params=params, timeout=5)

            # Check for firewall detection
            firewall_detected, firewall_details = check_for_firewall(response)
            if firewall_detected:
                result['status'] = False
                result['details'] = f"Test blocked by firewall. {firewall_details}"
                result['remediation'] = "Ensure that your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
                return result

            if response.status_code == 200 and 'Sensitive Data' in response.text:
                result['status'] = False
                result['details'] = f"IDOR vulnerability detected for user ID {user_id}"
                result['remediation'] = "Implement proper authorization checks to prevent IDOR attacks."
                return result

        result['details'] = "No IDOR vulnerabilities detected."

    except Exception as e:
        result['status'] = False
        result['details'] = f"IDOR test failed: {str(e)}"
        result['remediation'] = "Ensure that authorization checks are enforced in your application."

    return result

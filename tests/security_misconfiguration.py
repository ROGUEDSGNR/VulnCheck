# tests/security_misconfiguration.py

import requests
from tests.firewall_detection import check_for_firewall

def check_security_misconfiguration(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    issues = []

    # Example: Check for common admin pages
    admin_urls = [
        f"https://{domain}/admin/",
        f"https://{domain}/administrator/",
    ]

    try:
        for admin_url in admin_urls:
            response = requests.get(admin_url, timeout=5)

            # Check for firewall detection
            firewall_detected, firewall_details = check_for_firewall(response)
            if firewall_detected:
                result['status'] = False
                result['details'] = f"Test blocked by firewall. {firewall_details}"
                result['remediation'] = "Ensure that your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
                return result

            if response.status_code == 200:
                issues.append(f"Accessible admin page: {admin_url}")

        if issues:
            result['status'] = False
            result['details'] = '; '.join(issues)
            result['remediation'] = "Restrict access to administrative pages."
        else:
            result['details'] = "No security misconfigurations detected."

    except Exception as e:
        result['status'] = False
        result['details'] = f"Security misconfiguration check failed: {str(e)}"
        result['remediation'] = "Ensure that your server configurations follow security best practices."

    return result

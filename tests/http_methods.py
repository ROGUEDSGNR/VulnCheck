# tests/http_methods.py

import requests
from tests.firewall_detection import check_for_firewall

def check_http_methods(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    url = f"https://{domain}"

    try:
        response = requests.options(url, timeout=5)

        # Check for firewall detection
        firewall_detected, firewall_details = check_for_firewall(response)
        if firewall_detected:
            result['status'] = False
            result['details'] = f"Test blocked by firewall. {firewall_details}"
            result['remediation'] = "Ensure that your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
            return result

        allowed_methods = response.headers.get('Allow', '')

        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        enabled_dangerous_methods = [method for method in dangerous_methods if method in allowed_methods]

        if enabled_dangerous_methods:
            result['status'] = False
            result['details'] = f"Dangerous HTTP methods enabled: {', '.join(enabled_dangerous_methods)}"
            result['remediation'] = "Disable unnecessary HTTP methods on your web server."
        else:
            result['details'] = "No dangerous HTTP methods enabled."

    except Exception as e:
        result['status'] = False
        result['details'] = f"HTTP methods check failed: {str(e)}"
        result['remediation'] = "Ensure that only necessary HTTP methods are enabled on your web server."

    return result

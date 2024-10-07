# tests/headers.py

import requests
from tests.firewall_detection import check_for_firewall

def check_headers(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    url = f"https://{domain}"

    try:
        response = requests.get(url, timeout=5)

        # Check for firewall detection
        firewall_detected, firewall_details = check_for_firewall(response)
        if firewall_detected:
            result['status'] = False
            result['details'] = f"Test blocked by firewall. {firewall_details}"
            result['remediation'] = "Ensure your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
            return result

        headers = response.headers
        missing_headers = []
        security_headers = ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security', 'Referrer-Policy', 'Permissions-Policy']

        for header in security_headers:
            if header not in headers:
                missing_headers.append(header)

        if missing_headers:
            result['status'] = False
            result['details'] = f"Missing security headers: {', '.join(missing_headers)}"
            result['remediation'] = f"Add the following security headers to your HTTP responses: {', '.join(missing_headers)}."
        else:
            result['details'] = "All essential security headers are present."

    except Exception as e:
        result['status'] = False
        result['details'] = f"Header check failed: {str(e)}"
        result['remediation'] = "Ensure your server is correctly configured to send appropriate HTTP headers."

    return result

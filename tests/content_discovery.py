# tests/content_discovery.py

import requests
from tests.firewall_detection import check_for_firewall

def content_discovery(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    url = f"https://{domain}"
    wordlist = ['.git/', '.svn/', 'backup/', 'admin/', 'test/', 'config.php.bak', 'index.php.old']

    found_paths = []

    try:
        for item in wordlist:
            test_url = f"{url}/{item}"
            response = requests.get(test_url, timeout=5, allow_redirects=False)

            # Check for firewall detection
            firewall_detected, firewall_details = check_for_firewall(response)
            if firewall_detected:
                result['status'] = False
                result['details'] = f"Test blocked by firewall. {firewall_details}"
                result['remediation'] = "Ensure your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
                return result

            if response.status_code == 200:
                found_paths.append(test_url)

        if found_paths:
            result['status'] = False
            result['details'] = f"Accessible sensitive paths: {', '.join(found_paths)}"
            result['remediation'] = "Restrict access to sensitive directories/files using server configurations."
        else:
            result['details'] = "No sensitive paths detected."

    except Exception as e:
        result['status'] = False
        result['details'] = f"Content discovery failed: {str(e)}"
        result['remediation'] = "Review your server configurations and ensure sensitive paths are protected."

    return result

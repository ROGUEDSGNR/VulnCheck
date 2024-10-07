# tests/file_upload.py

import requests
from tests.firewall_detection import check_for_firewall

def test_file_upload(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    url = f"https://{domain}/upload"  # Adjust the endpoint accordingly

    files = {'file': ('test.php', '<?php phpinfo(); ?>', 'application/x-php')}
    try:
        response = requests.post(url, files=files, timeout=5)

        # Check for firewall detection
        firewall_detected, firewall_details = check_for_firewall(response)
        if firewall_detected:
            result['status'] = False
            result['details'] = f"Test blocked by firewall. {firewall_details}"
            result['remediation'] = "Ensure that your firewall settings are not overly restrictive or whitelist this tool for accurate testing."
            return result

        if response.status_code == 200 and 'Success' in response.text:
            result['status'] = False
            result['details'] = "File upload vulnerability detected. Server accepts dangerous file types."
            result['remediation'] = "Restrict file types allowed for upload and validate the file contents."
        else:
            result['details'] = "File upload handling appears secure."

    except Exception as e:
        result['status'] = False
        result['details'] = f"File upload test failed: {str(e)}"
        result['remediation'] = "Ensure proper validation and sanitization of uploaded files."

    return result

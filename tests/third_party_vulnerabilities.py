# tests/third_party_vulnerabilities.py

import requests
from bs4 import BeautifulSoup
from tests.firewall_detection import check_for_firewall

def check_third_party_vulnerabilities(domain):
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

        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        vulnerable_libraries = []

        for script in scripts:
            src = script['src']
            if 'jquery' in src.lower():
                version = src.split('jquery-')[-1].split('.js')[0]
                if version < '3.5.0':
                    vulnerable_libraries.append(f"jQuery version {version} is outdated.")

        if vulnerable_libraries:
            result['status'] = False
            result['details'] = '; '.join(vulnerable_libraries)
            result['remediation'] = "Update the identified libraries to the latest secure versions."
        else:
            result['details'] = "No vulnerable third-party libraries detected."

    except Exception as e:
        result['status'] = False
        result['details'] = f"Third-party vulnerabilities check failed: {str(e)}"
        result['remediation'] = "Regularly update third-party libraries to mitigate known vulnerabilities."

    return result

# tests/csrf.py

import requests
from bs4 import BeautifulSoup
from tests.firewall_detection import check_for_firewall

def check_csrf_protection(domain):
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
        forms = soup.find_all('form')
        unprotected_forms = []

        for form in forms:
            inputs = form.find_all('input')
            token_found = False
            for input_tag in inputs:
                if 'csrf' in input_tag.get('name', '').lower():
                    token_found = True
                    break
            if not token_found:
                unprotected_forms.append(form.get('action', 'No action attribute'))

        if unprotected_forms:
            result['status'] = False
            result['details'] = f"Forms without CSRF protection: {', '.join(unprotected_forms)}"
            result['remediation'] = "Implement CSRF tokens in forms to protect against CSRF attacks."
        else:
            result['details'] = "All forms have CSRF tokens."

    except Exception as e:
        result['status'] = False
        result['details'] = f"CSRF protection check failed: {str(e)}"
        result['remediation'] = "Ensure that all forms are protected with CSRF tokens."

    return result

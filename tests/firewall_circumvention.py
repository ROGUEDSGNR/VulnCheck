# tests/firewall_circumvention.py

import requests
import base64
import random
import time
import urllib.parse
from selenium import webdriver
from selenium.webdriver.common.by import By
from tests.firewall_detection import check_for_firewall  # Ensure this is imported correctly

def random_case(payload):
    """Randomly changes the case of each character in the payload"""
    return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)

def add_padding(payload):
    """Adds random padding around the payload to bypass detection"""
    junk = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=5))
    return f"{junk}{payload}{junk}"

def send_with_selenium(url, payload):
    """Use Selenium to send the payload as if it were coming from a real browser"""
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')  # Run in headless mode (no GUI)
    driver = webdriver.Chrome(options=options)

    try:
        print(f"Trying to send payload with Selenium: {payload}")
        driver.get(url)
        input_element = driver.find_element(By.NAME, 'input')
        input_element.send_keys(payload)
        input_element.submit()
        time.sleep(3)  # Wait to see if the WAF responds differently
        response_text = driver.page_source
        return response_text
    finally:
        driver.quit()

def test_firewall_circumvention(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    paths = ["/vulnerable_endpoint", "/login", "/admin", "/search", "/api"]

    techniques = [
        {'name': 'Standard SQL Injection', 'payload': "' OR '1'='1", 'method': 'GET'},
        {'name': 'Double URL Encoded', 'payload': urllib.parse.quote(urllib.parse.quote("' OR '1'='1")), 'method': 'GET'},
        {'name': 'Base64 + URL Encoding', 'payload': urllib.parse.quote(base64.b64encode(b"' OR '1'='1").decode()), 'method': 'GET'},
        {'name': 'Randomized Case', 'payload': random_case("' OR '1'='1"), 'method': 'GET'},
        {'name': 'Padded Payload', 'payload': add_padding("' OR '1'='1"), 'method': 'GET'},
        {'name': 'Selenium Payload', 'payload': "' OR '1'='1", 'method': 'BROWSER'},  # Use a real browser
    ]

    for path in paths:
        for technique in techniques:
            try:
                url = f"https://{domain}{path}"
                payload = technique['payload']
                headers = {
                    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    'Referer': 'https://www.example.com',
                    'Accept-Language': 'en-US,en;q=0.9',
                }

                # Use Selenium for browser-based testing
                if technique['method'] == 'BROWSER':
                    response_text = send_with_selenium(url, payload)
                    if "blocked" not in response_text.lower():
                        result['status'] = False
                        result['details'] += f"\nSuccessfully bypassed firewall using technique: {technique['name']} on path {path}"
                        result['remediation'] = (
                            f"The firewall was bypassed using the '{technique['name']}' evasion technique. "
                            f"Consider tightening firewall rules or adjusting rule sets to prevent this evasion."
                        )
                        return result
                    continue

                response = requests.request(
                    method=technique['method'],
                    url=url,
                    headers=headers,
                    params={'input': payload} if technique['method'] == 'GET' else None,
                    data={'input': payload} if technique['method'] == 'POST' else None,
                    timeout=20
                )

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

                # Random delay to mimic human behavior
                time.sleep(random.uniform(1, 3))

            except requests.exceptions.RequestException as e:
                result['status'] = False
                result['details'] += f"\nTest failed for {technique['name']} on path {path}: {str(e)}"
                result['remediation'] = "Ensure firewall rules are comprehensive to detect evasion techniques."

    if result['status']:
        result['details'] = "All firewall circumvention attempts were blocked by the firewall."
    return result

# tests/firewall_detection.py

def check_for_firewall(response):
    """
    Checks if a response indicates the presence of a firewall or WAF.
    """
    firewall_indicators = [
        "mod_security", "cloudflare", "sucuri", "imperva", "akamai", "incapsula",
        "barracuda", "webknight", "f5 big-ip", "denyall", "profense", "sitelock",
        "wallarm", "netlify", "secure entry", "x-sucuri-id", "x-sucuri-block", "x-waf-blocked"
    ]
    
    detected = False
    details = []

    # Check headers for firewall indicators
    for header, value in response.headers.items():
        header = header.lower()
        value = value.lower()

        if any(indicator in value for indicator in firewall_indicators):
            detected = True
            details.append(f"Detected firewall header: {header.title()} - {value.title()}")

    # Check response status code
    if response.status_code in [403, 406, 429]:
        details.append(f"Potential firewall detected: HTTP status code {response.status_code}")
        detected = True

    # Check for specific WAF patterns in the response body
    if response.text and any(indicator in response.text.lower() for indicator in firewall_indicators):
        details.append("Firewall/WAF pattern detected in the response body")
        detected = True

    # Only flag a firewall if there's more than just an Apache header or a simple 403 status code
    if detected and not (len(details) == 1 and "apache" in response.headers.get("server", "").lower()):
        return True, ". ".join(details)

    return False, ""

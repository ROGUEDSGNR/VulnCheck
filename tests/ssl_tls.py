# tests/ssl_tls.py

import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from tests.firewall_detection import check_for_firewall

def check_ssl_certificate(domain):
    result = {'status': True, 'details': '', 'remediation': ''}
    
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert_bin = s.getpeercert(True)
            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            expiry_date = cert.not_valid_after_utc
            current_time = datetime.now(timezone.utc)

            if expiry_date < current_time:
                result['status'] = False
                result['details'] = f"SSL certificate expired on {expiry_date}"
                result['remediation'] = "Renew the SSL certificate and install it properly on your server."
            else:
                days_left = (expiry_date - current_time).days
                result['details'] = f"SSL certificate is valid. Expiry date: {expiry_date} ({days_left} days left)"
    except Exception as e:
        result['status'] = False
        result['details'] = f"SSL/TLS check failed: {str(e)}"
        result['remediation'] = "Ensure your server is configured to use a valid SSL/TLS certificate."

    return result

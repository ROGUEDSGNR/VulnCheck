# VulnCheck Security Scanner

## Overview

**VulnCheck** is a Python-based security scanning tool designed for educational purposes and authorized security assessments. It performs a comprehensive security scan on a target domain by running various tests to identify potential vulnerabilities, including options to test firewall circumvention techniques.

---

## Disclaimer

> **Warning:** This tool is intended for use on domains and systems for which you have explicit permission to perform security testing. Unauthorized scanning of systems without permission may be illegal and unethical. Always ensure you comply with all applicable laws and regulations.

---

## Features

- **SSL/TLS Certificate Checks:** Validates the SSL/TLS certificate configuration.
- **HTTP Headers Analysis:** Inspects HTTP headers for security configurations.
- **Vulnerability Scanning:**
  - Cross-Site Scripting (XSS)
  - SQL Injection
  - Cross-Site Request Forgery (CSRF)
  - Directory Traversal
  - Insecure Direct Object References (IDOR)
  - File Upload Vulnerabilities
  - Unvalidated Redirects and Forwards
  - Security Misconfigurations
  - Sensitive Data Exposure
  - Broken Authentication and Session Management
  - Clickjacking
- **Content Discovery:** Attempts to find hidden or unlinked content.
- **HTTP Methods Analysis:** Evaluates allowed HTTP methods for potential risks.
- **Cookie Security Settings:** Checks for secure cookie attributes.
- **Third-Party Library Vulnerabilities:** Scans for known vulnerabilities in third-party libraries.
- **Firewall Circumvention Tests (Optional):** Attempts to bypass web application firewalls using various evasion techniques.

---

## Installation

### Prerequisites

- Python 3.6 or higher
- `pip` package manager

### Clone the Repository

```bash
git clone https://github.com/ROGUEDSGNR/vulncheck.git
cd vulncheck
```

### Install Dependencies

It's recommended to use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

pip install -r requirements.txt
```

**Ensure `requirements.txt` includes all necessary packages:**

```
requests
termcolor
concurrent.futures
[other dependencies]
```

---

## Usage

### Basic Scan

To perform a basic security scan on a target domain:

```bash
python vulncheck.py example.com
```

### Enable Firewall Circumvention Tests

To include firewall circumvention tests, use the `-fc` or `--firewall-circumvention` flag:

```bash
python vulncheck.py example.com -fc
```

### Command-Line Options

- `domain`: The target domain to scan (required).
- `-fc`, `--firewall-circumvention`: Enables firewall circumvention tests (optional).

### Example

```bash
python vulncheck.py example.com -fc
```

---

## Output

The tool provides color-coded output for easy interpretation:

- **✔ Passed Tests**: Green color indicates tests that passed with no issues found.
- **✖ Failed Tests**: Red color indicates vulnerabilities detected.
- **⚠ Tests Blocked by Firewall**: Yellow color indicates tests blocked by a firewall or security mechanism.

### Sample Output

```plaintext
Starting security scan on example.com

Firewall Circumvention Test enabled.

Security Scan Results:

✔ Passed Tests:

SSL/TLS Check: ✔ Passed
Details: SSL certificate is valid and properly configured.

HTTP Headers Check: ✔ Passed
Details: Security headers are properly set.

✖ Failed Tests:

XSS Vulnerability: ✖ Failed
Details: Reflected XSS vulnerability detected on /search.
Remediation: Implement proper input sanitization and output encoding.

SQL Injection Vulnerability: ✖ Failed
Details: SQL injection vulnerability found on /login.
Remediation: Use parameterized queries and input validation.

⚠ Tests Blocked by Firewall:

Firewall Circumvention Test: ⚠ Blocked by Firewall
Details: Firewall detected using technique: URL Encoded on path /admin - WAF response detected.
```

---

## Configuration

### Customizing Tests

You can customize the tests by modifying or adding modules in the `tests` directory. Each test module should contain a function that performs the test and returns a result dictionary with the following keys:

- `status`: `True` if the test passed, `False` if it failed.
- `details`: A string providing details about the test outcome.
- `remediation`: Suggested steps to remediate any issues found.

### Adjusting Concurrency

By default, the tool runs tests concurrently using all available CPU cores. To adjust the number of concurrent threads, modify the `max_workers` parameter in `vulncheck.py`:

```python
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    # Your code here
```

---

## Development

### Adding New Tests

1. **Create a New Test Module**

   - Navigate to the `tests` directory.
   - Create a new Python file, e.g., `my_new_test.py`.

2. **Implement the Test Function**

   ```python
   # tests/my_new_test.py

   def test_my_new_vulnerability(domain):
       result = {'status': True, 'details': '', 'remediation': ''}
       # Implement your test logic here
       return result
   ```

3. **Import the Test Module**

   In `vulncheck.py`, add the import statement:

   ```python
   from tests import my_new_test
   ```

4. **Add the Test Function to the Test List**

   ```python
   test_functions = [
       # Existing tests...
       ('My New Vulnerability Test', my_new_test.test_my_new_vulnerability),
   ]
   ```

---

## Best Practices

- **Authorized Testing Only:** Always ensure you have explicit permission to scan the target domain.
- **Stay Updated:** Regularly update the tool and its dependencies to incorporate the latest security checks.
- **Ethical Use:** Use the tool responsibly and ethically, adhering to all applicable laws and regulations.
- **Performance Considerations:** Be cautious with the number of concurrent threads to avoid overwhelming the target server.

---

## Troubleshooting

### Common Issues

- **Permission Errors:** Ensure you have the necessary permissions to execute the script and access network resources.
- **Dependency Conflicts:** Verify that all required packages are installed and up-to-date.
- **Firewall Circumvention Test Failures:** If tests are failing due to exceptions (e.g., Selenium errors), ensure that the test scripts are correctly implemented and that all dependencies (like web drivers) are properly configured.

### Selenium Errors

If you encounter Selenium errors during the firewall circumvention tests:

- **Check WebDriver Compatibility:** Ensure the ChromeDriver version matches your installed version of Chrome.
- **Update Selectors:** Verify that the web elements your test scripts are interacting with exist on the target pages.
- **Implement Waits:** Use explicit waits to handle dynamic content loading.

---

## Contribution Guidelines

We welcome contributions from the community!

### Steps to Contribute

1. **Fork the Repository**

   Click on the "Fork" button at the top right corner of the GitHub repository page.

2. **Clone Your Fork**

   ```bash
   git clone https://github.com/ROGUEDSGNR/vulncheck.git
   cd vulncheck
   ```

3. **Create a Feature Branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make Changes**

   - Add new features or fix bugs.
   - Write tests for your new code.
   - Ensure existing tests pass.

5. **Commit Your Changes**

   ```bash
   git commit -am "Add new feature or fix"
   ```

6. **Push to Your Fork**

   ```bash
   git push origin feature/your-feature-name
   ```

7. **Submit a Pull Request**

   Open a pull request to the main repository with a detailed description of your changes.

---

## License

This project is licensed under the [MIT License](LICENSE). You are free to use, modify, and distribute this software per the license terms.

---

## Support and Contact

If you have any questions, issues, or suggestions, please open an issue on the GitHub repository or contact the maintainers directly.

- **GitHub Issues:** [https://github.com/yourusername/vulncheck/issues](https://github.com/ROGUEDSGNR/vulncheck/issues)
- **Email:** [hello@roguedsgnr.com](hello@roguedsgnr.com)

---

## Acknowledgments

- **Contributors:** Thank you to all the contributors who have helped improve VulnCheck.
- **Community:** Inspired by the security community and resources like OWASP.
- **Libraries Used:** This tool utilizes several open-source libraries, including `requests`, `termcolor`, and others.

---

## Frequently Asked Questions (FAQ)

### Is it legal to use VulnCheck on any website?

No, you must have explicit permission to perform security scans on a website. Unauthorized scanning can be illegal and unethical.

### Can I add my own tests?

Yes, the tool is designed to be extensible. You can add new test modules following the guidelines in the [Development](#development) section.

### How do I report a bug or request a feature?

Please open an issue on the GitHub repository with detailed information.

---

## Additional Resources

- **OWASP Top Ten Security Risks:** [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
- **Python Documentation:** [https://docs.python.org/3/](https://docs.python.org/3/)
- **Termcolor Documentation:** [https://pypi.org/project/termcolor/](https://pypi.org/project/termcolor/)

---

**Note:** Always use VulnCheck responsibly and ethically. The developer is not responsible for any misuse of this tool.

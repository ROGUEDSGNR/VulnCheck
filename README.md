# VulnCheck
VulnCheck is a command-line security scanning tool written in Python. It allows users to perform comprehensive security assessments on their websites or domains by checking for common vulnerabilities and misconfigurations. VulnCheck is designed to be easy to use, providing actionable insights and remediation advice directly in the terminal.

### **Overview of the VulnCheck Tool**

1. **Main Script (`vulncheck.py`):**

   - **Purpose**: Acts as the entry point of the application.
   - **Functionality**:
     - Accepts a domain as a command-line argument.
     - Validates the domain format.
     - Optionally enables firewall circumvention tests with the `-fc` flag.
     - Initializes a dictionary to store test results categorized as `passed`, `failed`, or `firewall_blocked`.
     - Defines a list of test functions imported from various modules in the `tests` directory.
     - Executes tests in parallel using `ThreadPoolExecutor` for efficiency.
     - Collects and categorizes the results from each test.
     - Displays the results with color-coded output for better readability using the `termcolor` library.

2. **Test Modules (Located in the `tests` Directory):**

   - **Modules Included**:
     - `ssl_tls`: Checks SSL/TLS certificate validity and configuration.
     - `headers`: Analyzes HTTP headers for security configurations.
     - `xss`: Tests for Cross-Site Scripting vulnerabilities.
     - `sql_injection`: Checks for SQL Injection vulnerabilities.
     - `content_discovery`: Attempts to discover hidden or unlinked content.
     - `csrf`: Verifies the presence of Cross-Site Request Forgery protection.
     - `directory_traversal`: Tests for Directory Traversal vulnerabilities.
     - `idor`: Checks for Insecure Direct Object References.
     - `file_upload`: Tests for insecure file upload functionalities.
     - `unvalidated_redirects`: Looks for unvalidated redirects and forwards.
     - `security_misconfiguration`: Checks for common security misconfigurations.
     - `sensitive_data_exposure`: Scans for exposure of sensitive data.
     - `authentication`: Tests for broken authentication and session management.
     - `http_methods`: Analyzes allowed HTTP methods for potential risks.
     - `cookie_settings`: Checks the security settings of cookies.
     - `clickjacking`: Tests for Clickjacking vulnerabilities.
     - `third_party_vulnerabilities`: Scans for known vulnerabilities in third-party libraries.

   - **Firewall Circumvention Test (`firewall_circumvention.py`)**:
     - **Purpose**: Attempts to bypass web application firewalls (WAFs) using various evasion techniques.
     - **Techniques Used**:
       - Standard SQL Injection.
       - URL Encoding, Hex Encoding, Multiple Encoding (combination of URL, Base64, Hex).
       - Case Manipulation (randomly changing the case of payload characters).
       - Adding Padding or Junk Data to the payload.
       - Injecting Spaces into SQL keywords.
       - HTTP Header Smuggling.
       - Using Non-standard HTTP Methods (e.g., `PROPFIND`).
       - Chunked Transfer Encoding.
       - Timing-based Delays.
       - Null Byte Injection.
       - Testing with different HTTP protocol versions (HTTP/2 and HTTP/3).

     - **Workflow**:
       - Iterates over a list of common endpoints (e.g., `/login`, `/admin`).
       - Applies each evasion technique to the payload.
       - Sends HTTP requests using the specified method and payload.
       - Checks if the firewall blocks the request using the `check_for_firewall` function.
       - Records the result and provides remediation suggestions if the firewall is bypassed.

3. **Result Presentation:**

   - **Categorization**: Test results are categorized into:
     - **Passed Tests**: No issues found.
     - **Failed Tests**: Vulnerabilities detected.
     - **Tests Blocked by Firewall**: Attempts blocked by a firewall or security mechanism.
   - **Output**: Results are displayed with color-coded symbols and messages:
     - **✔ Passed**: Green color for successful tests.
     - **✖ Failed**: Red color for tests where vulnerabilities were found.
     - **⚠ Blocked by Firewall**: Yellow color for tests blocked by firewalls.

---

### **How the Tool Works**

1. **Running the Tool:**

   - Execute the script from the command line:
     ```bash
     python vulncheck.py example.com
     ```
   - To enable firewall circumvention tests:
     ```bash
     python vulncheck.py example.com -fc
     ```

2. **Domain Validation:**

   - The tool first validates the domain format using a regular expression to ensure it's correctly structured before proceeding with the tests.

3. **Executing Tests in Parallel:**

   - Utilizes `ThreadPoolExecutor` to run multiple tests concurrently, reducing the total scan time.

4. **Collecting and Processing Results:**

   - Each test function returns a result dictionary with:
     - **status** (`True` for pass, `False` for fail).
     - **details**: Additional information about the test outcome.
     - **remediation**: Suggestions for fixing any issues found.

5. **Displaying the Results:**

   - The tool prints a summary of all tests, categorized and color-coded for clarity.
   - Provides detailed information and remediation steps for failed tests.

---

### **Example Output**

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

### **Key Features and Benefits**

- **Modular Design**: Easy to add or remove tests without altering the main script significantly.
- **Extensibility**: New tests can be added by creating additional modules in the `tests` directory and importing them in `vulncheck.py`.
- **Parallel Execution**: Improves efficiency by running tests concurrently.
- **Detailed Reporting**: Provides actionable insights and remediation steps for any vulnerabilities found.
- **Optional Firewall Testing**: Can test the effectiveness of WAFs and identify potential evasion techniques.

---

### **How to Use the Tool**

1. **Setup Environment:**

   - Install the required Python packages (e.g., `requests`, `termcolor`, `concurrent.futures`).
   - Use a virtual environment to manage dependencies.

2. **Run the Tool:**

   - Execute the script with the target domain.
   - Use the `-fc` flag if you wish to include firewall circumvention tests.

3. **Review Results:**

   - Analyze the output to identify any vulnerabilities.
   - Follow the remediation steps provided for any failed tests.

4. **Customize Tests:**

   - Modify existing test modules or add new ones as needed.
   - Ensure that each test function returns a consistent result dictionary.

---

### **Considerations and Best Practices**

- **Authorization**: Always ensure you have explicit permission to perform security scans on the target domain to comply with legal and ethical standards.

- **Resource Management**: Be cautious with the number of concurrent threads to avoid overwhelming the target server or violating any usage policies.

- **Updates and Maintenance**:

  - Keep the tool and its dependencies updated to incorporate the latest security checks and best practices.
  - Regularly review and update test modules to handle new types of vulnerabilities.

- **Logging and Reporting**:

  - Consider implementing a logging mechanism to save scan results to a file for future reference.
  - Enhance the reporting format to include timestamps and more detailed context if needed.

---

### **Next Steps**

- **Troubleshooting Errors**:

  - If you encounter specific errors (like the Selenium error), inspect the relevant test module.
  - Ensure that any web elements referenced in your Selenium scripts exist on the target page.

- **Future Enhancements**:

  - **User Interface**: Develop a GUI or web-based interface for users who prefer not to use the command line.
  - **Configuration Files**: Allow users to specify settings and options via a configuration file.
  - **Automated Updates**: Implement a mechanism to automatically update test modules with the latest vulnerability checks.

---

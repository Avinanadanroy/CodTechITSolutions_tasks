import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re  # Import the 're' module

# *** IMPORTANT: Configure your target URL and session cookies here if needed ***
# This example is tailored for applications that use session cookies for interaction,
# like DVWA. If your target doesn't use them, you might need to remove or adjust
# the 'cookies' parameter in the requests calls.
# Make sure to set the correct URL and cookies for your target application.

TARGET_URL = "http://localhost/DVWA/"  # Set your DVWA base URL (adjust if different)
COOKIES = {
    'PHPSESSID': 'b3d4e3979afd9e85ddfe8e2e0754e916',  # Replace with your actual PHPSESSID
    'security': 'low'  # Set the security level you want to test (e.g., low, medium, high)
}

def get_all_forms(url):
    try:
        response = requests.get(url, cookies=COOKIES)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error accessing {url}: {e}")
        return []

def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        inputs = []

        for tag in form.find_all("input"):
            input_type = tag.attrs.get("type", "text")
            input_name = tag.attrs.get("name")
            if input_name:
                inputs.append({"type": input_type, "name": input_name})
        for tag in form.find_all("textarea"):
            input_name = tag.attrs.get("name")
            if input_name:
                inputs.append({"type": "textarea", "name": input_name})

        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
    except AttributeError:
        print("[-] Error parsing form details.")
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}

    for input_detail in form_details["inputs"]:
        input_name = input_detail.get("name")
        if input_name:
            if input_detail["type"] in ["text", "search", "textarea"]:
                data[input_name] = payload
            else:
                data[input_name] = "test"

    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, cookies=COOKIES, allow_redirects=False)
        return requests.get(target_url, params=data, cookies=COOKIES, allow_redirects=False)
    except requests.exceptions.RequestException as e:
        print(f"[-] Error submitting form to {target_url}: {e}")
        return None

def is_sqli_vulnerable(response):
    if response is None:
        return False
    errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "fatal error: unspecified argument supplied and no default found"
    ]
    for error in errors:
        if error in response.text.lower():
            return True
    return False

def test_sql_injection_forms(url):
    forms = get_all_forms(url)
    sql_payloads = ["' OR '1'='1", "';", "\";--", "' UNION SELECT 1,2,3 --+", "\" UNION ALL SELECT NULL,NULL--"]
    found = False

    print(f"\n[*] Testing SQL Injection in forms on: {url}")
    for form in forms:
        form_details = get_form_details(form)
        if not form_details:
            continue
        print(f"[+] Found form with action: {form_details.get('action')}, method: {form_details.get('method')}")
        for payload in sql_payloads:
            response = submit_form(form_details, url, payload)
            if response and is_sqli_vulnerable(response):
                print(f"[!!!] SQL Injection vulnerability found in form with payload: {payload}")
                found = True
                break
        if found:
            break
    if not found:
        print("[-] No SQL Injection vulnerability detected in form inputs.")

def test_sql_injection_url_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    sql_payloads = ["' OR '1'='1", "';", "\";--", "' UNION SELECT 1,2,3 --+", "\" UNION ALL SELECT NULL,NULL--"]
    found = False

    print(f"\n[*] Testing SQL Injection in URL parameters on: {url}")
    for param in params:
        print(f"[+] Testing parameter: {param}")
        original_value = params[param][0]
        for payload in sql_payloads:
            test_params = params.copy()
            test_params[param] = [original_value + payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            try:
                response = requests.get(test_url, cookies=COOKIES, allow_redirects=False, timeout=5)
                response.raise_for_status()
                if is_sqli_vulnerable(response):
                    print(f"[!!!] SQL Injection vulnerability found in URL parameter `{param}` with payload: {payload}")
                    found = True
                    break
            except requests.exceptions.RequestException as e:
                print(f"[-] Error accessing {test_url}: {e}")
        if found:
            break
    if not found:
        print("[-] No SQL Injection vulnerability detected in URL parameters.")

def test_xss_in_forms(url):
    forms = get_all_forms(url)
    xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    found = False

    print(f"\n[*] Testing XSS in forms on: {url}")
    print(f"[+] Detected {len(forms)} form(s)")
    for form in forms:
        form_details = get_form_details(form)
        if not form_details:
            continue
        print(f"[+] Found form with action: {form_details.get('action')}, method: {form_details.get('method')}")
        for payload in xss_payloads:
            response = submit_form(form_details, url, payload)
            if response and payload.lower() in response.text.lower():
                print(f"[!!!] XSS vulnerability found in form with payload: {payload}")
                found = True
                break
        if found:
            break
    if not found:
        print("[-] No XSS vulnerability detected in form inputs.")

def test_xss_in_url_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    found = False

    print(f"\n[*] Testing XSS in URL parameters on: {url}")
    for param in params:
        print(f"[+] Testing parameter: {param}")
        original_value = params[param][0]
        for payload in xss_payloads:
            test_params = params.copy()
            test_params[param] = [original_value + payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            try:
                response = requests.get(test_url, cookies=COOKIES, allow_redirects=False, timeout=5)
                response.raise_for_status()
                if payload.lower() in response.text.lower():
                    print(f"[!!!] XSS vulnerability found in URL param `{param}` with payload: {payload}")
                    found = True
                    break
            except requests.exceptions.RequestException as e:
                print(f"[-] Error accessing {test_url}: {e}")
        if found:
            break
    if not found:
        print("[-] No XSS vulnerability detected in URL parameters.")

def identify_tech_stack(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()

        server_header = response.headers.get('Server')
        powered_by_header = response.headers.get('X-Powered-By')

        print("\n[*] Technology Stack Identification:")
        if server_header:
            print(f"  Server: {server_header}")
        if powered_by_header:
            print(f"  X-Powered-By: {powered_by_header}")

        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.find('meta', {'name': 'generator'}):
            generator = soup.find('meta', {'name': 'generator'})['content']
            print(f"  Generator: {generator}")
        elif re.search(r'wp-content', response.text):
            print("  Likely using WordPress")
        elif re.search(r'joomla', response.text, re.IGNORECASE):
            print("  Likely using Joomla")

    except requests.exceptions.RequestException as e:
        print(f"[-] Error during technology identification: {e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred during technology identification: {e}")

def basic_directory_enumeration(url, common_dirs_file="common_directories.txt"):
    print("\n[*] Basic Directory Enumeration:")
    try:
        with open(common_dirs_file, 'r') as f:
            common_directories = [line.strip() for line in f]
    except FileNotFoundError:
        print(f"[-] Error: Common directories file not found at {common_dirs_file}")
        return

    for directory in common_directories:
        target_url = urljoin(url, directory)
        try:
            response = requests.get(target_url, timeout=3)
            if response.status_code == 200:
                print(f"[+] Found directory: {target_url} (Status: {response.status_code})")
            elif response.status_code == 403:
                print(f"[!] Forbidden directory: {target_url} (Status: {response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error accessing {target_url}: {e}")

def advanced_vulnerability_scan(target_url):
    print("\n[*] Performing Advanced Vulnerability Scan:")
    test_sql_injection_forms(target_url)
    test_sql_injection_url_params(target_url)
    test_xss_in_forms(target_url)
    test_xss_in_url_params(target_url)

if __name__ == "__main__":
    target_url = input("Enter target URL for advanced vulnerability scan: ").strip()
    if not target_url and TARGET_URL:
        target_url = TARGET_URL

    if not target_url:
        print("[-] Target URL cannot be empty.")
    else:
        identify_tech_stack(target_url)
        basic_directory_enumeration(target_url)
        advanced_vulnerability_scan(target_url)

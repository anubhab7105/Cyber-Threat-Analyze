import requests
from urllib.parse import urlparse
import time
import json
import re

# Configuration
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
REQUEST_DELAY = 1  # Seconds between requests to avoid overwhelming servers
SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/.htaccess", "/backup.zip", "/wp-config.php",
    "/appsettings.json", "/robots.txt", "/.DS_Store", "/phpinfo.php"
]

def normalize_url(url):
    """Ensure URL has a scheme and extract base domain."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def check_sensitive_files(target_url):
    """Check for exposed sensitive files."""
    findings = []
    for path in SENSITIVE_PATHS:
        full_url = target_url + path
        try:
            response = requests.get(
                full_url,
                headers={'User-Agent': USER_AGENT},
                timeout=10,
                allow_redirects=False
            )
            if response.status_code == 200:
                findings.append(f"Exposed sensitive file: {full_url}")
            time.sleep(REQUEST_DELAY)
        except requests.RequestException:
            continue
    return findings

def check_common_misconfigurations(target_url):
    """Check for security headers and directory listings."""
    findings = []
    try:
        # Check root directory for listing
        response = requests.get(
            target_url,
            headers={'User-Agent': USER_AGENT},
            timeout=10
        )
        if "Index of /" in response.text:
            findings.append("Directory listing enabled at root")
        
        # Check security headers
        security_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing CSP header",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header",
            "X-Frame-Options": "Missing X-Frame-Options header"
        }
        for header, message in security_headers.items():
            if header not in response.headers:
                findings.append(message)
        
        # Check HTTP methods
        response = requests.options(
            target_url,
            headers={'User-Agent': USER_AGENT},
            timeout=10
        )
        if 'TRACE' in response.headers.get('Allow', ''):
            findings.append("TRACE method enabled (potential XST vulnerability)")
        
        time.sleep(REQUEST_DELAY)
    except requests.RequestException:
        pass
    return findings

def check_https_redirect(target_url):
    """Check if HTTP redirects to HTTPS."""
    findings = []
    if target_url.startswith("http://"):
        https_url = target_url.replace("http://", "https://", 1)
        try:
            # Check HTTPS accessibility
            requests.get(https_url, headers={'User-Agent': USER_AGENT}, timeout=10)
        except:
            findings.append("HTTPS version inaccessible")
            return findings
        
        # Check HTTP to HTTPS redirect
        try:
            response = requests.get(
                target_url,
                headers={'User-Agent': USER_AGENT},
                allow_redirects=False,
                timeout=10
            )
            if response.status_code not in [301, 302] or not response.headers.get('Location', '').startswith('https://'):
                findings.append("HTTP does not redirect to HTTPS")
        except:
            pass
    return findings

def check_breached_credentials(target_url):
    """Check if domain appears in breach databases (using simplified approach)."""
    domain = urlparse(target_url).netloc
    api_url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
    try:
        response = requests.get(
            api_url,
            headers={'User-Agent': USER_AGENT},
            timeout=15
        )
        if response.status_code == 200:
            breaches = json.loads(response.text)
            if breaches:
                breach_names = [b['Name'] for b in breaches]
                return [f"Domain breached in: {', '.join(breach_names)}"]
    except:
        pass
    return []

def scan_website(url):
    """Orchestrate all security checks."""
    normalized_url = normalize_url(url)
    
    results = []
    results.extend(check_sensitive_files(normalized_url))
    results.extend(check_common_misconfigurations(normalized_url))
    results.extend(check_https_redirect(normalized_url))
    results.extend(check_breached_credentials(normalized_url))
    
    return results if results else ["No critical vulnerabilities found"]
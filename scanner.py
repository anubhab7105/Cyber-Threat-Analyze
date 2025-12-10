#!/usr/bin/env python3
"""
Advanced Website Security Scanner - Single File Version
Author: Soumyajit Dutta
Date: 2025
"""

import requests
import re
import ssl
import socket
import json
import argparse
import threading
from queue import Queue
from urllib.parse import urlparse, urlencode, urljoin
from datetime import datetime, timedelta

requests.packages.urllib3.disable_warnings()

# ============================
# Global Configuration
# ============================

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

COMMON_PORTS = [80, 443, 21, 22, 25, 110, 143, 3306, 8080, 8443]
THREADS = 10

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.env", "/.htaccess", "/backup.zip",
    "/config.php", "/appsettings.json", "/database.sqlite", "/db.sqlite3",
    "/wp-config.php", "/id_rsa", "/phpinfo.php", "/server-status"
]

CMS_SIGNATURES = {
    "wordpress": ["wp-content", "wp-includes", "wp-json"],
    "joomla": ["Joomla!", "com_content"],
    "drupal": ["Drupal.settings", "sites/all"],
    "magento": ["Mage.Cookies", "Magento"]
}

WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare"],
    "AWS WAF": ["awswaf"],
    "Sucuri": ["sucuri"],
    "ModSecurity": ["mod_security", "modsecurity"]
}

SQLI_PAYLOADS = ["'", '"', "--", "' OR '1'='1"]
XSS_PAYLOAD = '"><svg/onload=alert(`xss_test`)>'

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "dev", "test", "api", "portal", "cpanel"
]

# ============================
# Utility Functions
# ============================

def normalize_url(url):
    """Ensure scheme & trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.scheme + "://" + parsed.netloc + "/"

def get(url, allow_redirects=True):
    try:
        return requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=10,
            verify=False,
            allow_redirects=allow_redirects
        )
    except:
        return None

# ============================
# Sensitive File Scanner
# ============================

def scan_sensitive_files(base):
    findings = []
    for path in SENSITIVE_PATHS:
        full = base + path.lstrip("/")
        r = get(full, allow_redirects=False)
        if r and r.status_code == 200:
            findings.append(f"Exposed sensitive file: {full}")
    return findings

# ============================
# Security Header Scanner
# ============================

def scan_security_headers(base):
    findings = []
    r = get(base)
    if not r:
        return ["Unable to fetch root page"]

    required = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]

    for header in required:
        if header not in r.headers:
            findings.append(f"Missing header: {header}")

    return findings

# ============================
# Directory Listing Detection
# ============================

def scan_directory_listing(base):
    r = get(base)
    if not r:
        return []

    indicators = ["Index of /", "<title>Index of", "autoindex"]

    for marker in indicators:
        if marker.lower() in r.text.lower():
            return ["Directory listing enabled"]

    return []

# ============================
# HTTPS & TLS Scanner
# ============================

def scan_https(base):
    results = []
    parsed = urlparse(base)
    host = parsed.netloc

    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                results.append(f"TLS Protocol: {protocol}")

                # Certificate expiration
                exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if exp < datetime.utcnow():
                    results.append("Certificate expired")
                else:
                    days = (exp - datetime.utcnow()).days
                    results.append(f"Certificate valid for {days} more days")

    except Exception as e:
        results.append("HTTPS connection failed")

    return results

# ============================
# HTTP Method Scanner
# ============================

def scan_http_methods(base):
    findings = []
    try:
        r = requests.options(base, timeout=10, verify=False)
        allow = r.headers.get("Allow", "")

        if "TRACE" in allow:
            findings.append("TRACE method enabled")

        if "PUT" in allow:
            findings.append("PUT method enabled")

    except:
        pass

    return findings

# ============================
# Cookie Security Scanner
# ============================

def scan_cookies(base):
    findings = []
    r = get(base)
    if not r:
        return findings

    for cookie in r.cookies:
        if not cookie.secure:
            findings.append(f"Cookie not Secure: {cookie.name}")
        if "httponly" not in cookie._rest.keys():
            findings.append(f"Cookie missing HttpOnly: {cookie.name}")
        if "samesite" not in cookie._rest.keys():
            findings.append(f"Cookie missing SameSite: {cookie.name}")

    return findings

# ============================
# CORS Scanner
# ============================

def scan_cors(base):
    findings = []
    r = get(base)
    if not r:
        return findings

    origin = r.headers.get("Access-Control-Allow-Origin", "")
    credentials = r.headers.get("Access-Control-Allow-Credentials", "")

    if origin == "*":
        findings.append("CORS allows any origin (*)")

    if credentials == "true" and origin == "*":
        findings.append("CORS misconfiguration: Credentials allowed with wildcard origin")

    return findings

# ============================
# CMS Detection
# ============================

def scan_cms(base):
    r = get(base)
    if not r:
        return []

    text = r.text.lower()
    found = []

    for cms, signs in CMS_SIGNATURES.items():
        for sig in signs:
            if sig.lower() in text:
                found.append(f"CMS Detected: {cms}")
                break

    return found

# ============================
# WAF Detection
# ============================

def scan_waf(base):
    r = get(base)
    if not r:
        return []

    text = r.text.lower()
    found = []

    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in text:
                found.append(f"WAF Detected: {waf}")
                break

    return found

# ============================
# SQL Injection Tests
# ============================

def scan_sqli(base):
    findings = []
    for payload in SQLI_PAYLOADS:
        test_url = base + "?" + urlencode({"id": f"1{payload}"})
        r = get(test_url)
        if r and any(x in r.text.lower() for x in ["sql", "syntax", "database"]):
            findings.append(f"Possible SQL Injection at parameter id using payload: {payload}")
    return findings

# ============================
# XSS Reflection Tests
# ============================

def scan_xss(base):
    test_url = base + "?" + urlencode({"q": XSS_PAYLOAD})
    r = get(test_url)
    if r and XSS_PAYLOAD in r.text:
        return ["Reflected XSS detected"]
    return []

# ============================
# Subdomain Enumeration
# ============================

def scan_subdomains(base):
    findings = []
    domain = urlparse(base).netloc

    for sub in SUBDOMAIN_WORDLIST:
        url = f"http://{sub}.{domain}"
        r = get(url)
        if r and r.status_code < 400:
            findings.append(f"Subdomain Found: {sub}.{domain}")

    return findings

# ============================
# Port Scan
# ============================

def scan_port(host, port, results):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((host, port))
        results.append(f"Port {port} open")
        sock.close()
    except:
        pass

def scan_ports(base):
    host = urlparse(base).netloc
    results = []
    threads = []

    for port in COMMON_PORTS:
        t = threading.Thread(target=scan_port, args=(host, port, results))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return results

# ============================
# Report Generators
# ============================

def save_json_report(data, filename="scan_result.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def save_html_report(data, filename="scan_report.html"):
    html = "<html><body><h1>Website Security Scan Report</h1>"
    for section, findings in data.items():
        html += f"<h2>{section}</h2><ul>"
        for item in findings:
            html += f"<li>{item}</li>"
        html += "</ul>"
    html += "</body></html>"

    with open(filename, "w") as f:
        f.write(html)

# ============================
# Main Scanner
# ============================

def run_scanner(url):
    base = normalize_url(url)

    results = {
        "Sensitive Files": scan_sensitive_files(base),
        "Security Headers": scan_security_headers(base),
        "Directory Listing": scan_directory_listing(base),
        "HTTPS & TLS": scan_https(base),
        "HTTP Methods": scan_http_methods(base),
        "Cookies": scan_cookies(base),
        "CORS": scan_cors(base),
        "CMS Detection": scan_cms(base),
        "WAF Detection": scan_waf(base),
        "SQL Injection": scan_sqli(base),
        "XSS Tests": scan_xss(base),
        "Subdomains": scan_subdomains(base),
        "Port Scan": scan_ports(base)
    }

    save_json_report(results)
    save_html_report(results)

    return results

# ============================
# CLI Interface
# ============================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Target website URL")
    args = parser.parse_args()

    output = run_scanner(args.url)

    print(json.dumps(output, indent=4))
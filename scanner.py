# it's just an prototype created for college project if you find any mistake or have any suggestions please suggest me

import socket
import requests
import logging

# logging
logging.basicConfig(filename='scan_results.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Open Ports Scanner
def scan_ports(target, ports):
    """Scan open ports on the target machine."""
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            open_ports.append(port)
            print(f"[ALERT] Port {port} is OPEN on {target}")
            logging.info(f"Port {port} is open on {target}")
    return open_ports

# SQL Injection Scanner
def test_sql_injection(target):
    """Test for SQL injection vulnerabilities."""
    vulnerable_urls = []
    payloads = ["'", "\"", " OR 1=1 --", "' OR '1'='1"]
    for payload in payloads:
        url = f"{target}?id={payload}"
        response = requests.get(url)
        if "error" in response.text or "SQL" in response.text:
            vulnerable_urls.append(url)
            print(f"[WARNING] Possible SQL Injection vulnerability at {url}")
            logging.info(f"SQL Injection detected at {url}")
    return vulnerable_urls

# XSS Scanner
def test_xss(target):
    """Test for Cross-Site Scripting vulnerabilities."""
    xss_payloads = ["<script>alert('XSS')</script>", "\" onmouseover=alert('XSS') \"", "'><script>alert('XSS')</script>"]
    vulnerable_urls = []
    for payload in xss_payloads:
        url = f"{target}?search={payload}"
        response = requests.get(url)
        if payload in response.text:
            vulnerable_urls.append(url)
            print(f"[WARNING] Potential XSS vulnerability at {url}")
            logging.info(f"XSS vulnerability found at {url}")
    return vulnerable_urls

# Run all scans after changing the target ip and url
target_ip = "192.168.1.100" 
target_url = "http://example.com/product"  

ports_to_scan = [21, 22, 80, 443, 3306]
open_ports = scan_ports(target_ip, ports_to_scan)
sql_vulnerable_sites = test_sql_injection(target_url)
xss_vulnerable_sites = test_xss(target_url)

# It save's results to the files
with open("open_ports.txt", "w") as file:
    file.write(f"Open Ports on {target_ip}: {open_ports}\n")

with open("sql_vulnerabilities.txt", "w") as file:
    file.write(f"SQL Injection Vulnerabilities:\n{sql_vulnerable_sites}\n")

with open("xss_vulnerabilities.txt", "w") as file:
    file.write(f"XSS Vulnerabilities:\n{xss_vulnerable_sites}\n")

print("Scan Complete. Results saved in scan_results.log, open_ports.txt, sql_vulnerabilities.txt, and xss_vulnerabilities.txt.")
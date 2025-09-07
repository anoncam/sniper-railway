#!/usr/bin/env python3
"""
Advanced Security Scanner for Railway
Implements Sn1per functionality without subprocess calls
"""

import socket
import ssl
import json
import re
import base64
import hashlib
import time
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import urllib.parse
import http.client
from typing import List, Dict, Any, Optional

class AdvancedScanner:
    def __init__(self, target: str, scan_type: str = "normal"):
        self.target = target
        self.scan_type = scan_type
        self.results = {
            'target': target,
            'scan_type': scan_type,
            'started': datetime.now().isoformat(),
            'dns': {},
            'ports': {},
            'web': {},
            'vulnerabilities': [],
            'osint': {},
            'subdomains': [],
            'technologies': [],
            'headers': {},
            'ssl_info': {}
        }
        
    def run_full_scan(self) -> Dict:
        """Execute comprehensive scan based on type"""
        output = []
        output.append("=" * 70)
        output.append(" SN1PER-COMPATIBLE ADVANCED SECURITY SCAN")
        output.append("=" * 70)
        output.append(f"\n[*] Target: {self.target}")
        output.append(f"[*] Scan Type: {self.scan_type}")
        output.append(f"[*] Started: {self.results['started']}\n")
        
        # DNS Reconnaissance
        output.append("\n" + "="*70)
        output.append(" DNS RECONNAISSANCE")
        output.append("="*70)
        dns_results = self.dns_recon()
        output.extend(dns_results)
        
        # Port Scanning
        output.append("\n" + "="*70)
        output.append(" PORT SCANNING")
        output.append("="*70)
        port_results = self.port_scan()
        output.extend(port_results)
        
        # Web Application Analysis
        if self.scan_type in ['web', 'normal', 'vulnscan'] or 80 in self.results['ports'].get('open', []) or 443 in self.results['ports'].get('open', []):
            output.append("\n" + "="*70)
            output.append(" WEB APPLICATION ANALYSIS")
            output.append("="*70)
            web_results = self.web_analysis()
            output.extend(web_results)
        
        # Vulnerability Detection
        if self.scan_type in ['vulnscan', 'normal']:
            output.append("\n" + "="*70)
            output.append(" VULNERABILITY DETECTION")
            output.append("="*70)
            vuln_results = self.vulnerability_scan()
            output.extend(vuln_results)
        
        # OSINT Gathering
        if self.scan_type in ['osint', 'recon', 'normal']:
            output.append("\n" + "="*70)
            output.append(" OSINT GATHERING")
            output.append("="*70)
            osint_results = self.osint_gathering()
            output.extend(osint_results)
        
        # Subdomain Enumeration
        if self.scan_type in ['recon', 'normal', 'osint']:
            output.append("\n" + "="*70)
            output.append(" SUBDOMAIN ENUMERATION")
            output.append("="*70)
            subdomain_results = self.subdomain_enum()
            output.extend(subdomain_results)
        
        # Summary
        output.append("\n" + "="*70)
        output.append(" SCAN SUMMARY")
        output.append("="*70)
        output.append(f"[*] Target: {self.target}")
        output.append(f"[*] IP Address: {self.results['dns'].get('ip', 'Not resolved')}")
        output.append(f"[*] Open Ports: {len(self.results['ports'].get('open', []))}")
        output.append(f"[*] Vulnerabilities Found: {len(self.results['vulnerabilities'])}")
        output.append(f"[*] Subdomains Found: {len(self.results['subdomains'])}")
        output.append(f"[*] Technologies Detected: {len(self.results['technologies'])}")
        output.append(f"[*] Completed: {datetime.now().isoformat()}")
        
        return '\n'.join(output)
    
    def dns_recon(self) -> List[str]:
        """Comprehensive DNS reconnaissance"""
        output = []
        try:
            # Basic resolution
            ip = socket.gethostbyname(self.target)
            self.results['dns']['ip'] = ip
            output.append(f"[+] A Record: {self.target} -> {ip}")
            
            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.results['dns']['ptr'] = hostname
                output.append(f"[+] PTR Record: {ip} -> {hostname}")
            except:
                pass
            
            # DNS Records using dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # MX Records
            try:
                mx_records = resolver.resolve(self.target, 'MX')
                self.results['dns']['mx'] = []
                for mx in mx_records:
                    output.append(f"[+] MX Record: {mx.preference} {mx.exchange}")
                    self.results['dns']['mx'].append(str(mx.exchange))
            except:
                pass
            
            # TXT Records (SPF, DMARC, etc.)
            try:
                txt_records = resolver.resolve(self.target, 'TXT')
                self.results['dns']['txt'] = []
                for txt in txt_records:
                    txt_str = str(txt).strip('"')
                    if 'spf' in txt_str.lower():
                        output.append(f"[+] SPF Record: {txt_str[:100]}")
                    elif 'dmarc' in txt_str.lower():
                        output.append(f"[+] DMARC Record: {txt_str[:100]}")
                    self.results['dns']['txt'].append(txt_str)
            except:
                pass
            
            # NS Records
            try:
                ns_records = resolver.resolve(self.target, 'NS')
                self.results['dns']['ns'] = []
                for ns in ns_records:
                    output.append(f"[+] NS Record: {ns}")
                    self.results['dns']['ns'].append(str(ns))
            except:
                pass
                
        except Exception as e:
            output.append(f"[-] DNS Resolution failed: {str(e)}")
            self.results['dns']['error'] = str(e)
            
        return output
    
    def port_scan(self) -> List[str]:
        """Advanced port scanning with service detection"""
        output = []
        
        # Define ports based on scan type
        if self.scan_type == 'fullportonly':
            ports = list(range(1, 65536))
        elif self.scan_type in ['web', 'vulnscan']:
            ports = [80, 443, 8080, 8443, 3000, 3001, 4567, 5000, 8000, 8081, 8888, 9000]
        elif self.scan_type == 'port':
            ports = self.get_top_ports(100)
        else:
            ports = self.get_top_ports(20)
        
        output.append(f"[*] Scanning {len(ports)} ports...")
        
        open_ports = []
        services = {}
        
        def scan_port_with_banner(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.results['dns'].get('ip', self.target), port))
                
                if result == 0:
                    # Try to grab banner
                    try:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        if banner:
                            return (port, banner[:100])
                    except:
                        pass
                    return (port, self.get_service_name(port))
                sock.close()
                return None
            except:
                return None
        
        # Parallel port scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_port_with_banner, port) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    port, service = result
                    open_ports.append(port)
                    services[port] = service
                    output.append(f"[+] Port {port}/tcp OPEN - {service}")
        
        self.results['ports']['open'] = open_ports
        self.results['ports']['services'] = services
        
        if not open_ports:
            output.append("[-] No open ports found")
        else:
            output.append(f"\n[*] Total open ports: {len(open_ports)}")
            
        return output
    
    def web_analysis(self) -> List[str]:
        """Comprehensive web application analysis"""
        output = []
        
        for scheme, port in [('http', 80), ('https', 443)]:
            if port not in self.results['ports'].get('open', []) and port not in [80, 443]:
                continue
                
            url = f"{scheme}://{self.target}"
            if port not in [80, 443]:
                url += f":{port}"
            
            output.append(f"\n[*] Analyzing {url}")
            
            try:
                # Get headers and response
                response = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                
                # Store headers
                self.results['headers'][scheme] = dict(response.headers)
                
                # Security headers analysis
                security_headers = {
                    'Strict-Transport-Security': 'HSTS',
                    'X-Frame-Options': 'Clickjacking Protection',
                    'X-Content-Type-Options': 'MIME Sniffing Protection',
                    'Content-Security-Policy': 'CSP',
                    'X-XSS-Protection': 'XSS Protection'
                }
                
                output.append(f"[+] Status Code: {response.status_code}")
                output.append(f"[+] Server: {response.headers.get('Server', 'Not disclosed')}")
                
                # Check security headers
                for header, description in security_headers.items():
                    if header in response.headers:
                        output.append(f"[+] {description}: Present")
                    else:
                        output.append(f"[-] {description}: Missing")
                        self.results['vulnerabilities'].append({
                            'type': 'Missing Security Header',
                            'header': header,
                            'severity': 'Medium'
                        })
                
                # Technology detection
                if 'X-Powered-By' in response.headers:
                    tech = response.headers['X-Powered-By']
                    output.append(f"[+] Technology: {tech}")
                    self.results['technologies'].append(tech)
                
                # Check for common frameworks
                content = response.text[:10000]
                frameworks = {
                    'WordPress': ['wp-content', 'wp-includes'],
                    'Drupal': ['sites/all', 'drupal.js'],
                    'Joomla': ['joomla', 'com_content'],
                    'Django': ['csrfmiddlewaretoken'],
                    'Ruby on Rails': ['rails', 'action_controller'],
                    'ASP.NET': ['__VIEWSTATE', 'aspnet']
                }
                
                for framework, signatures in frameworks.items():
                    if any(sig in content for sig in signatures):
                        output.append(f"[+] Detected: {framework}")
                        self.results['technologies'].append(framework)
                
                # SSL Certificate check for HTTPS
                if scheme == 'https':
                    output.extend(self.check_ssl_cert())
                    
            except requests.exceptions.Timeout:
                output.append(f"[-] Timeout connecting to {url}")
            except Exception as e:
                output.append(f"[-] Error analyzing {url}: {str(e)}")
        
        return output
    
    def vulnerability_scan(self) -> List[str]:
        """Check for common vulnerabilities"""
        output = []
        
        # Check for common vulnerable paths
        vulnerable_paths = [
            '/.git/config',
            '/.env',
            '/wp-admin',
            '/admin',
            '/phpmyadmin',
            '/.DS_Store',
            '/backup.sql',
            '/config.php',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml'
        ]
        
        base_url = f"http://{self.target}"
        if 443 in self.results['ports'].get('open', []):
            base_url = f"https://{self.target}"
        
        output.append(f"[*] Checking for exposed sensitive files...")
        
        for path in vulnerable_paths:
            try:
                response = requests.get(f"{base_url}{path}", timeout=2, verify=False)
                if response.status_code == 200:
                    output.append(f"[!] FOUND: {path} (Status: {response.status_code})")
                    self.results['vulnerabilities'].append({
                        'type': 'Exposed Path',
                        'path': path,
                        'severity': 'High' if '.git' in path or '.env' in path else 'Medium'
                    })
            except:
                pass
        
        # Check for open redirect
        output.append(f"[*] Checking for open redirect...")
        redirect_payloads = [
            '//evil.com',
            '@evil.com',
            'https://evil.com'
        ]
        
        for payload in redirect_payloads:
            try:
                response = requests.get(f"{base_url}/?redirect={payload}", 
                                       timeout=2, verify=False, allow_redirects=False)
                if response.status_code in [301, 302] and 'evil.com' in response.headers.get('Location', ''):
                    output.append(f"[!] Open Redirect vulnerability detected")
                    self.results['vulnerabilities'].append({
                        'type': 'Open Redirect',
                        'severity': 'Medium'
                    })
                    break
            except:
                pass
        
        # Check for SQL injection points
        output.append(f"[*] Checking for SQL injection points...")
        sqli_payloads = ["'", '"', 'OR 1=1--', "' OR '1'='1"]
        
        for payload in sqli_payloads:
            try:
                response = requests.get(f"{base_url}/?id={payload}", 
                                       timeout=2, verify=False)
                if any(error in response.text for error in ['SQL syntax', 'mysql_fetch', 'PostgreSQL', 'Oracle error']):
                    output.append(f"[!] Potential SQL injection detected")
                    self.results['vulnerabilities'].append({
                        'type': 'SQL Injection',
                        'severity': 'Critical'
                    })
                    break
            except:
                pass
        
        return output
    
    def osint_gathering(self) -> List[str]:
        """OSINT information gathering"""
        output = []
        
        # Check Shodan-like services (without API key)
        output.append(f"[*] Gathering OSINT data...")
        
        # Check for GitHub dorks
        github_dorks = [
            f'"{self.target}" password',
            f'"{self.target}" api_key',
            f'"{self.target}" token',
            f'"{self.target}" secret'
        ]
        
        output.append(f"[+] GitHub Dork Queries Generated:")
        for dork in github_dorks:
            output.append(f"    - site:github.com {dork}")
        
        # Google dorks
        google_dorks = [
            f'site:{self.target} filetype:pdf',
            f'site:{self.target} filetype:xlsx',
            f'site:{self.target} "index of"',
            f'site:{self.target} inurl:admin',
            f'site:{self.target} intitle:"login"'
        ]
        
        output.append(f"[+] Google Dork Queries Generated:")
        for dork in google_dorks:
            output.append(f"    - {dork}")
        
        # Check archive.org
        output.append(f"[+] Wayback Machine URL:")
        output.append(f"    - https://web.archive.org/web/*/{self.target}")
        
        return output
    
    def subdomain_enum(self) -> List[str]:
        """Enumerate subdomains"""
        output = []
        output.append(f"[*] Enumerating subdomains...")
        
        # Common subdomains to check
        common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server',
            'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'admin', 'test',
            'portal', 'dev', 'staging', 'api', 'app', 'mobile',
            'ftp', 'ssh', 'cpanel', 'whm', 'autodiscover', 'autoconfig'
        ]
        
        found_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.target}"
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    output.append(f"[+] Found: {result}")
        
        self.results['subdomains'] = found_subdomains
        
        if not found_subdomains:
            output.append("[-] No subdomains found")
        else:
            output.append(f"\n[*] Total subdomains found: {len(found_subdomains)}")
        
        return output
    
    def check_ssl_cert(self) -> List[str]:
        """SSL certificate analysis"""
        output = []
        output.append(f"\n[*] SSL Certificate Analysis:")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate details
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    output.append(f"[+] Subject: {subject.get('commonName', 'N/A')}")
                    output.append(f"[+] Issuer: {issuer.get('organizationName', 'N/A')}")
                    output.append(f"[+] Valid From: {cert['notBefore']}")
                    output.append(f"[+] Valid Until: {cert['notAfter']}")
                    
                    # Check for wildcard
                    if '*' in subject.get('commonName', ''):
                        output.append(f"[+] Wildcard Certificate Detected")
                    
                    # Extract SANs
                    if 'subjectAltName' in cert:
                        sans = [x[1] for x in cert['subjectAltName']]
                        output.append(f"[+] Alternative Names: {', '.join(sans[:5])}")
                        
                    self.results['ssl_info'] = {
                        'subject': subject,
                        'issuer': issuer,
                        'valid_from': cert['notBefore'],
                        'valid_until': cert['notAfter']
                    }
                    
        except Exception as e:
            output.append(f"[-] SSL Certificate check failed: {str(e)}")
        
        return output
    
    def get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        return services.get(port, f'Unknown')
    
    def get_top_ports(self, count: int) -> List[int]:
        """Get top N most common ports"""
        top_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                     993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 10000,
                     32768, 49152, 49154, 1433, 2049, 2121, 2375, 2376, 3000,
                     3001, 4567, 5000, 5432, 5555, 5672, 6379, 7001, 8000, 8081,
                     8088, 8181, 8282, 8383, 8484, 8585, 8686, 8787, 8888, 9000,
                     9090, 9200, 9300, 11211, 27017, 27018, 27019, 28017, 50000]
        return top_ports[:count]
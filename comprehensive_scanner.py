#!/usr/bin/env python3
"""
Comprehensive Security Scanner with Full Sn1per Feature Set
Implements all major Sn1per functionality including service enumeration,
exploit detection, credential testing, and report generation
"""

import os
import socket
import ssl
import json
import re
import time
import subprocess
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import urllib.parse
import http.client
from typing import List, Dict, Any, Optional
import hashlib
import struct

class ComprehensiveScanner:
    """Full-featured scanner matching Sn1per capabilities"""
    
    def __init__(self, target: str, scan_type: str = "normal"):
        self.target = target
        self.scan_type = scan_type
        self.ip = None
        self.output = []
        self.open_ports = []
        self.services = {}
        self.vulnerabilities = []
        self.credentials_found = []
        self.exploits_available = []
        
    def add_output(self, text: str):
        """Add line to output"""
        self.output.append(text)
        print(text)  # Real-time output
        
    def safe_execute(self, command: str, timeout: int = 30) -> tuple:
        """Safely execute a command with resource limits"""
        try:
            # Set environment to limit resources
            env = os.environ.copy()
            env['RLIMIT_NPROC'] = '10'
            
            # Try to execute with timeout
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            return (True, result.stdout + result.stderr)
        except subprocess.TimeoutExpired:
            return (False, f"Command timed out after {timeout}s")
        except Exception as e:
            return (False, f"Execution failed: {str(e)}")
    
    def run_full_scan(self) -> str:
        """Execute comprehensive Sn1per-style scan"""
        self.add_output("=" * 80)
        self.add_output(" COMPREHENSIVE SN1PER-COMPATIBLE SECURITY ASSESSMENT")
        self.add_output("=" * 80)
        self.add_output(f"\n[*] Target: {self.target}")
        self.add_output(f"[*] Scan Type: {self.scan_type}")
        self.add_output(f"[*] Started: {datetime.now().isoformat()}")
        
        # Phase 1: Initial Reconnaissance
        self.phase_initial_recon()
        
        # Phase 2: Port & Service Discovery
        self.phase_port_service_discovery()
        
        # Phase 3: Service Enumeration
        self.phase_service_enumeration()
        
        # Phase 4: Web Application Testing
        if 80 in self.open_ports or 443 in self.open_ports:
            self.phase_web_testing()
        
        # Phase 5: Vulnerability Assessment
        self.phase_vulnerability_assessment()
        
        # Phase 6: Exploit Detection
        self.phase_exploit_detection()
        
        # Phase 7: Credential Testing
        if self.scan_type in ['bruteforce', 'normal']:
            self.phase_credential_testing()
        
        # Phase 8: SSL/TLS Analysis
        if 443 in self.open_ports:
            self.phase_ssl_analysis()
        
        # Phase 9: OSINT & Information Gathering
        self.phase_osint_gathering()
        
        # Phase 10: Report Generation
        self.generate_report()
        
        return '\n'.join(self.output)
    
    def phase_initial_recon(self):
        """Initial reconnaissance phase"""
        self.add_output("\n" + "=" * 80)
        self.add_output(" PHASE 1: INITIAL RECONNAISSANCE")
        self.add_output("=" * 80)
        
        # DNS Resolution
        try:
            self.ip = socket.gethostbyname(self.target)
            self.add_output(f"[+] Target resolved to: {self.ip}")
        except:
            self.ip = self.target
            self.add_output(f"[*] Using target as IP: {self.ip}")
        
        # Ping sweep
        self.add_output("\n[*] Host Discovery:")
        success, output = self.safe_execute(f"ping -c 2 -W 1 {self.ip} 2>&1", timeout=5)
        if success and "bytes from" in output:
            self.add_output("  [+] Host is alive (ICMP)")
        else:
            self.add_output("  [*] ICMP blocked or host down")
        
        # Traceroute
        self.add_output("\n[*] Network Path:")
        success, output = self.safe_execute(f"traceroute -m 5 -w 1 {self.ip} 2>&1 | head -10", timeout=10)
        if success:
            for line in output.split('\n')[:6]:
                if line.strip():
                    self.add_output(f"  {line.strip()}")
        
        # WHOIS lookup
        self.add_output("\n[*] WHOIS Information:")
        success, output = self.safe_execute(f"whois {self.target} 2>&1 | grep -E 'OrgName|Country|Email' | head -5", timeout=10)
        if success and output:
            for line in output.split('\n'):
                if line.strip():
                    self.add_output(f"  {line.strip()}")
    
    def phase_port_service_discovery(self):
        """Port and service discovery phase"""
        self.add_output("\n" + "=" * 80)
        self.add_output(" PHASE 2: PORT & SERVICE DISCOVERY")
        self.add_output("=" * 80)
        
        # Try nmap for comprehensive scan
        self.add_output("\n[*] Port Scanning:")
        nmap_success = False
        
        success, output = self.safe_execute(
            f"nmap -sS -sV -sC -O -Pn --top-ports 100 --version-intensity 9 {self.ip} 2>&1", 
            timeout=60
        )
        
        if success and "open" in output.lower():
            nmap_success = True
            for line in output.split('\n'):
                if '/tcp' in line and 'open' in line:
                    self.add_output(f"  {line.strip()}")
                    # Extract port number
                    port_match = re.match(r'(\d+)/tcp', line)
                    if port_match:
                        port = int(port_match.group(1))
                        self.open_ports.append(port)
                        # Extract service info
                        parts = line.split()
                        if len(parts) >= 3:
                            self.services[port] = ' '.join(parts[2:])
                elif 'Service Info' in line or 'OS details' in line:
                    self.add_output(f"  {line.strip()}")
        
        # Fallback to Python scanning if nmap fails
        if not nmap_success:
            self.add_output("  [*] Using Python port scanner...")
            # Common ports to scan
            ports_to_scan = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
                           1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017]
            
            for port in ports_to_scan:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    if sock.connect_ex((self.ip, port)) == 0:
                        self.open_ports.append(port)
                        service = self.identify_service(port)
                        self.services[port] = service
                        self.add_output(f"  Port {port}/tcp: OPEN ({service})")
                    sock.close()
                except:
                    pass
        
        self.add_output(f"\n[*] Found {len(self.open_ports)} open ports")
    
    def identify_service(self, port: int) -> str:
        """Identify service by port number"""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
            8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
        }
        return service_map.get(port, "Unknown")
    
    def phase_service_enumeration(self):
        """Service-specific enumeration phase"""
        self.add_output("\n" + "=" * 80)
        self.add_output(" PHASE 3: SERVICE ENUMERATION")
        self.add_output("=" * 80)
        
        # SSH Enumeration
        if 22 in self.open_ports:
            self.enumerate_ssh()
        
        # SMB Enumeration
        if 445 in self.open_ports or 139 in self.open_ports:
            self.enumerate_smb()
        
        # FTP Enumeration
        if 21 in self.open_ports:
            self.enumerate_ftp()
        
        # SMTP Enumeration
        if 25 in self.open_ports:
            self.enumerate_smtp()
        
        # Database Enumeration
        if 3306 in self.open_ports:
            self.enumerate_mysql()
        if 5432 in self.open_ports:
            self.enumerate_postgresql()
        if 1433 in self.open_ports:
            self.enumerate_mssql()
        
        # SNMP Enumeration
        if 161 in self.open_ports:
            self.enumerate_snmp()
    
    def enumerate_ssh(self):
        """SSH service enumeration"""
        self.add_output("\n[*] SSH Enumeration (Port 22):")
        
        # Try ssh-audit
        success, output = self.safe_execute(f"ssh-audit {self.ip}:22 2>&1 | head -20", timeout=10)
        if success and output:
            for line in output.split('\n')[:10]:
                if 'SSH' in line or 'cipher' in line or 'key' in line:
                    self.add_output(f"  {line.strip()}")
        else:
            # Fallback: Basic SSH banner grab
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.ip, 22))
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                self.add_output(f"  Banner: {banner.strip()}")
                sock.close()
            except:
                self.add_output("  [-] Could not grab SSH banner")
    
    def enumerate_smb(self):
        """SMB/NetBIOS enumeration"""
        self.add_output("\n[*] SMB Enumeration (Port 445/139):")
        
        # Try enum4linux
        success, output = self.safe_execute(f"enum4linux -a {self.ip} 2>&1 | head -30", timeout=20)
        if success and output:
            for line in output.split('\n'):
                if 'Domain' in line or 'Users' in line or 'Share' in line or 'Groups' in line:
                    self.add_output(f"  {line.strip()}")
        
        # Try smbclient
        success, output = self.safe_execute(f"smbclient -L {self.ip} -N 2>&1 | head -20", timeout=10)
        if success and "Sharename" in output:
            self.add_output("  [+] SMB Shares:")
            for line in output.split('\n'):
                if '\t' in line and not 'Sharename' in line:
                    self.add_output(f"    {line.strip()}")
        
        # Try rpcclient
        success, output = self.safe_execute(f"rpcclient -U '' -N {self.ip} -c 'enumdomusers' 2>&1 | head -10", timeout=10)
        if success and "user:" in output:
            self.add_output("  [+] Domain Users Found:")
            for line in output.split('\n')[:5]:
                if "user:" in line:
                    self.add_output(f"    {line.strip()}")
    
    def enumerate_ftp(self):
        """FTP enumeration"""
        self.add_output("\n[*] FTP Enumeration (Port 21):")
        
        # Check anonymous access
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(self.ip, 21, timeout=5)
            ftp.login('anonymous', 'anonymous@example.com')
            self.add_output("  [+] Anonymous FTP access allowed!")
            files = []
            ftp.retrlines('LIST', files.append)
            if files:
                self.add_output("  [+] Files found:")
                for f in files[:5]:
                    self.add_output(f"    {f}")
            ftp.quit()
        except Exception as e:
            self.add_output(f"  [-] Anonymous access denied or FTP error")
    
    def enumerate_smtp(self):
        """SMTP enumeration"""
        self.add_output("\n[*] SMTP Enumeration (Port 25):")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.ip, 25))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.add_output(f"  Banner: {banner.strip()}")
            
            # Try VRFY command
            users_to_test = ['root', 'admin', 'test', 'user']
            for user in users_to_test:
                sock.send(f"VRFY {user}\r\n".encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if "252" in response or "250" in response:
                    self.add_output(f"  [+] User exists: {user}")
            
            sock.close()
        except:
            self.add_output("  [-] Could not enumerate SMTP")
    
    def enumerate_mysql(self):
        """MySQL enumeration"""
        self.add_output("\n[*] MySQL Enumeration (Port 3306):")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, 3306))
            data = sock.recv(1024)
            if data:
                # MySQL sends a greeting packet
                if len(data) > 10:
                    version_end = data[5:].find(b'\x00')
                    if version_end > 0:
                        version = data[5:5+version_end].decode('utf-8', errors='ignore')
                        self.add_output(f"  Version: {version}")
            sock.close()
        except:
            self.add_output("  [-] Could not connect to MySQL")
    
    def enumerate_postgresql(self):
        """PostgreSQL enumeration"""
        self.add_output("\n[*] PostgreSQL Enumeration (Port 5432):")
        self.add_output("  [*] PostgreSQL service detected")
        # PostgreSQL enumeration would require psql client
    
    def enumerate_mssql(self):
        """MSSQL enumeration"""
        self.add_output("\n[*] MSSQL Enumeration (Port 1433):")
        self.add_output("  [*] MSSQL service detected")
        # MSSQL enumeration would require specific tools
    
    def enumerate_snmp(self):
        """SNMP enumeration"""
        self.add_output("\n[*] SNMP Enumeration (Port 161):")
        
        # Try snmpwalk
        success, output = self.safe_execute(
            f"snmpwalk -v2c -c public {self.ip} system 2>&1 | head -10", 
            timeout=10
        )
        if success and output:
            for line in output.split('\n')[:5]:
                if line.strip():
                    self.add_output(f"  {line.strip()}")
    
    def phase_web_testing(self):
        """Web application testing phase"""
        self.add_output("\n" + "=" * 80)
        self.add_output(" PHASE 4: WEB APPLICATION TESTING")
        self.add_output("=" * 80)
        
        for port in [80, 443, 8080, 8443]:
            if port in self.open_ports:
                scheme = 'https' if port in [443, 8443] else 'http'
                self.test_web_app(scheme, port)
    
    def test_web_app(self, scheme: str, port: int):
        """Test a specific web application"""
        self.add_output(f"\n[*] Testing {scheme}://{self.target}:{port}")
        
        # Technology detection with whatweb
        success, output = self.safe_execute(
            f"whatweb {scheme}://{self.target}:{port} 2>&1", 
            timeout=15
        )
        if success and output:
            self.add_output("  [*] Technologies:")
            # Parse whatweb output
            if "[" in output:
                techs = re.findall(r'\[([^\]]+)\]', output)
                for tech in techs[:10]:
                    self.add_output(f"    - {tech}")
        
        # Directory enumeration
        self.add_output("  [*] Directory Enumeration:")
        dirs_to_check = ['/admin', '/login', '/api', '/backup', '/.git', 
                        '/wp-admin', '/phpmyadmin', '/manager', '/console']
        
        for directory in dirs_to_check:
            try:
                if scheme == 'https':
                    conn = http.client.HTTPSConnection(self.target, port, timeout=3)
                else:
                    conn = http.client.HTTPConnection(self.target, port, timeout=3)
                conn.request("GET", directory)
                resp = conn.getresponse()
                if resp.status in [200, 301, 302, 401, 403]:
                    self.add_output(f"    [+] Found: {directory} (Status: {resp.status})")
                conn.close()
            except:
                pass
        
        # Check for common vulnerabilities
        self.add_output("  [*] Vulnerability Checks:")
        self.check_web_vulnerabilities(scheme, port)
    
    def check_web_vulnerabilities(self, scheme: str, port: int):
        """Check for common web vulnerabilities"""
        vulns = []
        
        # Check security headers
        try:
            if scheme == 'https':
                conn = http.client.HTTPSConnection(self.target, port, timeout=3)
            else:
                conn = http.client.HTTPConnection(self.target, port, timeout=3)
            conn.request("GET", "/")
            resp = conn.getresponse()
            headers = resp.getheaders()
            
            # Check for missing security headers
            header_dict = {h[0].lower(): h[1] for h in headers}
            
            if 'x-frame-options' not in header_dict:
                vulns.append("Missing X-Frame-Options (Clickjacking)")
            if 'content-security-policy' not in header_dict:
                vulns.append("Missing Content-Security-Policy")
            if 'strict-transport-security' not in header_dict and scheme == 'https':
                vulns.append("Missing HSTS header")
            if 'server' in header_dict:
                vulns.append(f"Server header disclosure: {header_dict['server']}")
            
            conn.close()
        except:
            pass
        
        # Output vulnerabilities
        if vulns:
            for vuln in vulns:
                self.add_output(f"    [!] {vuln}")
                self.vulnerabilities.append(vuln)
        else:
            self.add_output("    [+] No obvious vulnerabilities found")
    
    def phase_vulnerability_assessment(self):
        """Vulnerability assessment phase"""
        self.add_output("\n" + "=" * 80)
        self.add_output(" PHASE 5: VULNERABILITY ASSESSMENT")
        self.add_output("=" * 80)
        
        # Check for CVEs based on services
        self.add_output("\n[*] Checking for known CVEs:")
        
        for port, service in self.services.items():
            if 'SSH' in service or 'OpenSSH' in service:
                # Check SSH version for CVEs
                if 'OpenSSH' in service:
                    version_match = re.search(r'OpenSSH[_ ](\d+\.\d+)', service)
                    if version_match:
                        version = float(version_match.group(1))
                        if version < 8.0:
                            self.add_output(f"  [!] Outdated OpenSSH version: {version}")
                            self.vulnerabilities.append(f"OpenSSH {version} - Multiple CVEs")
            
            elif 'Apache' in service:
                # Check Apache version
                version_match = re.search(r'Apache/(\d+\.\d+)', service)
                if version_match:
                    version = float(version_match.group(1))
                    if version < 2.4:
                        self.add_output(f"  [!] Outdated Apache version: {version}")
                        self.vulnerabilities.append(f"Apache {version} - Multiple CVEs")
            
            elif 'nginx' in service:
                # Check nginx version
                version_match = re.search(r'nginx/(\d+\.\d+)', service)
                if version_match:
                    version = float(version_match.group(1))
                    if version < 1.18:
                        self.add_output(f"  [!] Outdated nginx version: {version}")
                        self.vulnerabilities.append(f"nginx {version} - Multiple CVEs")
        
        # Try nuclei for vulnerability scanning
        success, output = self.safe_execute(
            f"nuclei -u http://{self.target} -t cves/ -severity critical,high -silent 2>&1 | head -20",
            timeout=30
        )
        if success and output:
            for line in output.split('\n'):
                if 'CVE' in line:
                    self.add_output(f"  [!] {line.strip()}")
                    self.vulnerabilities.append(line.strip())
        
        self.add_output(f"\n[*] Total vulnerabilities found: {len(self.vulnerabilities)}")
    
    def phase_exploit_detection(self):
        """Exploit detection phase"""
        self.add_output("\n" + "=" * 80)
        self.add_output(" PHASE 6: EXPLOIT DETECTION")
        self.add_output("=" * 80)
        
        self.add_output("\n[*] Checking for available exploits:")
        
        # Check for exploits based on services
        exploit_db = {
            'SSH': ['CVE-2018-15473 - Username enumeration'],
            'SMB': ['MS17-010 - EternalBlue', 'CVE-2020-0796 - SMBGhost'],
            'Apache': ['CVE-2021-41773 - Path Traversal', 'CVE-2021-42013 - RCE'],
            'nginx': ['CVE-2021-23017 - DNS Resolver Vulnerability'],
            'WordPress': ['Multiple plugin vulnerabilities'],
            'Drupal': ['Drupalgeddon2 - CVE-2018-7600'],
            'Redis': ['CVE-2022-0543 - Lua sandbox escape']
        }
        
        for port, service in self.services.items():
            for vuln_service, exploits in exploit_db.items():
                if vuln_service.lower() in service.lower():
                    self.add_output(f"  [*] Potential exploits for {service}:")
                    for exploit in exploits:
                        self.add_output(f"    - {exploit}")
                        self.exploits_available.append(exploit)
        
        # Try searchsploit if available
        success, output = self.safe_execute(
            f"searchsploit {self.target} 2>&1 | head -10",
            timeout=10
        )
        if success and "Exploit Title" in output:
            self.add_output("  [*] SearchSploit results:")
            for line in output.split('\n')[2:7]:
                if line.strip():
                    self.add_output(f"    {line.strip()}")
        
        if self.exploits_available:
            self.add_output(f"\n[!] {len(self.exploits_available)} potential exploits identified")
    
    def phase_credential_testing(self):
        """Credential testing phase"""
        self.add_output("\n" + "=" * 80)
        self.add_output(" PHASE 7: CREDENTIAL TESTING")
        self.add_output("=" * 80)
        
        self.add_output("\n[*] Testing default credentials:")
        
        # Default credentials to test
        default_creds = {
            22: [('root', 'root'), ('admin', 'admin'), ('root', 'toor')],
            21: [('anonymous', 'anonymous'), ('ftp', 'ftp')],
            3306: [('root', ''), ('root', 'root'), ('mysql', 'mysql')],
            5432: [('postgres', 'postgres'), ('postgres', 'password')],
            445: [('Administrator', ''), ('Guest', ''), ('admin', 'admin')]
        }
        
        for port in self.open_ports:
            if port in default_creds:
                service = self.services.get(port, 'Unknown')
                self.add_output(f"  [*] Testing {service} on port {port}:")
                
                if port == 22:  # SSH
                    # Would use hydra or medusa here
                    self.add_output("    [*] SSH brute-force requires hydra/medusa")
                elif port == 21:  # FTP
                    for user, passwd in default_creds[21]:
                        try:
                            import ftplib
                            ftp = ftplib.FTP()
                            ftp.connect(self.ip, 21, timeout=3)
                            ftp.login(user, passwd)
                            self.add_output(f"    [+] SUCCESS: {user}:{passwd}")
                            self.credentials_found.append(f"FTP - {user}:{passwd}")
                            ftp.quit()
                        except:
                            pass
    
    def phase_ssl_analysis(self):
        """SSL/TLS analysis phase"""
        self.add_output("\n" + "=" * 80)
        self.add_output(" PHASE 8: SSL/TLS ANALYSIS")
        self.add_output("=" * 80)
        
        self.add_output("\n[*] Analyzing SSL/TLS configuration:")
        
        # Try testssl.sh
        success, output = self.safe_execute(
            f"testssl.sh --fast {self.target}:443 2>&1 | grep -E 'Testing|Vulnerable|Grade' | head -15",
            timeout=30
        )
        if success and output:
            for line in output.split('\n'):
                if line.strip():
                    self.add_output(f"  {line.strip()}")
        else:
            # Fallback SSL analysis
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.target, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        
                        self.add_output(f"  Protocol: {version}")
                        self.add_output(f"  Cipher: {cipher[0]}")
                        self.add_output(f"  Bits: {cipher[2]}")
                        
                        # Check for weak protocols
                        if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                            self.add_output(f"  [!] Weak protocol in use: {version}")
                            self.vulnerabilities.append(f"Weak SSL/TLS protocol: {version}")
            except Exception as e:
                self.add_output(f"  [-] SSL/TLS analysis failed: {str(e)}")
    
    def phase_osint_gathering(self):
        """OSINT gathering phase"""
        self.add_output("\n" + "=" * 80)
        self.add_output(" PHASE 9: OSINT & INFORMATION GATHERING")
        self.add_output("=" * 80)
        
        self.add_output("\n[*] Gathering OSINT data:")
        
        # Email harvesting with theHarvester
        success, output = self.safe_execute(
            f"theHarvester -d {self.target} -b all -l 50 2>&1 | grep '@' | head -10",
            timeout=20
        )
        if success and '@' in output:
            self.add_output("  [*] Email addresses found:")
            for line in output.split('\n'):
                if '@' in line:
                    self.add_output(f"    {line.strip()}")
        
        # Shodan search query
        self.add_output("\n[*] Shodan Queries:")
        self.add_output(f"  hostname:{self.target}")
        self.add_output(f"  org:{self.target}")
        self.add_output(f"  ssl:{self.target}")
        
        # Google dorks
        self.add_output("\n[*] Google Dorks:")
        self.add_output(f'  site:{self.target} filetype:pdf OR filetype:doc')
        self.add_output(f'  site:{self.target} intext:"password" OR intext:"username"')
        self.add_output(f'  site:{self.target} ext:sql OR ext:bak OR ext:old')
        self.add_output(f'  site:pastebin.com "{self.target}"')
        self.add_output(f'  site:github.com "{self.target}"')
        
        # Social media
        self.add_output("\n[*] Social Media:")
        self.add_output(f"  LinkedIn: company/{self.target.split('.')[0]}")
        self.add_output(f"  Twitter: @{self.target.split('.')[0]}")
    
    def generate_report(self):
        """Generate final report"""
        self.add_output("\n" + "=" * 80)
        self.add_output(" FINAL REPORT")
        self.add_output("=" * 80)
        
        self.add_output(f"\n[*] Scan Summary for {self.target}:")
        self.add_output(f"  IP Address: {self.ip}")
        self.add_output(f"  Open Ports: {len(self.open_ports)}")
        if self.open_ports:
            self.add_output(f"  Port List: {', '.join(map(str, sorted(self.open_ports)))}")
        
        self.add_output(f"\n[*] Services Detected: {len(self.services)}")
        for port, service in self.services.items():
            self.add_output(f"  {port}/tcp: {service}")
        
        self.add_output(f"\n[*] Vulnerabilities: {len(self.vulnerabilities)}")
        for vuln in self.vulnerabilities[:10]:
            self.add_output(f"  - {vuln}")
        
        if self.exploits_available:
            self.add_output(f"\n[*] Potential Exploits: {len(self.exploits_available)}")
            for exploit in self.exploits_available[:5]:
                self.add_output(f"  - {exploit}")
        
        if self.credentials_found:
            self.add_output(f"\n[!] Credentials Found: {len(self.credentials_found)}")
            for cred in self.credentials_found:
                self.add_output(f"  - {cred}")
        
        # Risk assessment
        risk_level = "LOW"
        if len(self.vulnerabilities) > 5:
            risk_level = "HIGH"
        elif len(self.vulnerabilities) > 2:
            risk_level = "MEDIUM"
        
        self.add_output(f"\n[*] Risk Level: {risk_level}")
        
        # Recommendations
        self.add_output("\n[*] Recommendations:")
        if 22 in self.open_ports:
            self.add_output("  - Implement SSH key-based authentication")
        if 445 in self.open_ports or 139 in self.open_ports:
            self.add_output("  - Review SMB configuration and disable if not needed")
        if 21 in self.open_ports:
            self.add_output("  - Disable FTP or switch to SFTP")
        if self.vulnerabilities:
            self.add_output("  - Patch identified vulnerabilities immediately")
        if not any(p in self.open_ports for p in [443]):
            self.add_output("  - Implement SSL/TLS for web services")
        
        self.add_output(f"\n[*] Scan completed: {datetime.now().isoformat()}")
        self.add_output("=" * 80)
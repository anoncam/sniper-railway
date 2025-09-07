#!/usr/bin/env python3
"""
Enhanced Security Scanner with Tool Execution
Attempts to run actual security tools with fallback to Python implementations
"""

import os
import socket
import ssl
import json
import re
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import urllib.parse
import http.client
from typing import List, Dict, Any, Optional

class ToolRunner:
    """Safely execute security tools with timeouts and fallbacks"""
    
    @staticmethod
    def run_tool(command: str, timeout: int = 30) -> tuple:
        """Run a tool and return (success, output)"""
        try:
            # Set strict resource limits
            env = os.environ.copy()
            env['RLIMIT_NPROC'] = '20'  # Max processes
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                preexec_fn=lambda: os.setrlimit(os.RLIMIT_NPROC, (20, 20))
            )
            return (True, result.stdout + result.stderr)
        except subprocess.TimeoutExpired:
            return (False, f"Tool timed out after {timeout} seconds")
        except Exception as e:
            return (False, f"Tool execution failed: {str(e)}")

class EnhancedScanner:
    def __init__(self, target: str, scan_type: str = "normal"):
        self.target = target
        self.scan_type = scan_type
        self.ip = None
        self.output = []
        self.tools_available = self.check_tools()
        
    def check_tools(self) -> Dict[str, bool]:
        """Check which tools are available"""
        tools = {
            'nmap': False,
            'nikto': False,
            'dirb': False,
            'whatweb': False,
            'wafw00f': False,
            'dnsenum': False,
            'dnsrecon': False,
            'theharvester': False,
            'amass': False,
            'subfinder': False,
            'sublist3r': False,
            'gobuster': False,
            'ffuf': False,
            'nuclei': False,
            'sslscan': False,
            'sslyze': False,
            'wapiti': False,
            'sqlmap': False,
            'masscan': False,
            'fierce': False
        }
        
        for tool in tools.keys():
            try:
                result = subprocess.run(
                    f"which {tool}",
                    shell=True,
                    capture_output=True,
                    timeout=2
                )
                tools[tool] = result.returncode == 0
            except:
                tools[tool] = False
                
        return tools
    
    def add_output(self, text: str):
        """Add line to output"""
        self.output.append(text)
        
    def run_full_scan(self) -> str:
        """Execute comprehensive scan with real tools"""
        self.add_output("=" * 70)
        self.add_output(" ENHANCED SN1PER-STYLE SECURITY SCAN")
        self.add_output("=" * 70)
        self.add_output(f"\n[*] Target: {self.target}")
        self.add_output(f"[*] Scan Type: {self.scan_type}")
        self.add_output(f"[*] Started: {datetime.now().isoformat()}")
        
        # List available tools
        available = [t for t, v in self.tools_available.items() if v]
        self.add_output(f"[*] Available Tools: {', '.join(available) if available else 'None (using fallbacks)'}\n")
        
        # Phase 1: DNS Reconnaissance
        self.phase_dns_recon()
        
        # Phase 2: Port Scanning
        self.phase_port_scan()
        
        # Phase 3: Web Enumeration
        self.phase_web_enum()
        
        # Phase 4: Vulnerability Scanning
        self.phase_vuln_scan()
        
        # Phase 5: SSL/TLS Analysis
        self.phase_ssl_analysis()
        
        # Phase 6: Subdomain Enumeration
        self.phase_subdomain_enum()
        
        # Phase 7: OSINT Collection
        self.phase_osint()
        
        # Summary
        self.add_output("\n" + "=" * 70)
        self.add_output(" SCAN COMPLETE")
        self.add_output("=" * 70)
        self.add_output(f"[*] Target: {self.target}")
        self.add_output(f"[*] Completed: {datetime.now().isoformat()}")
        
        return '\n'.join(self.output)
    
    def phase_dns_recon(self):
        """DNS Reconnaissance Phase"""
        self.add_output("\n" + "=" * 70)
        self.add_output(" PHASE 1: DNS RECONNAISSANCE")
        self.add_output("=" * 70)
        
        # Try to resolve target
        try:
            self.ip = socket.gethostbyname(self.target)
            self.add_output(f"[+] Resolved {self.target} to {self.ip}")
        except:
            self.add_output(f"[-] Could not resolve {self.target}")
            self.ip = self.target  # Assume it's already an IP
            
        # Run dnsenum if available
        if self.tools_available.get('dnsenum'):
            self.add_output("\n[*] Running dnsenum...")
            success, output = ToolRunner.run_tool(f"dnsenum --enum {self.target} 2>&1 | head -20", timeout=15)
            if success and output:
                for line in output.split('\n')[:10]:
                    if line.strip():
                        self.add_output(f"    {line.strip()}")
        
        # Run dnsrecon if available
        if self.tools_available.get('dnsrecon'):
            self.add_output("\n[*] Running dnsrecon...")
            success, output = ToolRunner.run_tool(f"dnsrecon -d {self.target} -t std 2>&1 | head -20", timeout=15)
            if success and output:
                for line in output.split('\n')[:10]:
                    if line.strip():
                        self.add_output(f"    {line.strip()}")
        
        # Run fierce if available
        if self.tools_available.get('fierce'):
            self.add_output("\n[*] Running fierce...")
            success, output = ToolRunner.run_tool(f"fierce --domain {self.target} 2>&1 | head -20", timeout=15)
            if success and output:
                for line in output.split('\n')[:10]:
                    if line.strip():
                        self.add_output(f"    {line.strip()}")
    
    def phase_port_scan(self):
        """Port Scanning Phase"""
        self.add_output("\n" + "=" * 70)
        self.add_output(" PHASE 2: PORT SCANNING")
        self.add_output("=" * 70)
        
        # Try nmap first
        if self.tools_available.get('nmap'):
            self.add_output("\n[*] Running nmap...")
            if self.scan_type == 'stealth':
                cmd = f"nmap -sS -sV -O -Pn --top-ports 100 {self.ip} 2>&1"
            elif self.scan_type == 'fullportonly':
                cmd = f"nmap -p- -Pn {self.ip} 2>&1"
            else:
                cmd = f"nmap -sV -sC -O -Pn --top-ports 1000 {self.ip} 2>&1"
                
            success, output = ToolRunner.run_tool(cmd, timeout=60)
            if success and output:
                for line in output.split('\n'):
                    if 'open' in line.lower() or 'PORT' in line:
                        self.add_output(f"    {line.strip()}")
        
        # Try masscan as alternative
        elif self.tools_available.get('masscan'):
            self.add_output("\n[*] Running masscan...")
            cmd = f"masscan -p1-1000 {self.ip} --rate=100 2>&1"
            success, output = ToolRunner.run_tool(cmd, timeout=30)
            if success and output:
                for line in output.split('\n'):
                    if 'open' in line.lower():
                        self.add_output(f"    {line.strip()}")
        
        # Fallback to Python port scan
        else:
            self.add_output("\n[*] Running Python port scan...")
            common_ports = [21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443]
            open_ports = []
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((self.ip, port))
                    sock.close()
                    return port if result == 0 else None
                except:
                    return None
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(scan_port, port) for port in common_ports]
                for future in as_completed(futures):
                    port = future.result()
                    if port:
                        open_ports.append(port)
                        self.add_output(f"    Port {port}/tcp: OPEN")
            
            if not open_ports:
                self.add_output("    No open ports found")
    
    def phase_web_enum(self):
        """Web Enumeration Phase"""
        if self.scan_type not in ['web', 'normal', 'vulnscan']:
            return
            
        self.add_output("\n" + "=" * 70)
        self.add_output(" PHASE 3: WEB ENUMERATION")
        self.add_output("=" * 70)
        
        # Run whatweb
        if self.tools_available.get('whatweb'):
            self.add_output("\n[*] Running whatweb...")
            for scheme in ['http', 'https']:
                cmd = f"whatweb {scheme}://{self.target} 2>&1 | head -10"
                success, output = ToolRunner.run_tool(cmd, timeout=15)
                if success and output:
                    self.add_output(f"  {scheme.upper()}:")
                    for line in output.split('\n')[:5]:
                        if line.strip():
                            self.add_output(f"    {line.strip()}")
        
        # Run wafw00f
        if self.tools_available.get('wafw00f'):
            self.add_output("\n[*] Running wafw00f (WAF detection)...")
            cmd = f"wafw00f http://{self.target} 2>&1"
            success, output = ToolRunner.run_tool(cmd, timeout=15)
            if success and output:
                for line in output.split('\n'):
                    if 'detected' in line.lower() or 'WAF' in line:
                        self.add_output(f"    {line.strip()}")
        
        # Run nikto
        if self.tools_available.get('nikto'):
            self.add_output("\n[*] Running nikto...")
            cmd = f"nikto -h http://{self.target} -C all -maxtime 30s 2>&1 | head -30"
            success, output = ToolRunner.run_tool(cmd, timeout=45)
            if success and output:
                for line in output.split('\n')[:20]:
                    if '+' in line or 'OSVDB' in line:
                        self.add_output(f"    {line.strip()}")
        
        # Run dirb
        if self.tools_available.get('dirb'):
            self.add_output("\n[*] Running dirb...")
            cmd = f"timeout 20 dirb http://{self.target} -N 404 2>&1 | head -30"
            success, output = ToolRunner.run_tool(cmd, timeout=25)
            if success and output:
                for line in output.split('\n'):
                    if 'FOUND' in line or '==>' in line:
                        self.add_output(f"    {line.strip()}")
        
        # Run gobuster
        elif self.tools_available.get('gobuster'):
            self.add_output("\n[*] Running gobuster...")
            cmd = f"timeout 20 gobuster dir -u http://{self.target} -w /usr/share/wordlists/dirb/common.txt -t 10 2>&1 | head -20"
            success, output = ToolRunner.run_tool(cmd, timeout=25)
            if success and output:
                for line in output.split('\n'):
                    if 'Status:' in line:
                        self.add_output(f"    {line.strip()}")
    
    def phase_vuln_scan(self):
        """Vulnerability Scanning Phase"""
        if self.scan_type not in ['vulnscan', 'normal']:
            return
            
        self.add_output("\n" + "=" * 70)
        self.add_output(" PHASE 4: VULNERABILITY SCANNING")
        self.add_output("=" * 70)
        
        # Run nuclei if available
        if self.tools_available.get('nuclei'):
            self.add_output("\n[*] Running nuclei...")
            cmd = f"nuclei -u http://{self.target} -severity critical,high,medium -timeout 5 2>&1 | head -20"
            success, output = ToolRunner.run_tool(cmd, timeout=30)
            if success and output:
                for line in output.split('\n')[:15]:
                    if '[' in line and ']' in line:
                        self.add_output(f"    {line.strip()}")
        
        # Run wapiti if available
        if self.tools_available.get('wapiti'):
            self.add_output("\n[*] Running wapiti...")
            cmd = f"timeout 30 wapiti -u http://{self.target} --max-scan-time 20 2>&1 | grep -E 'vuln|found|SQL|XSS' | head -10"
            success, output = ToolRunner.run_tool(cmd, timeout=35)
            if success and output:
                for line in output.split('\n')[:10]:
                    if line.strip():
                        self.add_output(f"    {line.strip()}")
        
        # Basic vulnerability checks
        self.add_output("\n[*] Common vulnerability checks...")
        vulns_to_check = [
            ('/.git/', 'Git repository exposed'),
            ('/.env', 'Environment file exposed'),
            ('/wp-admin/', 'WordPress admin found'),
            ('/admin/', 'Admin panel found'),
            ('/phpinfo.php', 'PHPInfo exposed'),
            ('/.htaccess', 'htaccess file exposed'),
            ('/server-status', 'Server status exposed')
        ]
        
        for path, desc in vulns_to_check:
            try:
                conn = http.client.HTTPConnection(self.target, timeout=2)
                conn.request("GET", path)
                resp = conn.getresponse()
                if resp.status in [200, 301, 302]:
                    self.add_output(f"    [!] {desc} at {path}")
                conn.close()
            except:
                pass
    
    def phase_ssl_analysis(self):
        """SSL/TLS Analysis Phase"""
        self.add_output("\n" + "=" * 70)
        self.add_output(" PHASE 5: SSL/TLS ANALYSIS")
        self.add_output("=" * 70)
        
        # Run sslscan
        if self.tools_available.get('sslscan'):
            self.add_output("\n[*] Running sslscan...")
            cmd = f"sslscan --no-colour {self.target}:443 2>&1 | grep -E 'Accepted|Preferred|Certificate' | head -15"
            success, output = ToolRunner.run_tool(cmd, timeout=20)
            if success and output:
                for line in output.split('\n')[:10]:
                    if line.strip():
                        self.add_output(f"    {line.strip()}")
        
        # Run sslyze
        elif self.tools_available.get('sslyze'):
            self.add_output("\n[*] Running sslyze...")
            cmd = f"sslyze --regular {self.target}:443 2>&1 | head -30"
            success, output = ToolRunner.run_tool(cmd, timeout=25)
            if success and output:
                for line in output.split('\n')[:20]:
                    if 'VULNERABLE' in line or 'OK' in line:
                        self.add_output(f"    {line.strip()}")
        
        # Fallback SSL check
        else:
            self.add_output("\n[*] Basic SSL/TLS check...")
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.target, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        self.add_output(f"    SSL Version: {ssock.version()}")
                        self.add_output(f"    Cipher: {ssock.cipher()[0]}")
                        if cert:
                            self.add_output(f"    Subject: {cert.get('subject', [{}])[0]}")
            except Exception as e:
                self.add_output(f"    SSL/TLS connection failed: {str(e)}")
    
    def phase_subdomain_enum(self):
        """Subdomain Enumeration Phase"""
        if self.scan_type not in ['recon', 'normal', 'osint']:
            return
            
        self.add_output("\n" + "=" * 70)
        self.add_output(" PHASE 6: SUBDOMAIN ENUMERATION")
        self.add_output("=" * 70)
        
        # Run subfinder
        if self.tools_available.get('subfinder'):
            self.add_output("\n[*] Running subfinder...")
            cmd = f"subfinder -d {self.target} -silent 2>&1 | head -10"
            success, output = ToolRunner.run_tool(cmd, timeout=20)
            if success and output:
                for line in output.split('\n')[:10]:
                    if line.strip():
                        self.add_output(f"    {line.strip()}")
        
        # Run sublist3r
        if self.tools_available.get('sublist3r'):
            self.add_output("\n[*] Running sublist3r...")
            cmd = f"sublist3r -d {self.target} -t 5 2>&1 | grep -v 'Searching' | head -15"
            success, output = ToolRunner.run_tool(cmd, timeout=25)
            if success and output:
                for line in output.split('\n')[:10]:
                    if line.strip() and not 'Enumerating' in line:
                        self.add_output(f"    {line.strip()}")
        
        # Run amass
        if self.tools_available.get('amass'):
            self.add_output("\n[*] Running amass...")
            cmd = f"timeout 20 amass enum -passive -d {self.target} 2>&1 | head -10"
            success, output = ToolRunner.run_tool(cmd, timeout=25)
            if success and output:
                for line in output.split('\n')[:10]:
                    if line.strip():
                        self.add_output(f"    {line.strip()}")
        
        # Fallback subdomain check
        if not any([self.tools_available.get(t) for t in ['subfinder', 'sublist3r', 'amass']]):
            self.add_output("\n[*] Basic subdomain enumeration...")
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging']
            found = []
            for sub in common_subdomains:
                try:
                    test_domain = f"{sub}.{self.target}"
                    socket.gethostbyname(test_domain)
                    found.append(test_domain)
                    self.add_output(f"    [+] {test_domain}")
                except:
                    pass
            if not found:
                self.add_output("    No subdomains found")
    
    def phase_osint(self):
        """OSINT Collection Phase"""
        if self.scan_type not in ['osint', 'recon', 'normal']:
            return
            
        self.add_output("\n" + "=" * 70)
        self.add_output(" PHASE 7: OSINT COLLECTION")
        self.add_output("=" * 70)
        
        # Run theharvester
        if self.tools_available.get('theharvester'):
            self.add_output("\n[*] Running theHarvester...")
            cmd = f"theHarvester -d {self.target} -b google,bing -l 10 2>&1 | head -20"
            success, output = ToolRunner.run_tool(cmd, timeout=30)
            if success and output:
                for line in output.split('\n')[:15]:
                    if '@' in line or 'found' in line.lower():
                        self.add_output(f"    {line.strip()}")
        
        # Generate OSINT queries
        self.add_output("\n[*] OSINT Search Queries:")
        self.add_output(f"  Google Dorks:")
        self.add_output(f"    site:{self.target} filetype:pdf")
        self.add_output(f"    site:{self.target} inurl:admin")
        self.add_output(f"    site:{self.target} intitle:login")
        self.add_output(f"    site:{self.target} ext:sql OR ext:bak")
        self.add_output(f"  GitHub:")
        self.add_output(f"    {self.target} password")
        self.add_output(f"    {self.target} api_key")
        self.add_output(f"    {self.target} token")
        self.add_output(f"  Shodan:")
        self.add_output(f"    hostname:{self.target}")
        self.add_output(f"  Wayback Machine:")
        self.add_output(f"    https://web.archive.org/web/*/{self.target}")
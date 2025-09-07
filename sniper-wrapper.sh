#!/bin/bash
# Wrapper for Sn1per to limit resource usage in Railway environment

# Set strict resource limits
ulimit -u 50      # Max 50 processes
ulimit -n 1024    # Max 1024 file descriptors
ulimit -v 2097152 # Max 2GB virtual memory

# Disable parallel scanning features
export SNIPER_THREADS=1
export MAX_PROCS=5
export PARALLEL_PROCS=1

# Create minimal config to disable resource-intensive modules
cat > /tmp/sniper-minimal.conf << 'EOF'
# Minimal Sn1per config for Railway
THREADS="1"
PARALLEL="1"
ENABLE_AUTO_UPDATES="0"
ENABLE_OPENVAS="0"
ENABLE_METASPLOIT="0"
ENABLE_MSFCONSOLE="0"
ENABLE_MASSCAN="0"
ENABLE_NMAP_SCRIPTS="0"
AUTO_BRUTE="0"
FULLNMAPSCAN="0"
ENABLE_NIKTO="0"
ENABLE_SQLMAP="0"
ENABLE_WAPITI="0"
EOF

# Run sniper with minimal config
/usr/bin/sniper.original "$@" 2>&1 | head -n 10000 || true

# Fallback to basic scanning if sniper fails
if [ $? -ne 0 ]; then
    echo "[!] Sn1per failed, running basic scan..."
    TARGET=$(echo "$@" | grep -oP '(?<=-t )[^ ]+' | head -1)
    if [ ! -z "$TARGET" ]; then
        echo "[*] Target: $TARGET"
        echo "[*] Running basic reconnaissance..."
        
        # DNS lookup
        echo -e "\n[+] DNS Information:"
        host "$TARGET" 2>/dev/null || nslookup "$TARGET" 2>/dev/null || echo "DNS lookup failed"
        
        # Basic port scan
        echo -e "\n[+] Port Scan (top 100 ports):"
        timeout 30 nmap -sT -T4 --top-ports 100 "$TARGET" 2>/dev/null || \
        python3 -c "
import socket
import sys
target = '$TARGET'
common_ports = [21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443]
print(f'Scanning {target}...')
for port in common_ports:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f'Port {port}: Open')
        sock.close()
    except:
        pass
        "
        
        # Web detection
        echo -e "\n[+] Web Services:"
        curl -s -I "http://$TARGET" 2>/dev/null | head -5 || echo "HTTP not available"
        curl -s -I "https://$TARGET" 2>/dev/null | head -5 || echo "HTTPS not available"
        
        echo -e "\n[*] Basic scan completed"
    fi
fi
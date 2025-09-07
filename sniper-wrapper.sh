#!/bin/bash
# Wrapper for Sn1per to prevent resource exhaustion in Railway

echo "[*] Sn1per wrapper starting - Railway optimized mode"

# Extract target from arguments
TARGET=""
MODE="normal"
for arg in "$@"; do
    if [ "$prev_arg" == "-t" ]; then
        TARGET="$arg"
    elif [ "$prev_arg" == "-m" ]; then
        MODE="$arg"
    fi
    prev_arg="$arg"
done

if [ -z "$TARGET" ]; then
    echo "[!] No target specified"
    exit 1
fi

echo "[*] Target: $TARGET"
echo "[*] Mode: $MODE"

# Set very strict limits BEFORE trying to run sniper
ulimit -u 20      # Max 20 processes (very conservative)
ulimit -n 256     # Max 256 file descriptors
ulimit -v 1048576 # Max 1GB virtual memory

# Always use fallback scan in Railway - Sn1per is too resource intensive
echo "[*] Using optimized scanning for Railway environment..."
echo ""
echo "======================================================================"
echo " RAILWAY-OPTIMIZED SCAN"
echo "======================================================================"
echo ""

# DNS Information
echo "[*] DNS Resolution:"
python3 -c "
import socket
try:
    ip = socket.gethostbyname('$TARGET')
    print(f'  $TARGET resolves to {ip}')
except:
    print('  Unable to resolve $TARGET')
" 2>/dev/null || echo "  DNS resolution failed"

echo ""
echo "[*] Basic Port Scan:"
python3 -c "
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

target = '$TARGET'
common_ports = [21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443]

def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        return (port, result == 0)
    except:
        return (port, False)

print(f'  Scanning common ports on {target}...')
open_ports = []

with ThreadPoolExecutor(max_workers=5) as executor:
    futures = [executor.submit(scan_port, port) for port in common_ports]
    for future in as_completed(futures):
        port, is_open = future.result()
        if is_open:
            open_ports.append(port)
            print(f'  Port {port}/tcp: OPEN')

if not open_ports:
    print('  No common ports found open')
else:
    print(f'  Found {len(open_ports)} open port(s)')
" 2>/dev/null || echo "  Port scan failed"

echo ""
echo "[*] Web Service Detection:"

# Check HTTP
echo -n "  HTTP (80): "
curl -s --max-time 2 -o /dev/null -w "%{http_code}" "http://$TARGET" 2>/dev/null || echo "Connection failed"

echo ""
echo -n "  HTTPS (443): "
curl -s --max-time 2 -o /dev/null -w "%{http_code}" "https://$TARGET" 2>/dev/null || echo "Connection failed"

echo ""
echo ""
echo "[*] HTTP Headers (if available):"
curl -s --max-time 2 -I "http://$TARGET" 2>/dev/null | head -10 || echo "  No HTTP headers available"

echo ""
echo "======================================================================"
echo " SCAN COMPLETE"
echo "======================================================================"
echo ""
echo "[*] Scan completed for $TARGET"
echo "[*] Mode: $MODE (Railway-optimized)"
echo ""

# Exit successfully
exit 0
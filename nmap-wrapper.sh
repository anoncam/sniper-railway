#!/bin/bash
# Nmap wrapper script for Railway environment
# Falls back to Python-based scanning if nmap fails

ARGS="$@"
NMAP_BIN="/usr/bin/nmap"

# Try running nmap directly first
if $NMAP_BIN $ARGS 2>/dev/null; then
    exit 0
fi

# If nmap fails with permission error, try with reduced privileges
if $NMAP_BIN --unprivileged --send-ip $ARGS 2>/dev/null; then
    exit 0
fi

# Final fallback: Use Python-based TCP scanner
python3 - <<EOF
import sys
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
import time

args = "$ARGS".split()
target = None
ports = "1-1000"  # Default port range

# Parse basic nmap arguments
for i, arg in enumerate(args):
    if not arg.startswith('-'):
        target = arg
    elif arg == '-p':
        if i + 1 < len(args):
            ports = args[i + 1]

if not target:
    print("No target specified")
    sys.exit(1)

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def parse_ports(port_spec):
    ports = []
    if '-' in port_spec:
        start, end = port_spec.split('-')
        ports = range(int(start), int(end) + 1)
    elif ',' in port_spec:
        ports = [int(p) for p in port_spec.split(',')]
    else:
        ports = [int(port_spec)]
    return ports

# Resolve hostname
try:
    host_ip = socket.gethostbyname(target)
except:
    print(f"Failed to resolve {target}")
    sys.exit(1)

print(f"Starting Python fallback scan of {target} ({host_ip})")
print(f"PORT      STATE SERVICE")

port_list = parse_ports(ports)
open_ports = []

with ThreadPoolExecutor(max_workers=100) as executor:
    results = executor.map(lambda p: scan_port(host_ip, p), port_list)
    for port in results:
        if port:
            open_ports.append(port)
            print(f"{port}/tcp   open  unknown")

if not open_ports:
    print("All scanned ports are closed")
else:
    print(f"\nFound {len(open_ports)} open ports")
EOF
from flask import Flask, render_template, request, jsonify, session, send_file
from flask_cors import CORS
import subprocess
import os
import json
import uuid
import threading
import time
from datetime import datetime
import re
import socket
from concurrent.futures import ThreadPoolExecutor

# Import our advanced scanner
try:
    from scanner import AdvancedScanner
    HAS_ADVANCED_SCANNER = True
except ImportError as e:
    print(f"Warning: Could not import AdvancedScanner: {e}")
    HAS_ADVANCED_SCANNER = False

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
CORS(app)

RESULTS_DIR = '/app/results'
os.makedirs(RESULTS_DIR, exist_ok=True)

scan_status = {}

def sanitize_input(input_string):
    return re.sub(r'[^\w\s\-\.\:\/]', '', input_string)

def fallback_port_scan(target, ports="1-1000"):
    """Fallback Python-based port scanner when nmap fails"""
    results = []
    try:
        host_ip = socket.gethostbyname(target)
        results.append(f"Resolved {target} to {host_ip}")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((host_ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # Parse port range
        if '-' in ports:
            start, end = ports.split('-')
            port_list = range(int(start), min(int(end) + 1, 65536))
        else:
            port_list = [int(ports)]
        
        results.append(f"Scanning {len(port_list)} ports...")
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            scan_results = executor.map(scan_port, port_list)
            for port in scan_results:
                if port:
                    open_ports.append(port)
                    results.append(f"Port {port}/tcp open")
        
        if open_ports:
            results.append(f"\nFound {len(open_ports)} open ports: {', '.join(map(str, open_ports))}")
        else:
            results.append("\nAll scanned ports appear closed or filtered")
            
    except Exception as e:
        results.append(f"Scan error: {str(e)}")
    
    return '\n'.join(results)

def run_scan(scan_id, target, scan_type, options):
    scan_status[scan_id] = {
        'status': 'running',
        'started': datetime.now().isoformat(),
        'target': target,
        'type': scan_type,
        'output': '',
        'progress': 0
    }
    
    try:
        # Use advanced scanner with Sn1per-like functionality
        if HAS_ADVANCED_SCANNER:
            scanner = AdvancedScanner(target, scan_type)
            
            # Run scan in thread-safe way
            def update_progress():
                scan_status[scan_id]['progress'] = 10
                time.sleep(0.5)
                scan_status[scan_id]['progress'] = 30
                time.sleep(0.5)
                scan_status[scan_id]['progress'] = 50
                time.sleep(0.5)
                scan_status[scan_id]['progress'] = 70
                time.sleep(0.5)
                scan_status[scan_id]['progress'] = 90
            
            progress_thread = threading.Thread(target=update_progress)
            progress_thread.start()
            
            # Run the comprehensive scan
            scan_output = scanner.run_full_scan()
            scan_status[scan_id]['output'] = scan_output
            scan_status[scan_id]['progress'] = 100
            scan_status[scan_id]['status'] = 'completed'
            scan_status[scan_id]['finished'] = datetime.now().isoformat()
            
            # Save results
            with open(f'{RESULTS_DIR}/{scan_id}.json', 'w') as f:
                json.dump(scan_status[scan_id], f)
            
            return
        
        # Fallback to basic scanning if advanced scanner not available
        output_lines = []
        output_lines.append("=" * 70)
        output_lines.append(" BASIC SECURITY SCAN (Advanced Scanner Not Available)")
        output_lines.append("=" * 70)
        output_lines.append("")
        output_lines.append(f"[*] Target: {target}")
        output_lines.append(f"[*] Scan Type: {scan_type}")
        output_lines.append(f"[*] Started: {datetime.now().isoformat()}")
        output_lines.append("")
        
        scan_status[scan_id]['output'] = '\n'.join(output_lines)
        scan_status[scan_id]['progress'] = 10
        
        # DNS Resolution
        output_lines.append("[*] DNS Resolution:")
        try:
            ip = socket.gethostbyname(target)
            output_lines.append(f"    {target} resolves to {ip}")
            scan_status[scan_id]['progress'] = 20
        except Exception as e:
            output_lines.append(f"    Unable to resolve {target}: {str(e)}")
            ip = target  # Try to use as IP if DNS fails
        
        scan_status[scan_id]['output'] = '\n'.join(output_lines)
        
        # Port Scanning
        output_lines.append("")
        output_lines.append("[*] Port Scan Results:")
        scan_status[scan_id]['progress'] = 30
        
        # Different ports based on scan type
        if scan_type in ['web', 'vulnscan']:
            ports_to_scan = [80, 443, 8080, 8443, 3000, 4567, 8000, 8888]
        elif scan_type == 'fullportonly':
            ports_to_scan = list(range(1, 1001))  # Top 1000 ports
        elif scan_type == 'port':
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
        else:
            ports_to_scan = [22, 80, 443, 8080, 8443]  # Quick scan for normal/stealth
        
        open_ports = []
        total_ports = len(ports_to_scan)
        
        def scan_single_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5 if scan_type == 'stealth' else 1.0)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # Scan ports with progress updates
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(scan_single_port, port) for port in ports_to_scan]
            for i, future in enumerate(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
                    output_lines.append(f"    Port {port}/tcp: OPEN")
                    scan_status[scan_id]['output'] = '\n'.join(output_lines)
                
                # Update progress
                progress = 30 + int((i / total_ports) * 40)
                scan_status[scan_id]['progress'] = progress
        
        if not open_ports:
            output_lines.append("    No open ports found in scan range")
        else:
            output_lines.append(f"    Total open ports: {len(open_ports)}")
        
        scan_status[scan_id]['output'] = '\n'.join(output_lines)
        scan_status[scan_id]['progress'] = 70
        
        # Web Service Detection (if applicable)
        if scan_type in ['web', 'normal', 'vulnscan'] or 80 in open_ports or 443 in open_ports:
            output_lines.append("")
            output_lines.append("[*] Web Service Detection:")
            scan_status[scan_id]['progress'] = 80
            
            # Check HTTP
            if 80 in open_ports:
                try:
                    import http.client
                    conn = http.client.HTTPConnection(target, timeout=2)
                    conn.request("HEAD", "/")
                    response = conn.getresponse()
                    output_lines.append(f"    HTTP: {response.status} {response.reason}")
                    server = response.getheader('Server', 'Unknown')
                    output_lines.append(f"    Server: {server}")
                    conn.close()
                except Exception as e:
                    output_lines.append(f"    HTTP: Error - {str(e)}")
            
            # Check HTTPS
            if 443 in open_ports:
                try:
                    import http.client
                    import ssl
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    conn = http.client.HTTPSConnection(target, context=context, timeout=2)
                    conn.request("HEAD", "/")
                    response = conn.getresponse()
                    output_lines.append(f"    HTTPS: {response.status} {response.reason}")
                    server = response.getheader('Server', 'Unknown')
                    output_lines.append(f"    Server: {server}")
                    conn.close()
                except Exception as e:
                    output_lines.append(f"    HTTPS: Error - {str(e)}")
        
        scan_status[scan_id]['output'] = '\n'.join(output_lines)
        scan_status[scan_id]['progress'] = 90
        
        # Summary
        output_lines.append("")
        output_lines.append("=" * 70)
        output_lines.append(" SCAN COMPLETE")
        output_lines.append("=" * 70)
        output_lines.append(f"[*] Target: {target}")
        output_lines.append(f"[*] Open Ports Found: {len(open_ports)}")
        output_lines.append(f"[*] Scan Type: {scan_type}")
        output_lines.append(f"[*] Completed: {datetime.now().isoformat()}")
        
        scan_status[scan_id]['output'] = '\n'.join(output_lines)
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['status'] = 'completed'
        scan_status[scan_id]['finished'] = datetime.now().isoformat()
        
        # Save results
        with open(f'{RESULTS_DIR}/{scan_id}.json', 'w') as f:
            json.dump(scan_status[scan_id], f)
            
    except Exception as e:
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['error'] = str(e)
        scan_status[scan_id]['finished'] = datetime.now().isoformat()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = sanitize_input(data.get('target', ''))
    scan_type = data.get('scan_type', 'normal')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    scan_id = str(uuid.uuid4())
    
    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, target, scan_type, options)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id})

@app.route('/status/<scan_id>')
def get_status(scan_id):
    if scan_id in scan_status:
        return jsonify(scan_status[scan_id])
    
    result_file = f'{RESULTS_DIR}/{scan_id}.json'
    if os.path.exists(result_file):
        with open(result_file, 'r') as f:
            return jsonify(json.load(f))
    
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/scans')
def list_scans():
    scans = []
    
    for scan_id, status in scan_status.items():
        scans.append({
            'id': scan_id,
            'target': status.get('target'),
            'type': status.get('type'),
            'status': status.get('status'),
            'started': status.get('started')
        })
    
    for filename in os.listdir(RESULTS_DIR):
        if filename.endswith('.json'):
            scan_id = filename[:-5]
            if scan_id not in scan_status:
                with open(f'{RESULTS_DIR}/{filename}', 'r') as f:
                    data = json.load(f)
                    scans.append({
                        'id': scan_id,
                        'target': data.get('target'),
                        'type': data.get('type'),
                        'status': data.get('status'),
                        'started': data.get('started')
                    })
    
    return jsonify(scans)

@app.route('/download/<scan_id>')
def download_results(scan_id):
    result_file = f'{RESULTS_DIR}/{scan_id}.json'
    if os.path.exists(result_file):
        return send_file(result_file, as_attachment=True)
    return jsonify({'error': 'Results not found'}), 404

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
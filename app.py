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
import nmap
from concurrent.futures import ThreadPoolExecutor

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
        # Start PostgreSQL service if needed
        subprocess.run(['service', 'postgresql', 'start'], capture_output=True, timeout=5)
        
        # First try to run a quick port scan to test nmap
        test_cmd = ['nmap', '--version']
        test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
        
        use_sniper = True
        if 'Operation not permitted' in test_result.stderr:
            scan_status[scan_id]['output'] = "[!] Detected restricted environment, using fallback scanning methods...\n\n"
            # Run fallback scan first
            fallback_result = fallback_port_scan(target)
            scan_status[scan_id]['output'] += fallback_result + "\n\n"
            scan_status[scan_id]['progress'] = 30
        
        # Build the sniper command
        cmd = ['/usr/bin/sniper']
        
        if scan_type == 'normal':
            cmd.extend(['-t', target])
        elif scan_type == 'stealth':
            cmd.extend(['-t', target, '-m', 'stealth'])
        elif scan_type == 'web':
            cmd.extend(['-t', target, '-m', 'web'])
        elif scan_type == 'port':
            cmd.extend(['-t', target, '-m', 'port'])
        elif scan_type == 'fullportonly':
            cmd.extend(['-t', target, '-m', 'fullportonly'])
        elif scan_type == 'osint':
            cmd.extend(['-t', target, '-m', 'osint'])
        elif scan_type == 'recon':
            cmd.extend(['-t', target, '-m', 'recon'])
        elif scan_type == 'vulnscan':
            cmd.extend(['-t', target, '-m', 'vulnscan'])
        
        if options.get('output_dir'):
            cmd.extend(['-w', f'/tmp/sniper-work/{scan_id}'])
        
        # Set environment variables for better tool compatibility
        env = os.environ.copy()
        env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/app/tools'
        env['HOME'] = '/root'
        env['NMAP_PRIVILEGED'] = '0'  # Force unprivileged mode
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
            preexec_fn=os.setsid  # Create new process group
        )
        
        output_lines = []
        for line in iter(process.stdout.readline, ''):
            if line:
                output_lines.append(line)
                scan_status[scan_id]['output'] = ''.join(output_lines[-1000:])
                
                if 'Scanning' in line:
                    scan_status[scan_id]['progress'] = 25
                elif 'Enumerating' in line:
                    scan_status[scan_id]['progress'] = 50
                elif 'Testing' in line:
                    scan_status[scan_id]['progress'] = 75
        
        process.wait()
        
        scan_status[scan_id]['status'] = 'completed'
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['finished'] = datetime.now().isoformat()
        
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
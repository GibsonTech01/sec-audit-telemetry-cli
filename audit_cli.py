#!/usr/bin/env python3
"""
sec-audit-telemetry-cli
Author: Joris Gibson
Description: Automated host security auditing and telemetry collection utility.
Designed for rapid baseline assessment and auditable JSON reporting.
"""

import sys
import os
import platform
import psutil
import socket
import json
from datetime import datetime, timezone

def collect_system_telemetry():
    """Gathers core OS and hardware resource utilization metrics."""
    return {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "cpu_usage_percent": psutil.cpu_percent(interval=1),
        "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "memory_used_percent": psutil.virtual_memory().percent,
        "disk_usage_percent": psutil.disk_usage('/').percent if platform.system() != "Windows" else psutil.disk_usage('C:\\').percent
    }

def audit_network_sockets():
    """Identifies active listening ports and network interfaces."""
    listening_services = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN:
            listening_services.append({
                "laddr_ip": conn.laddr.ip,
                "laddr_port": conn.laddr.port,
                "pid": conn.pid,
                "process_name": psutil.Process(conn.pid).name() if conn.pid else "Unknown"
            })
    return listening_services

def run_baseline_checks():
    """Executes basic security baseline posture checks."""
    checks = []
    
    # Check 1: Root / Administrative privileges
    is_admin = False
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    
    checks.append({
        "check_id": "SEC-001",
        "description": "Execution with elevated administrator privileges",
        "status": "FLAGGED" if is_admin else "PASS",
        "detail": "Running with root/admin rights is high risk for untrusted CLI execution." if is_admin else "Executed under standard user privileges."
    })

    return checks

def generate_report(output_file=None):
    report_data = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scanner_version": "1.0.0",
        "system_telemetry": collect_system_telemetry(),
        "baseline_checks": run_baseline_checks(),
        "open_listening_services": audit_network_sockets()
    }
    
    formatted_json = json.dumps(report_data, indent=2)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(formatted_json)
        print(f"[+] Audit report successfully generated: {output_file}")
    else:
        print(formatted_json)

if __name__ == "__main__":
    out = "audit_report.json" if "--export" in sys.argv else None
    print("[*] Initiating host telemetry & compliance baseline scan...")
    generate_report(out)

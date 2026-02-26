#!/usr/bin/env python3

# Author: Spoonman (Larry.Spohn@TrustedSec.com)
# QA and Personal Pythonian Consultant: Bandrel (Justin.Bollinger@TrustedSec.com)

import contextlib
import datetime
import glob as _glob
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import termios
import threading
from queue import Queue
import xml.etree.ElementTree as etree


def verify_python_version():
    import sys
    if sys.version_info[0] == 2:
        print('Python 3.6+ is required')
        quit(1)
    elif sys.version_info[0] == 3 and sys.version_info[1] < 6:
        print('Python 3.6+ is required')
        quit(1)


def save_terminal_state():
    """Save the current terminal state"""
    try:
        return termios.tcgetattr(sys.stdin)
    except:
        return None

def restore_terminal_state(state):
    """Restore terminal state and reset terminal"""
    if state:
        try:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, state)
        except:
            pass
    # Always try to reset terminal using stty as a fallback
    try:
        subprocess.run(['stty', 'sane'], check=False, stderr=subprocess.DEVNULL)
    except:
        pass

def ascii_art():
    print(r'''
________                   _____   _______  _________________
__  ___/______________________  | / /__   |/  /__    |__  __ \
_____ \___  __ \  __ \  __ \_   |/ /__  /|_/ /__  /| |_  /_/ /
____/ /__  /_/ / /_/ / /_/ /  /|  / _  /  / / _  ___ |  ____/
/____/ _  .___/\____/\____//_/ |_/  /_/  /_/  /_/  |_/_/
       /_/
    ''')

def is_hostname(line):
    """
    Determine if a line is a hostname (not an IP address or CIDR range)

    Args:
        line: The line to check

    Returns:
        True if the line appears to be a hostname, False if it's an IP/CIDR
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return False

    # Check if it's a CIDR notation
    if '/' in line:
        return False

    # Check if it's an IP address (simple regex)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, line):
        return False

    # If it contains letters or is a domain-like string, treat as hostname
    return True

def resolve_hostname(hostname):
    """
    Resolve a hostname to an IP address

    Args:
        hostname: The hostname to resolve

    Returns:
        IP address string, or None if resolution fails
    """
    try:
        ip = socket.gethostbyname(hostname.strip())
        return ip
    except (socket.gaierror, socket.herror, OSError) as e:
        print('\x1b[31m' + f'Warning: Could not resolve hostname {hostname}: {e}' + '\x1b[0m')
        return None

def preprocess_targets(target_file, output_path):
    """
    Preprocess the target file to separate hostnames from IPs.
    Creates a temporary file with IPs for masscan and a mapping file for NMAP.

    Args:
        target_file: Path to the original target file
        output_path: Directory for output files

    Returns:
        Tuple of (masscan_target_file, ip_to_hostname_map)
    """
    ip_to_hostname = {}
    masscan_targets = []

    print('\x1b[33m' + 'Preprocessing target file...' + '\x1b[0m')

    with open(target_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if is_hostname(line):
                # Resolve hostname to IP
                print(f'Resolving hostname: {line}')
                ip = resolve_hostname(line)
                if ip:
                    print(f'  {line} -> {ip}')
                    ip_to_hostname[ip] = line
                    masscan_targets.append(ip)
                else:
                    print(f'  Skipping {line} (resolution failed)')
            else:
                # It's already an IP or CIDR, add as-is
                masscan_targets.append(line)

    # Create temporary file for masscan with IPs
    masscan_file = f'{output_path}/masscan_targets.txt'
    with open(masscan_file, 'w') as f:
        for target in masscan_targets:
            f.write(f'{target}\n')

    # Save IP-to-hostname mapping
    mapping_file = f'{output_path}/ip_hostname_map.json'
    with open(mapping_file, 'w') as f:
        json.dump(ip_to_hostname, f, indent=2)

    print('\x1b[33m' + f'Resolved {len(ip_to_hostname)} hostnames to IPs' + '\x1b[0m')
    print('\x1b[33m' + f'Masscan target file: {masscan_file}' + '\x1b[0m')

    return masscan_file, ip_to_hostname

def _get_scripts_for_port(dest_port, target_scan):
    """Return comma-separated NSE script list for dest_port, or None."""
    table = EXTERNAL_PORT_SCRIPTS if target_scan == 'External' else INTERNAL_PORT_SCRIPTS
    return table.get(dest_port)


def _run_masscan_batch(batch, rate, output_file, target_file, source_port, exclusions_file):
    """Run masscan for one batch and return {port_key: set_of_ips}."""
    masscan_cmd = [
        'masscan',
        '-p', ','.join(batch),
        '--open',
        '--max-rate', rate,
        '--source-port', source_port,
        '-iL', target_file,
        '-oX', output_file
    ]

    if exclusions_file:
        masscan_cmd.extend(['--excludefile', exclusions_file])

    term_state = save_terminal_state()

    try:
        masscan_process = subprocess.Popen(masscan_cmd)
        masscan_process.wait()
    except KeyboardInterrupt:
        print(f'Killing PID {str(masscan_process.pid)}...')
        masscan_process.kill()
        masscan_process.wait()
        restore_terminal_state(term_state)
        raise
    except FileNotFoundError:
        print('\x1b[31m' + 'Error: masscan not found. Please install masscan.' + '\x1b[0m')
        restore_terminal_state(term_state)
        quit(1)
    except Exception as e:
        print('\x1b[31m' + f'Error running masscan: {e}' + '\x1b[0m')
        restore_terminal_state(term_state)
        quit(1)
    finally:
        restore_terminal_state(term_state)

    if masscan_process.returncode == 1:
        quit(1)

    if not os.path.exists(output_file) or os.stat(output_file).st_size == 0:
        return {}

    results = {}
    try:
        root = etree.parse(output_file)
        for host in root.findall('host'):
            ip_address = host.findall('address')[0].attrib['addr']
            ports_elem = host.find('ports')
            if ports_elem is not None:
                port_elem = ports_elem.find('port')
                if port_elem is not None:
                    protocol = port_elem.attrib.get('protocol', 'tcp')
                    portid = port_elem.attrib.get('portid', '')
                    port_key = f'U:{portid}' if protocol == 'udp' else portid
                    results.setdefault(port_key, set()).add(ip_address)
    except etree.ParseError as e:
        print('\x1b[31m' + f'Error parsing masscan XML: {e}' + '\x1b[0m')

    return results


def _select_probe_ports(dest_ports, max_ports=5):
    """Return up to max_ports high-probability ports from dest_ports."""
    dest_set = set(dest_ports)
    probe = [p for p in PROBE_PORT_PRIORITY if p in dest_set][:max_ports]
    if not probe:
        probe = list(dest_ports[:max_ports])
    return probe


# Result dirs and files written during a scan run.
_RESULT_DIRS  = ('masscan_results', 'live_hosts', 'nmap_results')
_RESULT_FILES = ('all_live_hosts.txt', 'masscan_targets.txt',
                 'ip_hostname_map.json', 'spoonmap_output.xml',
                 'findings.txt', 'findings.md')


def _previous_results_exist(output_path):
    """Return True if any prior scan output is present under output_path."""
    for d in _RESULT_DIRS:
        p = os.path.join(output_path, d)
        if os.path.isdir(p) and os.listdir(p):
            return True
    for f in _RESULT_FILES:
        if os.path.exists(os.path.join(output_path, f)):
            return True
    return False


def _delete_previous_results(output_path):
    """Remove all prior scan output under output_path."""
    for d in _RESULT_DIRS:
        p = os.path.join(output_path, d)
        if os.path.isdir(p):
            shutil.rmtree(p)
    for f in _RESULT_FILES:
        p = os.path.join(output_path, f)
        if os.path.exists(p):
            os.remove(p)


def mass_scan(scan_type, dest_ports, source_port, max_rate, target_file, exclusions_file, batch_size=5):
    status_summary = '\nSummary'

    if not os.path.exists(f'{output_path}/masscan_results'):
        os.makedirs(f'{output_path}/masscan_results')

    # Track unique IPs per port in memory for efficiency
    port_ips = {}

    effective_rate = max_rate

    # Full port scan: skip adaptive probe, run single masscan over 1-65535
    if scan_type == 'Full':
        print('\x1b[33m' + 'Full port scan: running masscan 1-65535 (no probe)...' + '\x1b[0m')
        output_file = f'{output_path}/masscan_results/portFull.xml'
        full_results = _run_masscan_batch(['1-65535'], max_rate, output_file,
                                          target_file, source_port, exclusions_file)
        os.makedirs(output_path + '/live_hosts', exist_ok=True)
        for port_key, ips in full_results.items():
            with open(f'{output_path}/live_hosts/port{port_key}.txt', 'w') as f:
                for ip in sorted(ips):
                    f.write(f'{ip}\n')
            host_count = len(ips)
            status_update = f'\nHosts Found on Port {port_key}: {host_count}'
            status_summary += status_update
            print('\x1b[33m' + status_update + '\x1b[0m')
        return status_summary

    probe_ports = _select_probe_ports(dest_ports)
    probe_set = set(probe_ports)
    remaining_ports = [p for p in dest_ports if p not in probe_set]

    # Only run probe when there are additional ports beyond the probe set
    if probe_ports and remaining_ports:
        half_rate = str(max(1, int(max_rate) // 2))
        probe_label = ', '.join(probe_ports)
        print('\x1b[33m' + f'Probe: scanning {probe_label} at {max_rate} pps then {half_rate} pps to check for packet loss...' + '\x1b[0m')
        fast_results = _run_masscan_batch(probe_ports, max_rate,
            f'{output_path}/masscan_results/probe_fast.xml', target_file, source_port, exclusions_file)
        slow_results = _run_masscan_batch(probe_ports, half_rate,
            f'{output_path}/masscan_results/probe_slow.xml', target_file, source_port, exclusions_file)

        fast_ips = {ip for s in fast_results.values() for ip in s}
        slow_ips = {ip for s in slow_results.values() for ip in s}
        new_ips = slow_ips - fast_ips

        if new_ips:
            print('\x1b[33m' + f'Probe found {len(new_ips)} additional host(s) at {half_rate} pps — switching to reduced rate for all batches.' + '\x1b[0m')
            effective_rate = half_rate
        else:
            print('\x1b[33m' + f'Probe found no additional hosts — continuing at {max_rate} pps.' + '\x1b[0m')

        # Merge probe results into port_ips and write live_hosts files now
        os.makedirs(output_path + '/live_hosts', exist_ok=True)
        for port_key in probe_ports:
            combined = fast_results.get(port_key, set()) | slow_results.get(port_key, set())
            if combined:
                port_ips[port_key] = combined
                with open(f'{output_path}/live_hosts/port{port_key}.txt', 'w') as f:
                    for ip in sorted(combined):
                        f.write(f'{ip}\n')
                host_count = len(combined)
                status_update = f'\nHosts Found on Port {port_key}: {host_count}'
                status_summary += status_update
                print('\x1b[33m' + status_update + '\x1b[0m')

        ports_to_batch = remaining_ports
    else:
        ports_to_batch = dest_ports  # no probe: batch all ports normally

    batches = [ports_to_batch[i:i + batch_size] for i in range(0, len(ports_to_batch), batch_size)]
    total_batches = len(batches)

    for batch_idx, batch in enumerate(batches):
        batch_label = ', '.join(batch)
        print('\x1b[33m' + f'Scanning ports {batch_label}...' + '\x1b[0m')

        output_file = f'{output_path}/masscan_results/batch_{batch_idx}.xml'

        batch_results = _run_masscan_batch(batch, effective_rate, output_file, target_file, source_port, exclusions_file)

        if not batch_results:
            print('\x1b[33m' + f'\nNo hosts found in batch {batch_idx + 1}/{total_batches} ({batch_label})')
            print('Masscan Completion Status: ' + '{:.0%}'.format((batch_idx + 1) / total_batches) + '\x1b[0m')
        else:
            # Initialize sets for all ports in this batch, loading existing data for resume
            for dest_port in batch:
                if dest_port not in port_ips:
                    port_ips[dest_port] = set()
                    live_host_file = f'{output_path}/live_hosts/port{dest_port}.txt'
                    if os.path.exists(live_host_file):
                        with open(live_host_file, 'r') as file:
                            port_ips[dest_port].update(line.strip() for line in file if line.strip())

            # Merge batch results into port_ips
            for port_key, ips in batch_results.items():
                if port_key in port_ips:
                    port_ips[port_key].update(ips)

            # Write per-port live_hosts files (nmap_scan expects this layout)
            os.makedirs(output_path + '/live_hosts', exist_ok=True)
            for dest_port in batch:
                if port_ips.get(dest_port):
                    with open(f'{output_path}/live_hosts/port{dest_port}.txt', 'w') as file:
                        for ip in sorted(port_ips[dest_port]):
                            file.write(f'{ip}\n')
                    host_count = len(port_ips[dest_port])
                    status_update = f'\nHosts Found on Port {dest_port}: {host_count}'
                    status_summary += status_update
                    print('\x1b[33m' + status_update + '\x1b[0m')

            print('\x1b[33m' + 'Masscan Completion Status: ' + '{:.0%}'.format((batch_idx + 1) / total_batches) + '\x1b[0m')

    return status_summary

def create_hostname_target_file(ip_file, hostname_file, ip_to_hostname):
    """
    Create a hostname-based target file from an IP-based file

    Args:
        ip_file: Path to file containing IP addresses
        hostname_file: Path to output file with hostnames
        ip_to_hostname: Dictionary mapping IPs to hostnames
    """
    with open(ip_file, 'r') as inf, open(hostname_file, 'w') as outf:
        for line in inf:
            ip = line.strip()
            # Use hostname if available, otherwise keep the IP
            hostname = ip_to_hostname.get(ip, ip)
            outf.write(f'{hostname}\n')

def nmap_worker(work_queue, completed_count, total_count, source_port, lock,
                interrupt_event, ip_to_hostname, script_scan=False, target_scan='Internal'):
    """Worker thread function to process NMAP scans from queue"""
    while not interrupt_event.is_set():
        try:
            # Get work item with timeout to check interrupt_event periodically
            try:
                host_file = work_queue.get(timeout=0.5)
            except:
                # Queue is empty or timeout occurred
                continue

            if host_file is None:  # Poison pill to stop worker
                work_queue.task_done()
                break

            dest_port = ((host_file.split('.')[0])[4:])
            output_file = f'{output_path}/nmap_results/port{dest_port}.xml'
            input_file = f'{output_path}/live_hosts/port{dest_port}.txt'

            # Create hostname-based target file if we have hostname mappings
            if ip_to_hostname:
                hostname_file = f'{output_path}/live_hosts/port{dest_port}_hostnames.txt'
                create_hostname_target_file(input_file, hostname_file, ip_to_hostname)
                input_file = hostname_file

            # Build command as list to prevent shell injection
            if 'U:' in dest_port:
                nmap_cmd = [
                    'nmap', '-T4', '-sU', '-sV',
                    '--version-intensity', '0',
                    '-Pn', '-p', dest_port[2:],
                    '--open', '--randomize-hosts',
                    '--source-port', source_port,
                    '-iL', input_file,
                    '-oX', output_file
                ]
            else:
                nmap_cmd = [
                    'nmap', '-T4', '-sS', '-sV',
                    '--version-intensity', '0',
                    '-Pn', '-p', dest_port,
                    '--open', '--randomize-hosts',
                    '--source-port', source_port,
                    '-iL', input_file,
                    '-oX', output_file
                ]

            if script_scan:
                scripts = _get_scripts_for_port(dest_port, target_scan)
                if scripts:
                    nmap_cmd.extend(['--script', scripts, '--script-timeout', '30s'])

            # Save terminal state before running nmap
            term_state = save_terminal_state()

            try:
                with lock:
                    print('\x1b[33m' + f'Grabbing service banners for port {dest_port}...\n' + '\x1b[0m')

                nmap_process = subprocess.Popen(nmap_cmd)

                # Poll process to allow interrupt checking
                while nmap_process.poll() is None and not interrupt_event.is_set():
                    threading.Event().wait(0.1)

                if interrupt_event.is_set() and nmap_process.poll() is None:
                    nmap_process.kill()
                    nmap_process.wait()
                else:
                    nmap_process.wait()

                    with lock:
                        completed_count[0] += 1
                        print('\x1b[33m' + '\nNMAP Completion Status: ' + \
                            '{:.0%}'.format(completed_count[0] / total_count) + \
                            '\x1b[0m')

            except FileNotFoundError:
                with lock:
                    print('\x1b[31m' + 'Error: nmap not found. Please install nmap.' + '\x1b[0m')
            except Exception as e:
                with lock:
                    print('\x1b[31m' + f'Error running nmap for port {dest_port}: {e}' + '\x1b[0m')
            finally:
                # Always restore terminal state after process completes
                restore_terminal_state(term_state)
                work_queue.task_done()

        except Exception as e:
            with lock:
                print('\x1b[31m' + f'Worker thread error: {e}' + '\x1b[0m')
            work_queue.task_done()

def nmap_scan(source_port, max_threads=5, ip_to_hostname=None,
              script_scan=False, target_scan='Internal'):
    """
    Perform NMAP scans using multiple threads for efficiency

    Args:
        source_port: Source port to use for scans
        max_threads: Maximum number of concurrent NMAP scans (default: 5)
        ip_to_hostname: Dictionary mapping IPs to hostnames (default: None)
        script_scan: Whether to run NSE scripts (default: False)
        target_scan: 'External' or 'Internal' (default: 'Internal')
    """
    if ip_to_hostname is None:
        ip_to_hostname = {}
    # Commence NMAP banner grabbing!
    os.makedirs(output_path+"/nmap_results", exist_ok=True)

    try:
        host_files = os.listdir(f'{output_path}/live_hosts')

        # Filter out files that have already been scanned
        files_to_scan = []
        for host_file in host_files:
            dest_port = ((host_file.split('.')[0])[4:])
            if not os.path.exists(f'{output_path}/nmap_results/port{dest_port}.xml'):
                files_to_scan.append(host_file)

        if not files_to_scan:
            print('\x1b[33m' + 'All ports have already been scanned.' + '\x1b[0m')
            return

        print('\x1b[33m' + f'Starting NMAP scans with {max_threads} concurrent threads...' + '\x1b[0m')

        # Create work queue and synchronization objects
        work_queue = Queue()
        completed_count = [0]  # Use list for mutable counter
        total_count = len(files_to_scan)
        lock = threading.Lock()
        interrupt_event = threading.Event()

        # Add work items to queue
        for host_file in files_to_scan:
            work_queue.put(host_file)

        # Create and start worker threads
        threads = []
        for _ in range(max_threads):
            thread = threading.Thread(
                target=nmap_worker,
                args=(work_queue, completed_count, total_count, source_port, lock,
                      interrupt_event, ip_to_hostname, script_scan, target_scan)
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)

        try:
            # Wait for all work to complete
            work_queue.join()

            # Send poison pills to stop workers
            for _ in range(max_threads):
                work_queue.put(None)

            # Wait for all threads to finish
            for thread in threads:
                thread.join(timeout=2)

        except KeyboardInterrupt:
            print('\x1b[31m' + '\nInterrupt received, stopping NMAP scans...' + '\x1b[0m')
            interrupt_event.set()

            # Wait for threads to finish with timeout
            for thread in threads:
                thread.join(timeout=5)

            raise

    except FileNotFoundError:
        print('\x1b[31m' + f'Error: live_hosts directory not found at {output_path}/live_hosts' + '\x1b[0m')
    except Exception as e:
        print('\x1b[31m' + f'Error during nmap scan: {e}' + '\x1b[0m')

# Counts the number of lines in a file
def lineCount(file):
    try:
        with open(file) as outFile:
            return sum(1 for line in outFile)
    except FileNotFoundError:
        print('\x1b[31m' + f'Warning: File not found: {file}' + '\x1b[0m')
        return 0
    except Exception as e:
        print('\x1b[31m' + f'Warning: Error reading file {file}: {e}' + '\x1b[0m')
        return 0


# Absolute path to the directory containing spoonmap.py — used to locate
# bundled community NSE scripts under nse/ regardless of the caller's CWD.
_DIR = os.path.dirname(os.path.realpath(__file__))

PROBE_PORT_PRIORITY = [
    '445',   # SMB — near-universal on Windows networks
    '3389',  # RDP — very common on Windows
    '80',    # HTTP — universal
    '443',   # HTTPS — universal
    '22',    # SSH — universal on Linux/network gear
    '135',   # RPC — common on Windows
    '139',   # NetBIOS — common on Windows
    '53',    # DNS — present on many infrastructure hosts
    '25',    # SMTP — common on mail servers
    '8080',  # Alternate HTTP — common
]

# Scripts run on EXTERNAL scans only
EXTERNAL_PORT_SCRIPTS = {
    '21':    'ftp-anon',
    '22':    'ssh-auth-methods,ssh2-enum-algos',
    '23':    'telnet-ntlm-info',
    '25':    'smtp-ntlm-info',
    '110':   'pop3-ntlm-info',
    '143':   'imap-ntlm-info',
    '443':   'ssl-cert',
    '465':   'smtp-ntlm-info,ssl-cert',
    '587':   'smtp-ntlm-info',
    '636':   'ssl-cert',
    '993':   'imap-ntlm-info,ssl-cert',
    '995':   'pop3-ntlm-info,ssl-cert',
    '1433':  'ms-sql-ntlm-info',
    '3389':  'rdp-ntlm-info',
    '2375':  'docker-version',
    '4243':  'docker-version',
    '4786':  f'{_DIR}/nse/cisco-siet.nse',
    '8443':  'ssl-cert',
    '10443': 'ssl-cert',
}

# Scripts run on INTERNAL scans only (no ssl-cert — not relevant for internal assessments)
INTERNAL_PORT_SCRIPTS = {
    '21':    'ftp-anon',
    '111':   'rpcinfo,nfs-showmount,nfs-ls',
    '139':   'smb-security-mode',
    '445':   'smb-security-mode,smb2-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067,smb-double-pulsar-backdoor,smb-vuln-cve-2017-7494',
    '2375':  'docker-version',
    '4243':  'docker-version',
    '1090':  'rmi-dumpregistry',
    '1433':  'ms-sql-info',
    '3389':  'rdp-enum-encryption,rdp-vuln-ms12-020',
    '4786':  f'{_DIR}/nse/cisco-siet.nse',
    'U:1434': 'ms-sql-info',
}

# Deprecated/weak SSH algorithms used by the ssh2-enum-algos finding check
WEAK_SSH_ALGOS = {
    'encrypt': {'arcfour', 'arcfour128', 'arcfour256',
                'aes128-cbc', 'aes192-cbc', 'aes256-cbc',
                '3des-cbc', 'blowfish-cbc', 'cast128-cbc'},
    'mac':     {'hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96',
                'hmac-ripemd160'},
    'kex':     {'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1'},
}

# Ports that should never be directly internet-facing; (port_string, severity, label)
EXTERNAL_SENSITIVE_PORTS = [
    ('445',   'HIGH', 'SMB — should not be internet-facing'),
    ('139',   'HIGH', 'NetBIOS Session Service — should not be internet-facing'),
    ('135',   'HIGH', 'MS-RPC — should not be internet-facing'),
    ('389',   'HIGH', 'LDAP — should not be internet-facing'),
    ('636',   'HIGH', 'LDAPS — should not be internet-facing'),
    ('1433',  'HIGH', 'MSSQL — database port should not be internet-facing'),
    ('1521',  'HIGH', 'Oracle — database port should not be internet-facing'),
    ('3306',  'HIGH', 'MySQL — database port should not be internet-facing'),
    ('5432',  'HIGH', 'PostgreSQL — database port should not be internet-facing'),
    ('6379',  'HIGH', 'Redis — database port should not be internet-facing'),
    ('9200',  'HIGH', 'Elasticsearch — should not be internet-facing'),
    ('27017', 'HIGH', 'MongoDB — database port should not be internet-facing'),
    ('111',   'HIGH', 'RPC/NFS — should not be internet-facing'),
    ('U:161', 'HIGH', 'SNMP — should not be internet-facing'),
    ('161',   'HIGH', 'SNMP — should not be internet-facing'),
    ('3389',  'HIGH', 'RDP — direct internet exposure is high risk'),
    ('21',    'HIGH', 'FTP — should not be exposed unless wrapped in SSL/SSH'),
    ('23',    'HIGH', 'Telnet — unencrypted, should not be internet-facing'),
    ('U:137', 'HIGH', 'NetBIOS Name Service — should not be internet-facing'),
    ('7001',  'HIGH', 'WebLogic — admin/app server port should not be internet-facing'),
    ('7002',  'HIGH', 'WebLogic — admin/app server SSL port should not be internet-facing'),
    ('2375',  'CRITICAL', 'Docker API — unauthenticated remote access should never be internet-facing'),
    ('4243',  'CRITICAL', 'Docker API — unauthenticated remote access should never be internet-facing'),
]

SERVICE_CATEGORIES = {
    'Web': [
        '80', '443', '7001', '7002', '8000', '8080', '8081', '8443', '8888', '9090', '10443'
    ],
    'Database': [
        '1433', 'U:1434', '1521', '3306', '5432', '6379', '9200', '27017'
    ],
    'Remote Management': [
        '22', '23', '3389', '5900', '5901', '6129', '1723', '5985', '5986'
    ],
    'Email': [
        '25', '110', '143', '465', '587', '993', '995'
    ],
    'Authentication': [
        '389', '636', '445', '135', '139', 'U:137'
    ],
    'Network Infrastructure': [
        '53', '179', '500', 'U:500', '161', 'U:161'
    ],
    'File Transfer': [
        '21', '111'
    ],
    'Specialized': [
        '1090', '3300', '4786', '6970', '2375', '4243'
    ],
}


def _scan_extra_sql_ports(output_path, source_port):
    """Scan SQL Server named instances discovered on non-standard ports."""
    discovered = {}  # {host_ip: [port, ...]}

    for fname in ('port1433.xml', 'portU:1434.xml'):
        fpath = f'{output_path}/nmap_results/{fname}'
        if not os.path.exists(fpath):
            continue
        try:
            root = etree.parse(fpath)
            for host in root.findall('host'):
                ip = host.findall('address')[0].attrib['addr']
                for script in host.iter('script'):
                    if script.attrib.get('id') != 'ms-sql-info':
                        continue
                    # Each <table> under the script represents one instance
                    for instance_table in script.findall('table/table'):
                        tcp_elem = instance_table.find("elem[@key='tcp']")
                        if tcp_elem is not None and tcp_elem.text not in ('1433', None):
                            discovered.setdefault(ip, []).append(tcp_elem.text)
        except Exception as e:
            print('\x1b[31m' + f'Warning: could not parse {fname} for SQL instances: {e}' + '\x1b[0m')

    for ip, ports in discovered.items():
        for port in ports:
            out_file = f'{output_path}/nmap_results/port{port}_sql.xml'
            if os.path.exists(out_file):
                continue
            print('\x1b[33m' + f'Discovered SQL Server instance on {ip}:{port} — running nmap -sV...' + '\x1b[0m')
            term_state = save_terminal_state()
            try:
                proc = subprocess.Popen([
                    'nmap', '-T4', '-sS', '-sV', '--version-intensity', '0',
                    '-Pn', '-p', port, '--source-port', source_port,
                    ip, '-oX', out_file
                ])
                proc.wait()
            except Exception as e:
                print('\x1b[31m' + f'Error scanning SQL port {port}: {e}' + '\x1b[0m')
            finally:
                restore_terminal_state(term_state)


SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']


def generate_findings(output_path, target_scan):
    """Parse nmap script output and write findings.txt and findings.md."""
    nmap_dir = f'{output_path}/nmap_results'
    if not os.path.exists(nmap_dir):
        return

    findings = []  # list of (severity, host, port_str, title, detail)

    # ── helpers ──────────────────────────────────────────────────────────────
    def add(sev, host, port, title, detail=''):
        findings.append((sev, host, str(port), title, detail))

    def scripts_for_elem(elem):
        """Return dict of {script_id: output} for a port or hostscript element."""
        return {s.attrib['id']: s.attrib.get('output', '')
                for s in elem.findall('script')}

    def port_str_from_fname(fname):
        """Derive a port string from a filename like port445.xml or portU:1434.xml."""
        stem = fname.replace('.xml', '').lstrip('port')
        # Strip optional _sql or other suffixes after the port number/key
        stem = re.sub(r'_\w+$', '', stem)
        if stem.startswith('U:'):
            return f'udp/{stem[2:]}'
        return f'tcp/{stem}'

    # ── parse every nmap XML result file ─────────────────────────────────────
    open_ports_by_host = {}  # {ip: [port_key, ...]} — for external exposure check

    for fname in sorted(os.listdir(nmap_dir)):
        if not fname.endswith('.xml'):
            continue
        fpath = f'{nmap_dir}/{fname}'
        try:
            root = etree.parse(fpath)
        except Exception:
            continue

        file_port_str = port_str_from_fname(fname)

        for host in root.findall('host'):
            addr_elem = host.find("address[@addrtype='ipv4']")
            if addr_elem is None:
                addr_elem = host.findall('address')[0]
            ip = addr_elem.attrib['addr']

            for port_elem in host.iter('port'):
                portid   = port_elem.attrib.get('portid', '')
                protocol = port_elem.attrib.get('protocol', 'tcp')
                port_key = f'U:{portid}' if protocol == 'udp' else portid
                port_str = f'{protocol}/{portid}'

                open_ports_by_host.setdefault(ip, []).append(port_key)
                scripts  = scripts_for_elem(port_elem)

                # ── ftp-anon ─────────────────────────────────────────────
                if 'ftp-anon' in scripts:
                    out = scripts['ftp-anon']
                    if 'Anonymous FTP login allowed' in out:
                        add('HIGH', ip, port_str, 'Anonymous FTP',
                            'Anonymous FTP login is permitted.')

                # ── ssh-auth-methods (external) ──────────────────────────
                if 'ssh-auth-methods' in scripts and target_scan == 'External':
                    out = scripts['ssh-auth-methods']
                    weak = [m for m in ('password', 'keyboard-interactive')
                            if m in out]
                    if weak:
                        add('HIGH', ip, port_str, 'Weak SSH Authentication',
                            f'Insecure auth method(s) enabled externally: {", ".join(weak)}.')

                # ── ssh2-enum-algos (external) ────────────────────────────
                if 'ssh2-enum-algos' in scripts and target_scan == 'External':
                    out = scripts['ssh2-enum-algos']
                    found_weak = []
                    for category, weak_set in WEAK_SSH_ALGOS.items():
                        for algo in weak_set:
                            if algo in out:
                                found_weak.append(algo)
                    if found_weak:
                        add('MEDIUM', ip, port_str, 'Weak SSH Algorithms',
                            f'Deprecated algorithm(s) offered: {", ".join(sorted(found_weak))}.')

                # ── *-ntlm-info (external only) ───────────────────────────
                if target_scan == 'External':
                    for sid, out in scripts.items():
                        if sid.endswith('-ntlm-info') and out.strip():
                            detail = out.strip().replace('\n', ' | ')[:200]
                            add('HIGH', ip, port_str, 'NTLM Information Disclosure',
                                f'Internal host details exposed: {detail}')

                # ── nfs-showmount / nfs-ls ────────────────────────────────
                for sid in ('nfs-showmount', 'nfs-ls'):
                    if sid in scripts and target_scan == 'Internal':
                        out = scripts[sid].strip()
                        if out:
                            add('HIGH', ip, port_str, 'NFS Shares Exposed',
                                f'NFS mount points visible: {out[:200]}')

                # ── docker-version (unauthenticated Docker API) ───────────
                if 'docker-version' in scripts:
                    out = scripts['docker-version'].strip()
                    if out:
                        add('CRITICAL', ip, port_str, 'Unauthenticated Docker API',
                            f'Docker API is accessible without authentication — '
                            f'full container control and likely host root via escape. {out[:150]}')

                # ── rmi-dumpregistry ──────────────────────────────────────
                if 'rmi-dumpregistry' in scripts and target_scan == 'Internal':
                    out = scripts['rmi-dumpregistry'].strip()
                    if out:
                        add('MEDIUM', ip, port_str, 'Java RMI Registry Exposed',
                            f'RMI objects: {out[:200]}')

                # ── rdp-enum-encryption ───────────────────────────────────
                if 'rdp-enum-encryption' in scripts and target_scan == 'Internal':
                    out = scripts['rdp-enum-encryption']
                    weak_rdp = ('Classic RDP' in out or
                                'CredSSP support: false' in out.lower() or
                                'CredSSP support: False' in out)
                    if weak_rdp:
                        add('MEDIUM', ip, port_str, 'Weak RDP Encryption',
                            'Classic RDP encryption or NLA not enforced.')

                # ── rdp-vuln-ms12-020 ─────────────────────────────────────
                if 'rdp-vuln-ms12-020' in scripts and target_scan == 'Internal':
                    out = scripts['rdp-vuln-ms12-020']
                    if 'VULNERABLE' in out and 'NOT VULNERABLE' not in out:
                        add('CRITICAL', ip, port_str, 'MS12-020 RDP (CVE-2012-0002)',
                            'Host is vulnerable to unauthenticated RDP RCE/DoS (MS12-020). '
                            'Apply MS12-020 patch immediately or disable RDP.')

                # ── Dameware on port 6129 ─────────────────────────────────
                if portid == '6129':
                    svc = port_elem.find('service')
                    if svc is not None:
                        svc_text = ' '.join([
                            svc.attrib.get('name', ''),
                            svc.attrib.get('product', ''),
                            svc.attrib.get('version', ''),
                        ]).lower()
                        if 'dameware' in svc_text:
                            add('HIGH', ip, port_str, 'Dameware Remote Control Detected',
                                'Service banner identifies DameWare Mini Remote Control. '
                                'Manual validation needed for CVE-2019-3980 (unauthenticated RCE). '
                                'Ref: https://github.com/tenable/poc/blob/master/Solarwinds/Dameware/dwrcs_dwDrvInst_rce.py')

                # ── SAP Gateway on port 3300 ─────────────────────────────
                if portid == '3300' and protocol == 'tcp':
                    add('HIGH', ip, port_str, 'SAP Gateway Detected',
                        'Port 3300 is used by SAP Gateway. May be vulnerable to unauthenticated '
                        'remote code execution. '
                        'Ref: https://github.com/chipik/SAP_GW_RCE_exploit')

                # ── Cisco Smart Install on port 4786 ─────────────────────
                # Only flag when cisco-siet.nse confirms the protocol —
                # bare port detection is too noisy (false positives).
                if portid == '4786' and protocol == 'tcp':
                    csi_out = scripts.get('cisco-siet', '')
                    if csi_out and 'NOT VULNERABLE' not in csi_out and 'VULNERABLE' in csi_out:
                        add('HIGH', ip, port_str, 'Cisco Smart Install Vulnerable',
                            'Confirmed via cisco-siet probe (CVE-2018-0171): device accepts '
                            'unauthenticated Smart Install commands, enabling arbitrary '
                            'configuration changes and file read/write. '
                            'Disable with: no vstack')

                # ── Cisco CUCM TFTP on port 6970 ─────────────────────────
                if portid == '6970' and protocol == 'tcp':
                    add('HIGH', ip, port_str, 'Cisco CUCM TFTP Detected',
                        'Port 6970 is used by Cisco Unified Communications Manager TFTP. '
                        'May be vulnerable to credential theft via SeeYouCM-Thief. '
                        'Ref: https://github.com/trustedsec/SeeYouCM-Thief')

                # ── ssl-cert — expired (External only) ───────────────────
                if 'ssl-cert' in scripts and target_scan == 'External':
                    out = scripts['ssl-cert']
                    m = re.search(r'Not valid after:\s+(\d{4}-\d{2}-\d{2})', out)
                    if m:
                        expiry = datetime.date.fromisoformat(m.group(1))
                        if expiry < datetime.date.today():
                            add('MEDIUM', ip, port_str, 'Expired TLS Certificate',
                                f'Certificate expired on {expiry}.')

            # ── host-level scripts (smb-security-mode, ms-sql-info, etc.) ────
            # These NSE scripts use hostrule and appear under <hostscript>,
            # not inside a <port> element.
            hostscript_elem = host.find('hostscript')
            if hostscript_elem is not None:
                hscripts = scripts_for_elem(hostscript_elem)

                # ── smb-security-mode / smb2-security-mode ────────────────
                for sid in ('smb-security-mode', 'smb2-security-mode'):
                    if sid in hscripts and target_scan == 'Internal':
                        out = hscripts[sid]
                        if 'not required' in out.lower() or 'disabled' in out.lower():
                            proto = 'SMBv1' if sid == 'smb-security-mode' else 'SMBv2'
                            add('HIGH', ip, file_port_str, f'{proto} Signing Not Required',
                                'SMB relay attacks are possible without signing enforcement.')

                # ── smb-security-mode → SMBv1 enabled ────────────────────
                if 'smb-security-mode' in hscripts and target_scan == 'Internal':
                    out = hscripts['smb-security-mode'].strip()
                    if out:
                        add('MEDIUM', ip, file_port_str, 'SMBv1 Enabled',
                            'SMBv1 protocol is active on this host. This legacy protocol '
                            'has known critical vulnerabilities (EternalBlue, MS08-067). '
                            'Disable SMBv1 immediately.')

                # ── smb-vuln-ms17-010 (EternalBlue) ──────────────────────
                if 'smb-vuln-ms17-010' in hscripts and target_scan == 'Internal':
                    out = hscripts['smb-vuln-ms17-010']
                    if 'VULNERABLE' in out and 'NOT VULNERABLE' not in out:
                        add('CRITICAL', ip, file_port_str, 'MS17-010 EternalBlue (CVE-2017-0143)',
                            'Host is vulnerable to unauthenticated SMBv1 RCE (EternalBlue). '
                            'Apply MS17-010 patch immediately and disable SMBv1.')

                # ── smb-vuln-ms08-067 (Conficker/NetAPI) ─────────────────
                if 'smb-vuln-ms08-067' in hscripts and target_scan == 'Internal':
                    out = hscripts['smb-vuln-ms08-067']
                    if 'VULNERABLE' in out and 'NOT VULNERABLE' not in out:
                        add('CRITICAL', ip, file_port_str, 'MS08-067 NetAPI (CVE-2008-4250)',
                            'Host is vulnerable to unauthenticated SMB RCE (Conficker vector). '
                            'Apply MS08-067 patch immediately and isolate host.')

                # ── smb-double-pulsar-backdoor ────────────────────────────
                if 'smb-double-pulsar-backdoor' in hscripts and target_scan == 'Internal':
                    out = hscripts['smb-double-pulsar-backdoor']
                    if 'VULNERABLE' in out and 'NOT VULNERABLE' not in out:
                        add('CRITICAL', ip, file_port_str, 'DoublePulsar Backdoor Active',
                            'Host has an active DoublePulsar implant — it has already been '
                            'compromised. Isolate immediately and begin incident response.')

                # ── smb-vuln-cve-2017-7494 (SambaCry) ────────────────────
                if 'smb-vuln-cve-2017-7494' in hscripts and target_scan == 'Internal':
                    out = hscripts['smb-vuln-cve-2017-7494']
                    if 'VULNERABLE' in out and 'NOT VULNERABLE' not in out:
                        add('CRITICAL', ip, file_port_str, 'SambaCry (CVE-2017-7494)',
                            'Samba is vulnerable to unauthenticated RCE via a writable share '
                            '(SambaCry). Update Samba immediately.')

                # ── ms-sql-info ───────────────────────────────────────────
                if 'ms-sql-info' in hscripts and target_scan == 'Internal':
                    out = hscripts['ms-sql-info'].strip()
                    if out:
                        add('INFO', ip, file_port_str, 'SQL Server Instance Discovered',
                            out[:300])

    # ── external exposure findings (port list, no script needed) ─────────────
    if target_scan == 'External':
        for ip, open_keys in open_ports_by_host.items():
            for port_key, severity, label in EXTERNAL_SENSITIVE_PORTS:
                if port_key in open_keys:
                    proto = 'udp' if port_key.startswith('U:') else 'tcp'
                    pnum  = port_key[2:] if port_key.startswith('U:') else port_key
                    add(severity, ip, f'{proto}/{pnum}',
                        'Service Exposed Externally', label)

    # ── sort and write ────────────────────────────────────────────────────────
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f[0]), f[1], f[2]))

    _write_findings_txt(output_path, target_scan, findings)
    _write_findings_md(output_path, target_scan, findings)
    print('\x1b[33m' + f'\nFindings written to {output_path}/findings.txt and findings.md' + '\x1b[0m')


# ── Reproduce commands and sample output for each finding type ────────────────
_FINDING_REPRO = {
    'MS17-010 EternalBlue (CVE-2017-0143)': {
        'flags': '--script smb-vuln-ms17-010',
        'sample': (
            'PORT    STATE SERVICE\n'
            '445/tcp open  microsoft-ds\n'
            '| smb-vuln-ms17-010:\n'
            '|   VULNERABLE:\n'
            '|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)\n'
            '|     State: VULNERABLE\n'
            '|     IDs:  CVE:CVE-2017-0143\n'
            '|     Risk factor: HIGH\n'
            '|     References:\n'
            '|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx\n'
            '|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143'
        ),
    },
    'MS08-067 NetAPI (CVE-2008-4250)': {
        'flags': '--script smb-vuln-ms08-067',
        'sample': (
            'PORT    STATE SERVICE\n'
            '445/tcp open  microsoft-ds\n'
            '| smb-vuln-ms08-067:\n'
            '|   VULNERABLE:\n'
            '|   Microsoft Windows system vulnerable to remote code execution (MS08-067)\n'
            '|     State: LIKELY VULNERABLE\n'
            '|     IDs:  CVE:CVE-2008-4250\n'
            '|     References:\n'
            '|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250'
        ),
    },
    'DoublePulsar Backdoor Active': {
        'flags': '--script smb-double-pulsar-backdoor',
        'sample': (
            'PORT    STATE SERVICE\n'
            '445/tcp open  microsoft-ds\n'
            '| smb-double-pulsar-backdoor:\n'
            '|   DoublePulsar SMB backdoor is INSTALLED\n'
            '|   Architecture: x64\n'
            '|_  XOR Key: 0xAB12CD34'
        ),
    },
    'SambaCry (CVE-2017-7494)': {
        'flags': '--script smb-vuln-cve-2017-7494',
        'sample': (
            'PORT    STATE SERVICE\n'
            '445/tcp open  netbios-ssn\n'
            '| smb-vuln-cve-2017-7494:\n'
            '|   VULNERABLE:\n'
            '|   SAMBA Remote Code Execution from Writable Share\n'
            '|     State: VULNERABLE\n'
            '|     IDs:  CVE:CVE-2017-7494\n'
            '|_  References: https://www.samba.org/samba/security/CVE-2017-7494.html'
        ),
    },
    'MS12-020 RDP (CVE-2012-0002)': {
        'flags': '--script rdp-vuln-ms12-020',
        'sample': (
            'PORT     STATE SERVICE\n'
            '3389/tcp open  ms-wbt-server\n'
            '| rdp-vuln-ms12-020:\n'
            '|   VULNERABLE:\n'
            '|   MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability\n'
            '|     State: VULNERABLE\n'
            '|     IDs:  CVE:CVE-2012-0002\n'
            '|_    Risk factor: HIGH'
        ),
    },
    'Unauthenticated Docker API': {
        'flags': '--script docker-version',
        'sample': (
            'PORT     STATE SERVICE\n'
            '2375/tcp open  docker\n'
            '| docker-version:\n'
            '|   Version: 24.0.5\n'
            '|   API Version: 1.43\n'
            '|   Go Version: go1.20.6\n'
            '|   Git Commit: a61e2b4\n'
            '|   OS: linux\n'
            '|_  Architecture: amd64'
        ),
    },
    'Service Exposed Externally': {
        'flags': '-sV',
        'sample': (
            'PORT     STATE SERVICE VERSION\n'
            '3306/tcp open  mysql   MySQL 8.0.32'
        ),
    },
    'Anonymous FTP': {
        'flags': '--script ftp-anon',
        'sample': (
            'PORT   STATE SERVICE\n'
            '21/tcp open  ftp\n'
            '| ftp-anon: Anonymous FTP login allowed (FTP code 230)\n'
            '|_drwxr-xr-x  2 ftp ftp 4096 Jan 15 12:00 pub'
        ),
    },
    'Weak SSH Authentication': {
        'flags': '--script ssh-auth-methods',
        'sample': (
            'PORT   STATE SERVICE\n'
            '22/tcp open  ssh\n'
            '| ssh-auth-methods:\n'
            '|   Supported authentication methods:\n'
            '|     publickey\n'
            '|     password\n'
            '|_    keyboard-interactive'
        ),
    },
    'NTLM Information Disclosure': {
        'flags': '--script "*-ntlm-info"',
        'sample': (
            'PORT    STATE SERVICE\n'
            '445/tcp open  microsoft-ds\n'
            '| smb-ntlm-info:\n'
            '|   Target_Name: CORP\n'
            '|   NetBIOS_Domain_Name: CORP\n'
            '|   NetBIOS_Computer_Name: DC01\n'
            '|   DNS_Domain_Name: corp.local\n'
            '|_  DNS_Computer_Name: DC01.corp.local'
        ),
    },
    'SMBv1 Signing Not Required': {
        'flags': '--script smb-security-mode',
        'sample': (
            'PORT    STATE SERVICE\n'
            '445/tcp open  microsoft-ds\n'
            '| smb-security-mode:\n'
            '|   account_used: guest\n'
            '|   authentication_level: user\n'
            '|   challenge_response: supported\n'
            '|_  message_signing: disabled (dangerous, but default)'
        ),
    },
    'SMBv2 Signing Not Required': {
        'flags': '--script smb2-security-mode',
        'sample': (
            'PORT    STATE SERVICE\n'
            '445/tcp open  microsoft-ds\n'
            '| smb2-security-mode:\n'
            '|   3.1.1:\n'
            '|_    Message signing enabled but not required'
        ),
    },
    'SMBv1 Enabled': {
        'flags': '--script smb-security-mode',
        'sample': (
            'PORT    STATE SERVICE\n'
            '445/tcp open  microsoft-ds\n'
            '| smb-security-mode:\n'
            '|   account_used: guest\n'
            '|   authentication_level: user\n'
            '|   challenge_response: supported\n'
            '|_  message_signing: required'
        ),
    },
    'NFS Shares Exposed': {
        'flags': '--script nfs-showmount,nfs-ls',
        'sample': (
            'PORT    STATE SERVICE\n'
            '111/tcp open  rpcbind\n'
            '| nfs-showmount:\n'
            '|   /exports  *\n'
            '|   /home     10.0.0.0/24\n'
            '| nfs-ls: Volume /exports\n'
            '|   access: Read Lookup NoModify NoExtend NoDelete NoExecute\n'
            '|   drwxr-xr-x  2  1000  1000  4096  Jan 15 12:00  .\n'
            '|_  -rw-r--r--  1  1000  1000  1024  Jan 15 12:00  data.csv'
        ),
    },
    'Dameware Remote Control Detected': {
        'flags': '-sV',
        'sample': (
            'PORT     STATE SERVICE  VERSION\n'
            '6129/tcp open  dameware DameWare Remote Control 12.0'
        ),
    },
    'SAP Gateway Detected': {
        'flags': '-sV',
        'sample': (
            'PORT     STATE SERVICE  VERSION\n'
            '3300/tcp open  sapgw00  SAP Gateway'
        ),
    },
    'Cisco Smart Install Vulnerable': {
        'flags': '-sV',
        'sample': (
            'PORT     STATE SERVICE  VERSION\n'
            '4786/tcp open  smart-install  Cisco Smart Install (VULNERABLE)'
        ),
    },
    'Cisco CUCM TFTP Detected': {
        'flags': '-sV',
        'sample': (
            'PORT     STATE SERVICE  VERSION\n'
            '6970/tcp open  tftp     Cisco Unified Communications Manager TFTP'
        ),
    },
    'Weak SSH Algorithms': {
        'flags': '--script ssh2-enum-algos',
        'sample': (
            'PORT   STATE SERVICE\n'
            '22/tcp open  ssh\n'
            '| ssh2-enum-algos:\n'
            '|   kex_algorithms: (8)\n'
            '|       diffie-hellman-group1-sha1 -- [info] removed in OpenSSH 8.8\n'
            '|       diffie-hellman-group14-sha1\n'
            '|   encryption_algorithms: (8)\n'
            '|       3des-cbc -- [info] disabled in OpenSSH 6.7\n'
            '|       aes128-cbc\n'
            '|   mac_algorithms: (10)\n'
            '|_      hmac-md5 -- [info] disabled in OpenSSH 6.7'
        ),
    },
    'Weak RDP Encryption': {
        'flags': '--script rdp-enum-encryption',
        'sample': (
            'PORT     STATE SERVICE\n'
            '3389/tcp open  ms-wbt-server\n'
            '| rdp-enum-encryption:\n'
            '|   Security layer\n'
            '|     CredSSP (NLA): SUCCESS\n'
            '|     SSL: SUCCESS\n'
            '|_    Native RDP: SUCCESS'
        ),
    },
    'Java RMI Registry Exposed': {
        'flags': '--script rmi-dumpregistry',
        'sample': (
            'PORT     STATE SERVICE\n'
            '1090/tcp open  java-rmi\n'
            '| rmi-dumpregistry:\n'
            '|   jmxrmi\n'
            '|     javax.management.remote.rmi.RMIServerImpl_Stub\n'
            '|_  @10.0.0.5:36721'
        ),
    },
    'Expired TLS Certificate': {
        'flags': '--script ssl-cert',
        'sample': (
            'PORT    STATE SERVICE\n'
            '443/tcp open  https\n'
            '| ssl-cert: Subject: commonName=example.corp\n'
            '| Not valid before: 2021-01-01T00:00:00\n'
            '|_Not valid after:  2022-01-01T00:00:00'
        ),
    },
    'SQL Server Instance Discovered': {
        'flags': '--script ms-sql-info',
        'sample': (
            'PORT     STATE SERVICE\n'
            '1433/tcp open  ms-sql-s\n'
            '| ms-sql-info:\n'
            '|   10.0.0.5\\MSSQLSERVER:\n'
            '|     Instance name: MSSQLSERVER\n'
            '|     Version:\n'
            '|       name: Microsoft SQL Server 2019 RTM\n'
            '|       number: 15.00.2000.00\n'
            '|_      Product: Microsoft SQL Server 2019'
        ),
    },
}


def _build_repro_cmd(title, port_str, host):
    """Build an nmap command to reproduce a finding."""
    parts = port_str.split('/', 1)
    if len(parts) != 2:
        return f'nmap -sV {host}  # could not parse port from "{port_str}"'
    proto, pnum = parts
    flags = _FINDING_REPRO.get(title, {}).get('flags', '-sV')
    udp_flag = '-sU ' if proto == 'udp' else ''
    return f'nmap {udp_flag}-p {pnum} {flags} {host}'


def _write_findings_txt(output_path, target_scan, findings):
    today = datetime.date.today()
    lines = [
        '=' * 60,
        'SpooNMAP Security Findings Report',
        '=' * 60,
        f'Scan Type:  {target_scan}',
        f'Date:       {today}',
        f'Output Dir: {output_path}',
        '',
    ]

    # Group by (severity, title, port_str) so all hosts with the same
    # vulnerability on the same port are together for easy copy-paste.
    groups = {}  # (sev, title, port_str) → list[host]
    for sev, host, port_str, title, _detail in findings:
        key = (sev, title, port_str)
        groups.setdefault(key, []).append(host)

    for sev in SEVERITY_ORDER:
        sev_keys = sorted(
            [k for k in groups if k[0] == sev],
            key=lambda k: (k[1], k[2]),
        )
        if not sev_keys:
            continue
        lines += [sev, '-' * len(sev), '']
        for key in sev_keys:
            _, title, port_str = key
            hosts = groups[key]
            repro = _FINDING_REPRO.get(title, {})
            lines.append(f'  [{title}]  port {port_str}')
            lines.append(f'  Affected hosts ({len(hosts)}):')
            for h in sorted(hosts):
                lines.append(h)
            lines.append('')
            if repro:
                cmd = _build_repro_cmd(title, port_str, hosts[0])
                lines.append('  Reproduce:')
                lines.append(f'    {cmd}')
                lines.append('')
                lines.append('  Sample output:')
                for sample_line in repro['sample'].splitlines():
                    lines.append(f'    {sample_line}')
                lines.append('')
            lines.append('  ' + '-' * 56)
            lines.append('')

    lines.append(f'Total findings: {len(findings)}')
    with open(f'{output_path}/findings.txt', 'w') as fh:
        fh.write('\n'.join(lines) + '\n')


def _write_findings_md(output_path, target_scan, findings):
    today = datetime.date.today()
    lines = [
        '# SpooNMAP Security Findings Report',
        '',
        f'**Scan:** {target_scan} | **Date:** {today}',
        '',
    ]
    for sev in SEVERITY_ORDER:
        group = [f for f in findings if f[0] == sev]
        if not group:
            continue
        lines += [f'## {sev}', '']
        # Sub-group by finding title, preserving first-seen insertion order
        by_title: dict = {}
        for _, host, port, title, detail in group:
            by_title.setdefault(title, []).append((host, port, detail))
        for title, rows in by_title.items():
            lines += [f'### {title}', '',
                      '| Host | Port | Detail |',
                      '|------|------|--------|']
            for host, port, detail in rows:
                detail_safe = detail.replace('|', '\\|')
                lines.append(f'| `{host}` | {port} | {detail_safe} |')
            lines.append('')
    lines.append(f'**Total findings:** {len(findings)}')
    with open(f'{output_path}/findings.md', 'w') as fh:
        fh.write('\n'.join(lines) + '\n')


def _cleanup_cmd(dir_path):
    """Handle --cleanup: remove prior scan output from output_path and exit."""
    idx = sys.argv.index('--cleanup')
    cleanup_path = None
    if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith('-'):
        cleanup_path = sys.argv[idx + 1]
    else:
        cfg_file = os.path.join(dir_path, 'config.json')
        if os.path.exists(cfg_file):
            with open(cfg_file) as fh:
                cfg = json.load(fh)
            cleanup_path = cfg.get('output_path', '')
            if cleanup_path and not os.path.isabs(cleanup_path):
                cleanup_path = os.path.join(dir_path, cleanup_path)

    if not cleanup_path:
        print('Usage: spoonmap.py --cleanup [output_path]')
        print('  output_path defaults to output_path in config.json')
        sys.exit(1)

    if not os.path.isdir(cleanup_path):
        print(f'Directory not found: {cleanup_path}')
        sys.exit(1)

    if not _previous_results_exist(cleanup_path):
        print(f'No scan data found in {cleanup_path}')
        sys.exit(0)

    _delete_previous_results(cleanup_path)
    print(f'Scan data removed from {cleanup_path}')
    sys.exit(0)


@contextlib.contextmanager
def _path_completion():
    """Enable filesystem tab-completion for a single input() call.

    Uses readline when available; silently skips on platforms without it
    (e.g. Windows without pyreadline).  The completer is reset to None
    on exit so it doesn't bleed into unrelated prompts.
    """
    try:
        import readline

        def _completer(text, state):
            pattern = os.path.expanduser(text) + '*'
            matches = _glob.glob(pattern)
            # Append '/' to directories so the user can keep tabbing deeper
            matches = [m + '/' if os.path.isdir(m) else m for m in matches]
            return matches[state] if state < len(matches) else None

        readline.set_completer_delims(' \t\n')
        readline.set_completer(_completer)
        readline.parse_and_bind('tab: complete')
        yield
    except ImportError:
        yield
    finally:
        try:
            readline.set_completer(None)  # type: ignore[name-defined]
        except Exception:
            pass


# The Main Guts
def main():
    global dir_path
    global output_path

    # Save initial terminal state
    initial_term_state = save_terminal_state()

    try:
        ascii_art()

        scan_type = ''
        dest_ports = []
        banner_scan = ''
        script_scan = ''
        target_scan = ''
        source_port = '53'
        max_rate = ''
        target_file = ''
        exclusions_file = ''
        status_summary = ''
        output_path = ''
        nmap_threads = 5  # Default number of concurrent NMAP threads
        masscan_batch_size = 5  # Default number of ports per masscan invocation


        # Get options from configuration file if it exists
        dir_path = os.path.dirname(os.path.realpath(__file__))

        if '--cleanup' in sys.argv:
            _cleanup_cmd(dir_path)  # prints result and exits
        if os.path.exists(f'{dir_path}/config.json'):
            with open(f'{dir_path}/config.json') as config:
                config_parser = json.load(config)

            scan_categories = config_parser.get('scan_categories', 'All')
            if scan_categories == 'All' or scan_categories == ['All']:
                scan_type = 'All'
                all_ports = [p for cat in SERVICE_CATEGORIES.values() for p in cat]
            elif scan_categories in ('Full', ['Full']):
                scan_type = 'Full'
                all_ports = ['1-65535']
            elif isinstance(scan_categories, list):
                valid = [c for c in scan_categories if c in SERVICE_CATEGORIES]
                scan_type = ', '.join(valid)
                all_ports = [p for name in valid for p in SERVICE_CATEGORIES[name]]
            else:
                all_ports = []
            # UDP ports sorted to end of batch
            dest_ports = [p for p in all_ports if not p.startswith('U:')] + \
                         [p for p in all_ports if p.startswith('U:')]
            # Allow dest_ports override for fully custom use
            if config_parser.get('dest_ports'):
                dest_ports = config_parser['dest_ports']
                scan_type = 'Custom'
            banner_scan = config_parser['banner_scan']
            if banner_scan == 'True':
                banner_scan = True
            else:
                banner_scan = False
            target_scan = config_parser['target_scan']
            max_rate = config_parser['max_rate']
            target_file = config_parser['target_file']
            output_path = config_parser['output_path']
            exclusions_file = config_parser['exclusions_file']
            nmap_threads = config_parser.get('nmap_threads', 5)
            masscan_batch_size = config_parser.get('masscan_batch_size', 5)
            script_scan = config_parser.get('script_scan', 'False') == 'True'

            # Resolve relative paths in config relative to the script directory
            if target_file and not os.path.isabs(target_file):
                target_file = os.path.join(dir_path, target_file)
            if output_path and not os.path.isabs(output_path):
                output_path = os.path.join(dir_path, output_path)
            if exclusions_file and not os.path.isabs(exclusions_file):
                exclusions_file = os.path.join(dir_path, exclusions_file)

        if scan_type == '':
            category_names = list(SERVICE_CATEGORIES.keys())
            while True:
                print('\nService Categories (comma-separated numbers, default: All)')
                for i, name in enumerate(category_names, 1):
                    ports = SERVICE_CATEGORIES[name]
                    print(f'\t({i}) {name}  [{", ".join(ports)}]')
                print(f'\t(9) Full Port Scan  [1-65535]')

                selection = input(
                    f'\nWhich categories would you like to scan (e.g. 1,3 — default: All)? '
                ).strip()

                if selection in ('9', 'full', 'f'):
                    scan_type = 'Full'
                    dest_ports = ['1-65535']
                    break

                if not selection:
                    # Default: all categories
                    scan_type = 'All'
                    all_ports = [p for cat in SERVICE_CATEGORIES.values() for p in cat]
                    dest_ports = [p for p in all_ports if not p.startswith('U:')] + \
                                 [p for p in all_ports if p.startswith('U:')]
                    break

                # Parse comma-separated indices
                try:
                    indices = [int(x.strip()) for x in selection.split(',')]
                    if all(1 <= i <= len(category_names) for i in indices):
                        selected = [category_names[i - 1] for i in indices]
                        scan_type = ', '.join(selected)
                        all_ports = [p for name in selected for p in SERVICE_CATEGORIES[name]]
                        dest_ports = [p for p in all_ports if not p.startswith('U:')] + \
                                     [p for p in all_ports if p.startswith('U:')]
                        break
                except ValueError:
                    pass
                # Invalid input — loop again

        if banner_scan == '':
            banner_choice = 1
            banner_choice = input(
                f'\nWould you like to enumerate service banners for any identified services '
                f'(default: Yes)? '
                ) or banner_choice
            if banner_choice == 1 or banner_choice[0].lower() == 'y':
                banner_scan = True
            else:
                banner_scan = False

        if script_scan == '':
            if banner_scan:
                script_choice = 'n'
                script_choice = input(
                    '\nWould you like to run NSE security scripts on identified services '
                    '(default: No)? '
                ) or script_choice
                script_scan = script_choice[0].lower() == 'y'
            else:
                script_scan = False

        # NSE scripts require banner scanning
        if script_scan:
            banner_scan = True

        if not target_scan:
            source_choice = '1'
            while True:
                print('\nTarget Scan')
                print('\t(1) External')
                print('\t(2) Internal')
                source_choice = input(
                    f'\nIs this an internal or external scan '
                    f'(default: External)? '
                    ) or source_choice
                if source_choice == '1':
                    target_scan = 'External'
                    source_port = '53'
                    break
                elif source_choice == '2':
                    target_scan = 'Internal'
                    source_port = '88'
                    break

        if not max_rate:
            if target_scan == "External":
                max_rate = '10000'
            else:
                max_rate = '1000'
            while True:
                try:
                    rate_choice = input(f'\nHow fast would you like to scan '
                        f'(default: {max_rate} packets/second)? '
                        ) or max_rate
                    if int(rate_choice):
                        max_rate = rate_choice
                        break
                except ValueError:
                    pass

        if not output_path:
            output_path = dir_path
            with _path_completion():
                output_path = input(f'\nPlease enter full path for output '
                    f'(default: {dir_path}): '
                    ) or output_path
            os.makedirs(output_path, exist_ok=True)

        if not target_file:
            target_file = output_path+"/ranges.txt"
            while True:
                print(target_file)
                print('\nExample Target File')
                print('One CIDR or IP Address per line\n')
                print('\t192.168.0.0/24')
                print('\t192.168.1.23')
                with _path_completion():
                    target_file = input(f'\nPlease enter the full path for the file '
                        f'containing target hosts (default: {target_file}): '
                        ) or target_file

                if os.path.exists(target_file):
                    break

        if not exclusions_file:
            exclusions_choice = 'n'
            exclusions_choice = input(f'\nWould you like to exclude any hosts?  (default: No) '
                ) or exclusions_choice

            if exclusions_choice[0].lower() == 'y':
                exclusions_file = f'{dir_path}/exclusions.txt'
                while True:
                    print('\nExample Exclusions File')
                    print('One CIDR or IP Address per line\n')
                    print('\t192.168.0.0/24')
                    print('\t192.168.1.23')
                    with _path_completion():
                        exclusions_file = input(f'\nPlease enter the full path for the file '
                            f'containing excluded hosts if applicable (default: {dir_path}/{exclusions_file}): '
                            ) or exclusions_file

                    if os.path.exists(exclusions_file):
                        break
                    else:
                        print('\x1b[31m' + f'Error: File not found: {exclusions_file}' + '\x1b[0m')
            else:
                exclusions_file = None
    
        print(f'\nScan Type: {scan_type}')
        print(f'Target Ports: {dest_ports}')
        print(f'Service Banner: {banner_scan}')
        print(f'NSE Script Scanning: {script_scan}')
        print(f'Source Port: {source_port}')
        print(f'Masscan Max Packet Rate (pps): {max_rate}')
        print(f'Target File: {target_file}')
        print(f'Exclusions File: {exclusions_file}')
        print(f'NMAP Concurrent Threads: {nmap_threads}')
        print(f'Masscan Batch Size: {masscan_batch_size}\n')

        # Detect previous scan results and ask whether to delete or append
        if _previous_results_exist(output_path):
            print('\x1b[33m' + '\nPrevious scan results detected in output directory.' + '\x1b[0m')
            while True:
                choice = input('Delete previous results or append to them? '
                               '[d]elete / [a]ppend (default: append): ').strip().lower() or 'a'
                if choice and choice[0] in ('d', 'a'):
                    break
            if choice[0] == 'd':
                _delete_previous_results(output_path)
                print('\x1b[33m' + 'Previous results deleted.' + '\x1b[0m')
            else:
                print('\x1b[33m' + 'Appending to previous results.' + '\x1b[0m')

        # Preprocess targets to handle hostnames
        masscan_target_file, ip_to_hostname = preprocess_targets(target_file, output_path)

        status_summary = mass_scan(scan_type, dest_ports, source_port, max_rate, masscan_target_file, exclusions_file, masscan_batch_size)

        # If service banners requested, send to nmap
        if banner_scan or script_scan:
            nmap_scan(source_port, nmap_threads, ip_to_hostname, script_scan, target_scan)

            if script_scan and target_scan == 'Internal':
                _scan_extra_sql_ports(output_path, source_port)

        # Combine all live hosts into one file
        all_ips = set()
        if os.path.exists(f'{output_path}/live_hosts'):
            host_files = os.listdir(f'{output_path}/live_hosts')
            for host_file in host_files:
                with open(f'{output_path}/live_hosts/{host_file}') as input_file:
                    for line in input_file:
                        all_ips.add(line)
            with open(f'{output_path}/all_live_hosts.txt', 'w') as output_file:
                for ip in all_ips:
                    output_file.write(ip)

            # Combine all XML results into one file
            if banner_scan or script_scan:
                result_dir = f'{output_path}/nmap_results/'
            else:
                result_dir = f'{output_path}/masscan_results/'
            xml_result = '<?xml version="1.0"?>\n<!-- SpooNMAP -->\n<nmaprun>\n'
            xml_files = os.listdir(result_dir)
            for xml_file in xml_files:
                root = etree.parse(result_dir + xml_file)
                hosts = root.findall('host')
                for host in hosts:
                    xml_result += etree.tostring(host, encoding="unicode", method="xml")
            xml_result += '</nmaprun>'
            with open(f'{output_path}/spoonmap_output.xml', 'w+') as spoonmap_output:
                spoonmap_output.write(xml_result)
            print('\x1b[33m' + f'\nResults written to {output_path}/spoonmap_output.xml' + '\x1b[0m')

            if script_scan:
                generate_findings(output_path, target_scan)

        else:
            status_summary += '\nNo hosts found.'

        # Print Summary
        print('\x1b[33m' + status_summary + '\x1b[0m')


    finally:
        # Always restore terminal state on exit
        restore_terminal_state(initial_term_state)

# Boilerplate
if __name__ == '__main__':
    verify_python_version()
    main()

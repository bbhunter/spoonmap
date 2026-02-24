#!/usr/bin/env python3

# Author: Spoonman (Larry.Spohn@TrustedSec.com)
# QA and Personal Pythonian Consultant: Bandrel (Justin.Bollinger@TrustedSec.com)

import json
import os
from pathlib import Path
import re
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

def mass_scan(scan_type, dest_ports, source_port, max_rate, target_file, exclusions_file, batch_size=5):
    status_summary = '\nSummary'

    if not os.path.exists(f'{output_path}/masscan_results'):
        os.makedirs(f'{output_path}/masscan_results')

    # Track unique IPs per port in memory for efficiency
    port_ips = {}

    # Group ports into batches for fewer masscan invocations
    batches = [dest_ports[i:i + batch_size] for i in range(0, len(dest_ports), batch_size)]
    total_batches = len(batches)

    for batch_idx, batch in enumerate(batches):
        batch_label = ', '.join(batch)
        print('\x1b[33m' + f'Scanning ports {batch_label}...' + '\x1b[0m')

        output_file = f'{output_path}/masscan_results/batch_{batch_idx}.xml'

        # Build command as list to prevent shell injection
        masscan_cmd = [
            'masscan',
            '-p', ','.join(batch),
            '--open',
            '--max-rate', max_rate,
            '--source-port', source_port,
            '-iL', target_file,
            '-oX', output_file
        ]

        if exclusions_file:
            masscan_cmd.extend(['--excludefile', exclusions_file])

        # Save terminal state before running masscan
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
            # Always restore terminal state after process completes
            restore_terminal_state(term_state)

        if masscan_process.returncode == 1:
            quit(1)

        # Parse results and distribute IPs to per-port sets
        try:
            if os.stat(output_file).st_size == 0:
                os.remove(output_file)
                print('\x1b[33m' + f'\nNo hosts found in batch {batch_idx + 1}/{total_batches} ({batch_label})')
                print('Masscan Completion Status: ' + '{:.0%}'.format((batch_idx + 1) / total_batches) + '\x1b[0m')
            else:
                root = etree.parse(output_file)
                hosts = root.findall('host')

                # Initialize sets for all ports in this batch, loading existing data for resume
                for dest_port in batch:
                    if dest_port not in port_ips:
                        port_ips[dest_port] = set()
                        live_host_file = f'{output_path}/live_hosts/port{dest_port}.txt'
                        if os.path.exists(live_host_file):
                            with open(live_host_file, 'r') as file:
                                port_ips[dest_port].update(line.strip() for line in file if line.strip())

                # masscan outputs one <host> per (IP, port) pair; read the port from the XML
                for host in hosts:
                    ip_address = host.findall('address')[0].attrib['addr']
                    ports_elem = host.find('ports')
                    if ports_elem is not None:
                        port_elem = ports_elem.find('port')
                        if port_elem is not None:
                            protocol = port_elem.attrib.get('protocol', 'tcp')
                            portid = port_elem.attrib.get('portid', '')
                            port_key = f'U:{portid}' if protocol == 'udp' else portid
                            if port_key in port_ips:
                                port_ips[port_key].add(ip_address)

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

        except etree.ParseError as e:
            print('\x1b[31m' + f'Error parsing XML for batch {batch_idx}: {e}' + '\x1b[0m')
        except Exception as e:
            print('\x1b[31m' + f'Error processing results for batch {batch_idx}: {e}' + '\x1b[0m')

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

def nmap_worker(work_queue, completed_count, total_count, source_port, lock, interrupt_event, ip_to_hostname):
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

def nmap_scan(source_port, max_threads=5, ip_to_hostname=None):
    """
    Perform NMAP scans using multiple threads for efficiency

    Args:
        source_port: Source port to use for scans
        max_threads: Maximum number of concurrent NMAP scans (default: 5)
        ip_to_hostname: Dictionary mapping IPs to hostnames (default: None)
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
                args=(work_queue, completed_count, total_count, source_port, lock, interrupt_event, ip_to_hostname)
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


SERVICE_CATEGORIES = {
    'Web': [
        '80', '443', '8000', '8080', '8081', '8443', '8888', '9090', '10443'
    ],
    'Database': [
        '1433', 'U:1434', '1521', '3306', '5432', '6379', '9200', '27017'
    ],
    'Remote Management': [
        '22', '23', '3389', '5900', '5901', '6129', '1723'
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
        '1090', '3300', '4786', '6970'
    ],
}


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
        if os.path.exists(f'{dir_path}/config.json'):
            with open(f'{dir_path}/config.json') as config:
                config_parser = json.load(config)

            scan_categories = config_parser.get('scan_categories', 'All')
            if scan_categories == 'All' or scan_categories == ['All']:
                scan_type = 'All'
                all_ports = [p for cat in SERVICE_CATEGORIES.values() for p in cat]
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

        if scan_type == '':
            category_names = list(SERVICE_CATEGORIES.keys())
            while True:
                print('\nService Categories (comma-separated numbers, default: All)')
                for i, name in enumerate(category_names, 1):
                    ports = SERVICE_CATEGORIES[name]
                    print(f'\t({i}) {name}  [{", ".join(ports)}]')

                selection = input(
                    f'\nWhich categories would you like to scan (e.g. 1,3 — default: All)? '
                ).strip()

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
            if target_scan == "External" and scan_type == "Small Port Scan":
                max_rate = '20000'
            elif target_scan == "External" and scan_type == "Full Port Scan":
                max_rate = '10000'
            elif target_scan == "Internal" and scan_type == "Small Port Scan":
                max_rate = '2000'
            elif target_scan == "Internal" and scan_type == "Full Port Scan":
                max_rate = '1000'
            else:
                max_rate = '2000'
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
                exclusions_file = 'exclusions.txt'
                while True:
                    print('\nExample Exclusions File')
                    print('One CIDR or IP Address per line\n')
                    print('\t192.168.0.0/24')
                    print('\t192.168.1.23')
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
        print(f'Source Port: {source_port}')
        print(f'Masscan Max Packet Rate (pps): {max_rate}')
        print(f'Target File: {target_file}')
        print(f'Exclusions File: {exclusions_file}')
        print(f'NMAP Concurrent Threads: {nmap_threads}')
        print(f'Masscan Batch Size: {masscan_batch_size}\n')

        # Preprocess targets to handle hostnames
        masscan_target_file, ip_to_hostname = preprocess_targets(target_file, output_path)

        status_summary = mass_scan(scan_type, dest_ports, source_port, max_rate, masscan_target_file, exclusions_file, masscan_batch_size)

        # If service banners requested, send to nmap
        if banner_scan or banner_scan == 'Yes':
            nmap_scan(source_port, nmap_threads, ip_to_hostname)

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
            if banner_scan :
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

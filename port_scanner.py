import subprocess

def run_scan(ip_address, protocol, ports_range):
    print(f"Performing {protocol} scan on ports {ports_range}...")
    args = ['nmap', '-p', ports_range, ip_address, '-oG', '-']
    if protocol == 'UDP':
        args.insert(2, '-sU')
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout

def extract_open_ports(nmap_output):
    open_ports = []
    for line in nmap_output.split('\n'):
        if 'Open' in line or 'open' in line:
            parts = line.split()
            for part in parts:
                if '/open' in part:
                    port_protocol = part.split('/')
                    port = port_protocol[0]
                    open_ports.append(port)
    return open_ports

def detailed_scan(ip_address, ports, protocol):
    if ports:
        port_list = ','.join(ports)
        print(f"Performing detailed {protocol} scan on ports: {port_list}")
        args = ['nmap', '-sV', '-p', port_list, '-sC', ip_address]
        if protocol == 'UDP':
            args.insert(2, '-sU')
        detailed_results = subprocess.run(args, capture_output=True, text=True)
        print(detailed_results.stdout)

def runScan(target_ip_address):
    print(f"Scan start on target IP address: {target_ip_address}")
    all_ports = '1-65535'
    # Perform the initial scans
    tcp_scan_output = run_scan(target_ip_address, 'TCP', all_ports)
    udp_scan_output = run_scan(target_ip_address, 'UDP', '1-1024')  # Limit UDP to well-known ports for practicality

    # Extract open ports from the scan outputs
    open_tcp_ports = extract_open_ports(tcp_scan_output)
    open_udp_ports = extract_open_ports(udp_scan_output)

    # Perform detailed scans on the open ports
    detailed_scan(target_ip_address, open_tcp_ports, 'TCP')
    detailed_scan(target_ip_address, open_udp_ports, 'UDP')
    

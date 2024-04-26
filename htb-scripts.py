import json
from port_scanner import run_scan

def read_target_ip_from_json_file(filepath):
    try:
        with open(filepath, 'r') as file:
            data = json.load(file)  # Load JSON data into a Python dictionary
            target_ip_address = data['network']['target_ip_address']  # Access the target IP address
            return target_ip_address
    except FileNotFoundError:
        print("Error: The file was not found.")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
    except KeyError:
        print("Error: Target IP address not found in JSON file.")
    return None

    scanner = nmap.PortScanner()
    print(f"Scanning TCP and UDP ports on {ip_address}...")

    # Scanning TCP ports
    scanner.scan(ip_address, '1-65535', '-sS')
    print("TCP scan results:")
    for protocol in scanner[ip_address].all_protocols():
        if protocol == 'tcp':
            lport = scanner[ip_address][protocol].keys()
            for port in lport:
                print(f'Port {port}/tcp is {scanner[ip_address][protocol][port]["state"]}')

    # Scanning UDP ports (considered more intrusive and slower, hence scanning only well-known ports)
    scanner.scan(ip_address, '1-1024', '-sU')
    print("UDP scan results:")
    for protocol in scanner[ip_address].all_protocols():
        if protocol == 'udp':
            lport = scanner[ip_address][protocol].keys()
            for port in lport:
                print(f'Port {port}/udp is {scanner[ip_address][protocol][port]["state"]}')

# Usage
config_file_path = 'config.json'
target_ip_address = read_target_ip_from_json_file(config_file_path)
if target_ip_address:
    print(f"The target IP address is: {target_ip_address}")
else:
    print("Failed to read target IP address.")

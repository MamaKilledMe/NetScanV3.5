#!/usr/bin/env python3

import threading
import socket
import ipaddress
import sys
import subprocess
import os

from scapy.all import ARP, Ether, srp, conf
import netifaces
from mac_vendor_lookup import MacLookup
import nmap
from tabulate import tabulate

# Initialize MacLookup
mac_lookup = MacLookup()

# Specify the full path to nmap.exe
nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"

def check_nmap_installation():
    if not os.path.isfile(nmap_path):
        print(f"Nmap executable not found at {nmap_path}. Please install Nmap or update the path in the script.")
        sys.exit(1)
    else:
        try:
            # Hide the command window when running subprocess
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            nmap_version_output = subprocess.check_output(
                [nmap_path, '--version'],
                universal_newlines=True,
                startupinfo=startupinfo
            )
            print("Nmap version detected:")
            print(nmap_version_output)
        except Exception as e:
            print(f"Error executing Nmap: {e}")
            sys.exit(1)

def get_default_interface():
    # Get the default gateway
    gateways = netifaces.gateways()
    default_gateway = gateways.get('default')
    if default_gateway is None or netifaces.AF_INET not in default_gateway:
        print("No default gateway found.")
        sys.exit(1)
    default_gateway_ip, default_iface_name = default_gateway[netifaces.AF_INET]
    print(f"Default gateway: {default_gateway_ip}, Interface: {default_iface_name}")
    return default_iface_name

def get_network_cidr(interface_name):
    addrs = netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]
    ip_addr = addrs['addr']
    netmask = addrs['netmask']
    network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
    return str(network)

def get_scapy_interface(netifaces_iface_name):
    # Keep the braces in the GUID and convert to lowercase
    iface_guid = netifaces_iface_name.lower()
    
    # Iterate over Scapy interfaces to find a matching GUID
    for iface in conf.ifaces.values():
        scapy_iface_guid = iface.guid.lower() if iface.guid else ''
        if iface_guid == scapy_iface_guid:
            return iface.name
    print("Could not find matching Scapy interface.")
    sys.exit(1)

def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout):
        hostname = 'Unknown'
    return hostname

def scan_network(cidr, scapy_iface_name):
    print(f"\nScanning network: {cidr}")
    # Set Scapy to use the correct network interface
    conf.iface = scapy_iface_name
    arp_request = ARP(pdst=cidr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    # Reduce timeout to speed up scanning if appropriate
    answered_list = srp(packet, timeout=2, verbose=False)[0]

    clients = []

    for sent, received in answered_list:
        ip_address = received.psrc
        mac_address = received.hwsrc
        hostname = resolve_hostname(ip_address)
        try:
            vendor = mac_lookup.lookup(mac_address)
        except KeyError:
            vendor = 'Unknown Vendor'
        clients.append({
            'ip': ip_address,
            'mac': mac_address,
            'hostname': hostname,
            'vendor': vendor
        })

    return clients

def scan_ports(client, nm):
    ip = client['ip']
    try:
        # Optimize Nmap scan arguments for speed
        nm.scan(
            ip,
            arguments='-Pn -T4 --max-retries 1 --min-parallelism 100',
            sudo=False
        )
        ports = []
        if 'tcp' in nm[ip]:
            for port in nm[ip]['tcp']:
                service = nm[ip]['tcp'][port]['name']
                state = nm[ip]['tcp'][port]['state']
                ports.append(f"{port}/tcp ({service}, {state})")
        client['ports'] = ', '.join(ports) if ports else 'No open ports found'
    except Exception as e:
        client['ports'] = 'Scan error'
        print(f"Error scanning {ip}: {e}")

def run_port_scans(clients):
    print("\nScanning open ports and services...")
    nm = nmap.PortScanner(nmap_search_path=(nmap_path,))

    threads = []
    for client in clients:
        thread = threading.Thread(target=scan_ports, args=(client, nm))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def display_results(clients):
    headers = ["IP Address", "Hostname", "MAC Address", "Vendor", "Open Ports"]
    table = []
    for client in clients:
        table.append([
            client['ip'],
            client['hostname'],
            client['mac'],
            client['vendor'],
            client.get('ports', 'Not scanned')
        ])
    print("\nAvailable devices on the network:")
    print(tabulate(table, headers=headers, tablefmt="pretty"))

if __name__ == "__main__":
    # Check if Nmap is installed
    check_nmap_installation()

    # Monkey-patch subprocess.Popen to hide command windows
    import types

    def hide_subprocess_popen(*args, **kwargs):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs['startupinfo'] = startupinfo
        return original_popen(*args, **kwargs)

    original_popen = subprocess.Popen
    subprocess.Popen = hide_subprocess_popen

    # Get the default network interface
    netifaces_iface_name = get_default_interface()

    # Get the network CIDR
    cidr = get_network_cidr(netifaces_iface_name)

    # Get the corresponding Scapy interface name
    scapy_iface_name = get_scapy_interface(netifaces_iface_name)

    # Scan the network
    clients = scan_network(cidr, scapy_iface_name)

    # Scan open ports and services on each client using Nmap
    run_port_scans(clients)

    # Display the results
    display_results(clients)



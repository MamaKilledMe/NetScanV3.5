# NetScanV3.5
Network Scanner V3.5

NetScan V3.5
Network Scanner V3.5 is a powerful and efficient Python-based tool for scanning and discovering devices on a local network. It performs an ARP scan to identify all connected devices, retrieves their MAC addresses, hostnames, and vendors, and integrates Nmap to scan for open ports and services on each discovered device. The tool is optimized for performance, uses multithreading, and suppresses command window popups on Windows systems.

Features:
Device Discovery: Identifies all active devices on the local network using ARP scans.
MAC Vendor Lookup: Retrieves the vendor information for each MAC address.
Hostname Resolution: Automatically resolves hostnames for each device.
Open Port Scanning: Uses Nmap to scan for open ports and services on each discovered device.
Multithreaded Scanning: Efficiently scans multiple devices in parallel to speed up the process.
Command Window Suppression: On Windows systems, Nmap scans are run without showing command prompt windows.
Tabulated Output: Displays results in a well-formatted table for easy reading.

Requirements:
Python 3.6+
Nmap (Ensure that the Nmap executable is installed and added to your system's PATH)
Required Python libraries:
scapy
netifaces
mac-vendor-lookup
python-nmap
tabulate

You can install these dependencies with the following command:
pip install scapy netifaces mac-vendor-lookup python-nmap tabulate

Usage:
Install Nmap: Make sure Nmap is installed on your system and accessible via the command line. You can download it from here.

Clone this Repository:
git clone https://github.com/MamaKilledMe/NetScanV3.5.git
Then:
cd NetScanV3.5

Run the Script:
python NetScanV3.5.py

View the Results: The script will automatically detect your default network interface, scan the local network, and display the discovered devices along with their IP addresses, MAC addresses, vendors, and any open ports.

Example Output:
Nmap version detected:
Nmap version 7.95 ( https://nmap.org )

Scanning network: 192.168.1.0/24

Scanning open ports and services...

Available devices on the network:
+----------------+----------------------+---------------------+-----------------------------+-----------------------------------------+
| IP Address     | Hostname             | MAC Address         | Vendor                      | Open Ports                              |
+----------------+----------------------+---------------------+-----------------------------+-----------------------------------------+
| 192.168.1.1    | router.local         | 08:B4:B1:27:A9:0C   | Google, Inc.                | 80/tcp (http), 443/tcp (https)          |
| 192.168.1.10   | desktop.local        | C8:58:C0:25:89:F1   | Intel Corporate             | 135/tcp (msrpc), 445/tcp (microsoft-ds) |
| 192.168.1.25   | raspberrypi.local    | D8:3A:DD:2C:4C:5F   | Raspberry Pi Trading Ltd.   | 22/tcp (ssh), 80/tcp (http)             |
+----------------+----------------------+---------------------+-----------------------------+-----------------------------------------+

Important Notes:
Use with Permission: Ensure you have permission to scan the network you are on. Unauthorized network scanning may violate local laws or organizational policies.
Run as Administrator: On some systems, administrative privileges may be required to perform network scanning tasks.
Windows Compatibility: The script has been optimized to hide command prompt windows on Windows systems during Nmap execution.

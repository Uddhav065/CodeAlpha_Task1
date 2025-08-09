# CodeAlpha_Task1
This basic network sniffer built to capture and analyze network traffic. It uses the Scapy library to listen for packets and dissect their layered structure, providing key insights into network communication.
The tool is ideal for educational purposes, security analysis, and network troubleshooting.
 The sniffer can perform the following tasks:
Capture live network packets.
Dissect packets to reveal their layered structure.
Display key information such as source/destination IPs, ports, and protocols.
Filter packets based on specific criteria to focus on relevant traffic.
-----------------------------------------------------------------------------------------------
 Features:
Cross-Platform Compatibility: The script is designed to run on Windows, Linux, and macOS.
Protocol Analysis: It can identify and display information for common protocols, including IP, TCP, UDP, and ICMP.
Configurable Sniffing: You can control the number of packets to capture or set a time limit.
Packet Filtering: Supports Berkeley Packet Filter (BPF) syntax for efficient traffic filtering.
------------------------------------------------------------------------------------------------
Before running the sniffer, you need to have the following installed:

Python 3: Make sure you have Python 3 installed on your system.

Scapy: A powerful Python library for packet manipulation. You can install it using pip:
------pip install scapy---------

Npcap (for Windows only):
On Windows, Scapy requires an underlying packet capture driver. Npcap is the recommended driver. 
Make sure to install it from the official Npcap website and check the "Support Npcap in WinPcap API-compatible Mode" box during installation.

------How to Run-----------

To run the sniffer, you must have administrator or root privileges. This is a security requirement for all network sniffing programs.
Open a terminal or command prompt with administrator rights:
Windows: Search for cmd or PowerShell, right-click, and select "Run as administrator."
Linux/macOS: Use sudo before the python command.
Navigate to the project directory:

==-----cd /path/to/your/project------
Run the script with the desired options:

Basic run (captures 10 packets):

==------python Scappy_sniffer.py -c 10-------
Sniff for 30 seconds:

==------python Scappy_sniffer.py -t 30-------

Filter for TCP traffic on port 80 (HTTP):

==------python Scappy_sniffer.py -f "tcp port 80"------
Capture and save packets to a file:

==------python Scappy_sniffer.py -c 50 -s my_capture.pcap------
Load and analyze packets from a saved file (no admin privileges needed for this):

==------python Scappy_sniffer.py -l my_capture.pcap------

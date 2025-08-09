from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, wrpcap, rdpcap # type: ignore
import sys
import datetime


def packet_analyzer(packet):
    """
    This function is called for every packet captured.
    It analyzes and displays relevant information from the packet.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] # Get current timestamp

    print(f"\n[{timestamp}] --- New Packet Captured ---")

    # Check for Ethernet Layer (Layer 2)
    if packet.haslayer(Ether):
        eth_layer = packet[Ether]
        print(f"  Ethernet: {eth_layer.src} -> {eth_layer.dst}")

    # Check for IP Layer (Layer 3)
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol_name = "Unknown"
        if ip_layer.proto == 6: # TCP protocol number
            protocol_name = "TCP"
        elif ip_layer.proto == 17: # UDP protocol number
            protocol_name = "UDP"
        elif ip_layer.proto == 1: # ICMP protocol number
            protocol_name = "ICMP"
        elif ip_layer.proto == 2: # IGMP protocol number
            protocol_name = "IGMP" 

        print(f"  IP: {ip_layer.src} -> {ip_layer.dst} | Protocol: {protocol_name}")

        # Check for TCP Layer (Layer 4 - Transport)
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"    TCP: {tcp_layer.sport} -> {tcp_layer.dport} | Flags: {tcp_layer.flags}")
            
            if hasattr(tcp_layer, 'load') and tcp_layer.load:
                
                pass 
        
        # Check for UDP Layer (Layer 4 - Transport)
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"    UDP: {udp_layer.sport} -> {udp_layer.dport}")
            # Optional: Display a glimpse of the UDP payload
            if hasattr(udp_layer, 'load') and udp_layer.load:
                # print(f"    Payload (UDP): {udp_layer.load[:30]}...") # First 30 bytes
                pass

        # Check for ICMP Layer (Layer 4 - Network utility)
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print(f"    ICMP: Type={icmp_layer.type}, Code={icmp_layer.code}")

    elif packet.haslayer(Ether): 
        if packet.type == 0x0806: 
            print(f"  ARP Packet detected.")

# --- 2. Main Sniffer Function ---
def start_sniffer(interface=None, count=0, timeout=None, pkt_filter="", save_file=None):
    
    print(f"\n--- Starting Network Sniffer ---")
    print(f"  Interface: {interface if interface else 'Default'}")
    print(f"  Packets to capture: {'Infinite' if count == 0 else count}")
    print(f"  Timeout: {timeout if timeout else 'None'}")
    print(f"  Filter: '{pkt_filter if pkt_filter else 'None (capturing all IP traffic)'}'")
    if save_file:
        print(f"  Captured packets will be saved to: '{save_file}'")

    captured_packets = []
    try:
        
        effective_filter = pkt_filter if pkt_filter else "ip" 

        packets = sniff(iface=interface, count=count, timeout=timeout,
                        prn=packet_analyzer, store=True, filter=effective_filter)
        captured_packets.extend(packets) # Add captured packets to our list

    except KeyboardInterrupt:
        print("\n--- Sniffer stopped by user (Ctrl+C) ---")
    except Exception as e:
        print(f"\n--- An error occurred: {e} ---")
        print("Hint: You might need root/administrator privileges (e.g., 'sudo python your_script.py').")
        print("Also, check if the specified interface exists.")
    finally:
        print("\n--- Sniffer session finished ---")
        if save_file and captured_packets:
            print(f"Saving {len(captured_packets)} packets to {save_file}...")
            wrpcap(save_file, captured_packets)
            print("Packets saved successfully.")
        elif save_file and not captured_packets:
            print("No packets were captured to save.")

# --- 3. Example Usage ---
if __name__ == "__main__":
    print("Welcome to your Basic Network Sniffer!")
    print("--------------------------------------")
    print("You can specify parameters or use defaults.")
    print("Examples:")
    print("  To sniff 10 packets: `python sniffer.py -c 10`")
    print("  To sniff for 30 seconds: `python sniffer.py -t 30`")
    print("  To sniff HTTP traffic: `python sniffer.py -f \"tcp port 80\"`")
    print("  To sniff and save to file: `python sniffer.py -s my_capture.pcap`")
    print("  To specify an interface (e.g., `eth0` or `Wi-Fi`): `python sniffer.py -i eth0`")
    print("  Remember to run with admin/root privileges (e.g., `sudo python sniffer.py`)")


    # --- Parse command-line arguments for flexibility ---
    # This section allows you to run the script with different settings directly from the terminal
    import argparse
    parser = argparse.ArgumentParser(description="A basic network sniffer built with Scapy.")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g., 'eth0', 'Wi-Fi')", default=None)
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-t", "--timeout", type=int, default=None, help="Duration in seconds to sniff")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string (e.g., 'tcp port 80')")
    parser.add_argument("-s", "--save", help="Filename to save captured packets to (e.g., 'capture.pcap')", default=None)
    parser.add_argument("-l", "--load", help="Load and display packets from a PCAP file instead of sniffing", default=None)

    args = parser.parse_args()

    if args.load:
        # If the user wants to load from a file, do that instead of sniffing
        print(f"\n--- Loading packets from '{args.load}' ---")
        try:
            loaded_packets = rdpcap(args.load)
            print(f"Successfully loaded {len(loaded_packets)} packets.")
            for i, pkt in enumerate(loaded_packets):
                print(f"\n--- Packet {i+1} from file ---")
                packet_analyzer(pkt) # Use the same analyzer function
        except FileNotFoundError:
            print(f"Error: File '{args.load}' not found.")
        except Exception as e:
            print(f"Error loading PCAP file: {e}")
    else:
        # Otherwise, start the live sniffer
        start_sniffer(interface=args.interface, count=args.count,
                      timeout=args.timeout, pkt_filter=args.filter,
                      save_file=args.save)

    print("\nThanks for using this Sniffer project! ")
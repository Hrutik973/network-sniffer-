import sys
import platform
from scapy.all import sniff, TCP, IP, conf, get_if_list

# Function to handle each packet
def handle_packet(packet, log):
    if packet.haslayer(IP) and packet.haslayer(TCP):  # Ensure IP and TCP layers are present
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")

# Function to get available network interfaces
def list_available_interfaces():
    available_interfaces = get_if_list()
    print(f"Available network interfaces from Scapy: {available_interfaces}")
    
    if not available_interfaces:
        print("No interfaces found. Trying alternative method...")
        # For Windows, use the 'ipconfig' command to fetch interfaces
        if platform.system() == 'Windows':
            import subprocess
            result = subprocess.run("ipconfig", capture_output=True, text=True)
            available_interfaces = [line.split(":")[1].strip() for line in result.stdout.splitlines() if "Wi-Fi" in line or "Ethernet" in line]
            print(f"Interfaces found via ipconfig: {available_interfaces}")
    
    return available_interfaces

# Main function to start packet sniffing
def main(interface, verbose=False):
    import re
    sanitized_interface = re.sub(r'[\\/:*?"<>|]', '_', interface)
    logfile_name = f"sniffer_{sanitized_interface}_log.txt"
    try:
        with open(logfile_name, 'w') as logfile:
            available_interfaces = list_available_interfaces()

            if interface not in available_interfaces:
                print(f"Error: Interface '{interface}' is not valid.")
                print(f"Please ensure you choose one of the following interfaces: {available_interfaces}")
                sys.exit(1)

            sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0, verbose=verbose)
    except IOError as e:
        print(f"Error opening log file {logfile_name}: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("Packet sniffing stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python pdcket_sniffer.py <interface> [verbose]")
        sys.exit(1)
    
    verbose = len(sys.argv) == 3 and sys.argv[2].lower() == "verbose"
    interface = sys.argv[1]
    
    main(interface, verbose)

from scapy.all import sniff, IP, TCP, UDP, Ether

# Function to process each captured packet
def process_packet(packet):
    print("\n--- Packet Captured ---")

    # Check if the packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip}")

        # Check if the packet has a TCP layer
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Protocol: TCP | Source Port: {src_port} | Destination Port: {dst_port}")

        # Check if the packet has a UDP layer
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Protocol: UDP | Source Port: {src_port} | Destination Port: {dst_port}")

        # Print payload data (first 100 bytes)
        if packet.haslayer(Raw):
            payload = packet[Raw].load[:100]  # Limit payload to first 100 bytes
            print(f"Payload (first 100 bytes): {payload}")

    # Print Ethernet layer information (optional)
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        print(f"Source MAC: {src_mac} | Destination MAC: {dst_mac}")

# Start sniffing packets
def start_sniffer(interface="eth0", count=0):
    print(f"Starting packet sniffer on interface {interface}...")
    sniff(iface=interface, prn=process_packet, count=count)

# Main program
if __name__ == "__main__":
    # Replace "eth0" with your network interface (use `ifconfig` to check)
    interface = "eth0"
    # Set `count=0` to capture indefinitely, or set a specific number of packets
    start_sniffer(interface=interface, count=10)

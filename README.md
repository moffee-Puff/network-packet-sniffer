# Network Packet Sniffer

A simple Python-based network packet sniffer built for Kali Linux. This tool captures and analyzes network traffic, providing insights into packets such as source/destination IP addresses, protocols, and payload data.

---

## How It Works

The packet sniffer uses the `scapy` library to capture and analyze network packets. Here's what it does:

1. **Packet Capture**:
   - The tool listens on a specified network interface (e.g., `eth0` or `wlan0`).
   - It captures packets in real-time as they travel through the network.

2. **Packet Analysis**:
   - For each captured packet, the tool extracts key information:
     - **Source IP**: The IP address of the sender.
     - **Destination IP**: The IP address of the receiver.
     - **Protocol**: The network protocol used (e.g., TCP, UDP, ICMP).
     - **Payload**: The raw data being transmitted (if applicable).

3. **Output**:
   - The tool prints the extracted information to the terminal in a readable format.

---

## How to Use

### Prerequisites
- Kali Linux (or any Linux distribution with Python 3).
- Python 3.x.
- The `scapy` library (install using `pip`).

### Installation

1. **Install Scapy**:
   ```bash
   sudo apt update
   sudo apt install python3-pip
   pip3 install scapy

 2. **Clone the Repository**:
   ```bash
git clone https://github.com/yourusername/network-packet-sniffer.git
cd network-packet-sniffer


 3. **Run the Script**:
   ```bash
sudo python3 packet_sniffer.py



4. **Specify the Network Interface**:
When prompted, enter the network interface you want to sniff (e.g., eth0, wlan0).

The tool will start capturing and displaying packets.
```bash
$ sudo python3 packet_sniffer.py
Enter the network interface to sniff (e.g., eth0, wlan0): wlan0
[*] Starting packet capture on wlan0...

[+] Packet Captured:
    Source IP: 192.168.1.100
    Destination IP: 192.168.1.1
    Protocol: TCP
    Payload: b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'

[+] Packet Captured:
    Source IP: 192.168.1.1
    Destination IP: 192.168.1.100
    Protocol: UDP
    Payload: b'\x00\x01\x02\x03'

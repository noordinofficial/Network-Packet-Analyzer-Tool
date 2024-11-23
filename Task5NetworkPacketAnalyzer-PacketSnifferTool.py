from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from datetime import datetime

# Global variables for statistics
packet_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}


def analyze_packet(packet):
    """
    Analyze each captured packet and log its details.
    """
    global packet_count

    if IP in packet:
        protocol = "Other"
        if TCP in packet:
            protocol = "TCP"
            packet_count["TCP"] += 1
        elif UDP in packet:
            protocol = "UDP"
            packet_count["UDP"] += 1
        elif ICMP in packet:
            protocol = "ICMP"
            packet_count["ICMP"] += 1
        else:
            packet_count["Other"] += 1

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        payload = bytes(packet[TCP].payload) if TCP in packet else "N/A"
        print(f"[{protocol}] {src_ip} -> {dst_ip} | Payload: {payload}")
        log_packet(f"[{protocol}] {src_ip} -> {dst_ip} | Payload: {payload}")

    elif ARP in packet:
        protocol = "ARP"
        packet_count["ARP"] += 1
        print(f"[{protocol}] {packet[ARP].psrc} -> {packet[ARP].pdst}")
        log_packet(f"[{protocol}] {packet[ARP].psrc} -> {packet[ARP].pdst}")
    else:
        packet_count["Other"] += 1


def log_packet(packet_info):
    """
    Save packet details to a log file.
    """
    with open("packets.log", "a") as log_file:
        log_file.write(f"{datetime.now()} - {packet_info}\n")


def start_sniffer(protocol_filter=None, interface="en0"):
    """
    Start the packet sniffer with optional filtering and interface.
    """
    print("Starting Packet Sniffer...")
    print(f"Filter: {protocol_filter if protocol_filter else 'None'}")
    print(f"Interface: {interface}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff_filter = None
        if protocol_filter:
            sniff_filter = f"{protocol_filter}"

        sniff(prn=analyze_packet, store=False, filter=sniff_filter, iface=interface)
    except KeyboardInterrupt:
        print("\nPacket Sniffer stopped.")
        generate_summary()


def generate_summary():
    """
    Generate and display a summary of captured packets.
    """
    print("\nSummary of Captured Packets:")
    for protocol, count in packet_count.items():
        print(f"{protocol}: {count}")
    print("\nCaptured packets are logged in 'packets.log'.")


if __name__ == "__main__":
    print("Welcome to the Advanced Packet Sniffer Tool!")
    print("Choose your options below:")

    # User input for filter
    protocol_filter = input(
        "Enter a protocol to filter (e.g., tcp, udp, icmp, arp) or press Enter for no filter: ").lower() or None

    # Default interface is set to "en0" (active on macOS)
    interface = "en0"

    # Start the sniffer
    start_sniffer(protocol_filter, interface)

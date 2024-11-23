# Network Packet Analyzer

## Overview
The **Network Packet Analyzer** is a tool developed to capture and analyze network packets in real time. It extracts and displays crucial information such as source and destination IP addresses, protocol types (TCP, UDP, ICMP, ARP), and packet payload data. This tool is designed for **educational purposes only** and emphasizes the importance of ethical use in network security and monitoring.

---

## Features
1. **Real-Time Packet Capture**:
   - Captures packets traveling through the specified network interface.
2. **Protocol Identification**:
   - Categorizes packets by protocol (TCP, UDP, ICMP, ARP, or Other).
3. **Packet Logging**:
   - Saves packet details to a log file (`packets.log`) for later analysis.
4. **Interactive Filtering**:
   - Allows users to filter packets by protocol (e.g., TCP or UDP).
5. **User-Friendly CLI**:
   - Offers a simple and interactive command-line interface.
6. **Summary Report**:
   - Displays a summary of captured packets by protocol after the sniffing session.

---

## How It Works
1. **Packet Sniffing**:
   - The tool uses the `scapy` library's `sniff` function to monitor and capture network traffic on a specific interface.
   - Users can specify protocol filters to narrow down the captured traffic (e.g., capture only TCP packets).

2. **Packet Analysis**:
   - For each captured packet:
     - **Source and Destination IPs** are extracted from the IP layer.
     - **Protocol Type** is identified (e.g., TCP, UDP, ICMP, ARP).
     - **Payload Data** is extracted and displayed, if available.

3. **Packet Logging**:
   - All captured packet details are logged to a file named `packets.log` with timestamps for auditing.

4. **Summary Report**:
   - At the end of the session, the tool summarizes the total number of packets captured for each protocol.

---

## Example

### Input:
- Run the tool with `tcp` as the filter and `en0` as the network interface.

### Output (Terminal):
Starting Packet Sniffer... Filter: tcp Interface: en0 Press Ctrl+C to stop.

### Output (Log File):
Contents of `packets.log`:

---

## Installation and Setup

### Prerequisites
- **Python 3.x** installed on your system.
- **Scapy Library**:
   Install using pip:
   pip install scapy
## Ethical Disclaimer
This tool is strictly for educational purposes. Unauthorized usage of packet sniffers to monitor network traffic without consent is illegal and can lead to serious legal consequences. Use this tool responsibly on networks you own or have explicit permission to monitor.


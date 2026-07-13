# ==========================================================
# Project : Network Traffic Detection System
# File    : capture_v6.py
# Module  : 6 - Suspicious Traffic Detection (Basic IDS)
# Author  : Pradeep Tunga
# ==========================================================

from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# Packet Counter
packet_number = 0

# Dictionary to count packets from each Source IP
packet_counter = {}

# Alert Threshold
THRESHOLD = 5

# Dictionary for Port Scan Detection
port_scan = {}

# Alert threshold
PORT_SCAN_THRESHOLD = 10

# Store alerted IPs
port_scan_alerted = set()


def packet_callback(packet):

    global packet_number

    packet_number += 1

    if packet.haslayer(IP):

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        protocol_number = packet[IP].proto

        # Convert protocol number to protocol name
        if protocol_number == 6:
            protocol = "TCP"

        elif protocol_number == 17:
            protocol = "UDP"

        elif protocol_number == 1:
            protocol = "ICMP"

        else:
            protocol = f"Unknown ({protocol_number})"

        # Get Port Numbers
        if packet.haslayer(TCP):

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif packet.haslayer(UDP):

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        else:

            source_port = "N/A"
            destination_port = "N/A"

        packet_length = len(packet)

        current_time = datetime.now().strftime("%I:%M:%S %p")
        
        # ==============================
        # Port Scan Detection
        # ==============================
        
        if destination_port != "N/A":
        # First time seeing this IP
            if source_ip not in port_scan:
                port_scan[source_ip] = set()
            # Add destination port
            port_scan[source_ip].add(destination_port)
        # Check threshold
        if (
            len(port_scan[source_ip]) > PORT_SCAN_THRESHOLD
            and source_ip not in port_scan_alerted
        ):
            print("\n🚨 POSSIBLE PORT SCAN DETECTED 🚨")
            print("Source IP :", source_ip)
            print("Ports Scanned :", len(port_scan[source_ip]))

            port_scan_alerted.add(source_ip)

            with open("alerts.txt", "a") as file:

                file.write("\n===============================\n")
                file.write("PORT SCAN DETECTED\n")
                file.write(f"Source IP : {source_ip}\n")
                file.write(
                f"Ports Scanned : {len(port_scan[source_ip])}\n"
                )
                file.write("===============================\n")

        # ===============================
        # Count packets from each IP
        # ===============================

        if source_ip in packet_counter:

            packet_counter[source_ip] += 1

        else:

            packet_counter[source_ip] = 1

        # ===============================
        # Alert Detection
        # ===============================

        if packet_counter[source_ip] > THRESHOLD:

            print("\n🚨 ALERT 🚨")
            print("Suspicious Activity Detected")
            print("Source IP :", source_ip)
            print("Packets   :", packet_counter[source_ip])
            print()

            # Save Alert
            with open("alerts.txt", "a") as alert_file:

                alert_file.write("\n=============================\n")
                alert_file.write("ALERT\n")
                alert_file.write(f"Time : {current_time}\n")
                alert_file.write(f"Source IP : {source_ip}\n")
                alert_file.write(f"Packets : {packet_counter[source_ip]}\n")
                alert_file.write("=============================\n")

        # ===============================
        # Display Packet
        # ===============================

        print("\n=========================================")
        print("Packet Number     :", packet_number)
        print("Time              :", current_time)
        print("Source IP         :", source_ip)
        print("Destination IP    :", destination_ip)
        print("Protocol          :", protocol)
        print("Source Port       :", source_port)
        print("Destination Port  :", destination_port)
        print("Packet Length     :", packet_length, "Bytes")
        print("=========================================")


print("Network Traffic Detection Started")
print("Capturing first 20 packets...\n")

sniff(prn=packet_callback)

print("\nCapture Completed!")
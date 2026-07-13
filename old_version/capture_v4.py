# ==========================================================
# Project : Network Traffic Detection System
# File    : capture_v4.py
# Author  : Pradeep Tunga
# Module  : 4 - Port Analysis
# ==========================================================

# Import required modules
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# Packet Counter
packet_number = 0


# Function called whenever a packet is captured
def packet_callback(packet):

    global packet_number
    packet_number += 1

    # Check whether packet has IP layer
    if packet.haslayer(IP):

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        protocol_number = packet[IP].proto

        # Convert Protocol Number to Name
        if protocol_number == 6:
            protocol = "TCP"

        elif protocol_number == 17:
            protocol = "UDP"

        elif protocol_number == 1:
            protocol = "ICMP"

        else:
            protocol = "Unknown"

        # -----------------------------------
        # Extract Port Numbers
        # -----------------------------------

        # If packet is TCP
        if packet.haslayer(TCP):

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        # If packet is UDP
        elif packet.haslayer(UDP):

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        # ICMP doesn't use ports
        else:

            source_port = "N/A"
            destination_port = "N/A"

        packet_length = len(packet)

        current_time = datetime.now().strftime("%I:%M:%S %p")

        print("\n================================================")
        print("Packet Number     :", packet_number)
        print("Capture Time      :", current_time)
        print("Source IP         :", source_ip)
        print("Destination IP    :", destination_ip)
        print("Protocol          :", protocol)
        print("Source Port       :", source_port)
        print("Destination Port  :", destination_port)
        print("Packet Length     :", packet_length, "Bytes")
        print("================================================")


print("Network Traffic Detection Started...")
print("Capturing first 10 packets...\n")

sniff(prn=packet_callback, count=10)

print("\nPacket Capture Completed!")
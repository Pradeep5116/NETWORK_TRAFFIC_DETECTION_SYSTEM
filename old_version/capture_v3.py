# ==========================================================
# Project : Network Traffic Detection System
# File    : capture_v3.py
# Author  : Pradeep Tunga
# Task    : Display Protocol Name and Capture Time
# ==========================================================

# Import required modules
from scapy.all import sniff, IP
from datetime import datetime

# Packet counter
packet_number = 0


# This function is called whenever a packet is captured
def packet_callback(packet):

    global packet_number
    packet_number += 1

    # Process only IP packets
    if packet.haslayer(IP):

        # Source IP Address
        source_ip = packet[IP].src

        # Destination IP Address
        destination_ip = packet[IP].dst

        # Protocol Number
        protocol_number = packet[IP].proto

        # Convert protocol number to protocol name
        if protocol_number == 6:
            protocol_name = "TCP"

        elif protocol_number == 17:
            protocol_name = "UDP"

        elif protocol_number == 1:
            protocol_name = "ICMP"

        else:
            protocol_name = "Unknown"

        # Packet Size
        packet_length = len(packet)

        # Current Time
        current_time = datetime.now().strftime("%I:%M:%S %p")

        print("\n================================================")
        print("Packet Number    :", packet_number)
        print("Capture Time     :", current_time)
        print("Source IP        :", source_ip)
        print("Destination IP   :", destination_ip)
        print("Protocol         :", protocol_name)
        print("Packet Length    :", packet_length, "Bytes")
        print("================================================")


print("Network Traffic Detection Started...")
print("Capturing first 10 packets...\n")

sniff(prn=packet_callback, count=10)

print("\nPacket Capture Completed!")
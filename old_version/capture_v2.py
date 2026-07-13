# ==========================================================
# Network Traffic Detection System
# Task 2 - Display Detailed Packet Information
# Author : Pradeep Tunga
# ==========================================================

# Import sniff() and IP class from Scapy
from scapy.all import sniff, IP


# Variable to count packets
packet_number = 0


# This function is called every time a packet is captured
def packet_callback(packet):

    # Access the global variable so we can update it
    global packet_number

    # Increase packet count by 1
    packet_number += 1

    # Check whether the packet contains an IP layer
    if packet.haslayer(IP):

        # Get Source IP Address
        source_ip = packet[IP].src

        # Get Destination IP Address
        destination_ip = packet[IP].dst

        # Get Protocol Number
        protocol = packet[IP].proto

        # Get Packet Length in Bytes
        packet_length = len(packet)

        print("\n====================================")
        print("Packet Number   :", packet_number)
        print("Source IP       :", source_ip)
        print("Destination IP  :", destination_ip)
        print("Protocol Number :", protocol)
        print("Packet Length   :", packet_length, "Bytes")
        print("====================================")


print("Network Traffic Detection Started...")
print("Capturing first 10 packets...\n")

# Capture 10 packets
sniff(prn=packet_callback, count=10)

print("\nPacket Capture Completed!")
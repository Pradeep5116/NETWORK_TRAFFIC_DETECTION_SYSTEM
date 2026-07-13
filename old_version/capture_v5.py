# ==========================================================
# Project : Network Traffic Detection System
# File    : capture_v5.py
# Author  : Pradeep Tunga
# Module  : 5 - Packet Logging System
# Purpose : Capture packets and save them into logs.txt
# ==========================================================

# Import required modules from Scapy
from scapy.all import sniff, IP, TCP, UDP

# Import datetime module to display current time
from datetime import datetime

# Global variable to count packets
packet_number = 0


# ==========================================================
# This function is automatically called whenever
# a packet is captured.
# ==========================================================
def packet_callback(packet):

    global packet_number

    # Increase packet count
    packet_number += 1

    # Check whether packet contains an IP layer
    if packet.haslayer(IP):

        # Get Source IP Address
        source_ip = packet[IP].src

        # Get Destination IP Address
        destination_ip = packet[IP].dst

        # Get Protocol Number
        protocol_number = packet[IP].proto

        # --------------------------------------------
        # Convert Protocol Number into Protocol Name
        # --------------------------------------------
        if protocol_number == 6:
            protocol = "TCP"

        elif protocol_number == 17:
            protocol = "UDP"

        elif protocol_number == 1:
            protocol = "ICMP"

        else:
            protocol = f"Unknown ({protocol_number})"

        # --------------------------------------------
        # Get Source and Destination Port
        # --------------------------------------------
        if packet.haslayer(TCP):

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif packet.haslayer(UDP):

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        else:

            source_port = "N/A"
            destination_port = "N/A"

        # Get Packet Size
        packet_length = len(packet)

        # Get Current Time
        current_time = datetime.now().strftime("%I:%M:%S %p")

        # ==================================================
        # Display Packet Information
        # ==================================================

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

        # ==================================================
        # Save Packet Information into logs.txt
        # ==================================================

        with open("logs.txt", "a") as file:

            file.write("\n================================================\n")
            file.write(f"Packet Number     : {packet_number}\n")
            file.write(f"Capture Time      : {current_time}\n")
            file.write(f"Source IP         : {source_ip}\n")
            file.write(f"Destination IP    : {destination_ip}\n")
            file.write(f"Protocol          : {protocol}\n")
            file.write(f"Source Port       : {source_port}\n")
            file.write(f"Destination Port  : {destination_port}\n")
            file.write(f"Packet Length     : {packet_length} Bytes\n")
            file.write("================================================\n")


# ==========================================================
# Program Starts Here
# ==========================================================

print("================================================")
print(" Network Traffic Detection Started ")
print(" Capturing First 10 Packets ")
print("================================================")

# Capture first 10 packets
sniff(
    prn=packet_callback,
    count=10
)

print("\nPacket Capture Completed!")
print("Packet details have been saved into logs.txt")
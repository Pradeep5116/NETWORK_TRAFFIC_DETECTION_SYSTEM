# ==========================================================
# Project : Network Traffic Detection System
# File    : packet_capture.py
# Author  : Pradeep Tunga
# Purpose : Capture packets and send them to other modules
# ==========================================================

# Import shared dashboard data

# Import Scapy modules
from scapy.all import sniff, IP, TCP, UDP

# Import datetime module
from datetime import datetime

# Import configuration
from config import PACKET_LIMIT

# Import protocol converter
from protocol_utils import get_protocol_name

# Import logger functions
from logger import log_packet

# Import detector functions
from detector import detect_packet_flood
from detector import detect_port_scan


# Packet Counter
packet_number = 0


# ==========================================================
# Function : packet_callback()
# Purpose  : Process every captured packet
# ==========================================================

def packet_callback(packet):

    global packet_number

    # Increase packet count
    packet_number += 1

    # Process only IP packets
    if packet.haslayer(IP):

        # -----------------------------
        # Extract IP Addresses
        # -----------------------------
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # -----------------------------
        # Protocol
        # -----------------------------
        protocol_number = packet[IP].proto
        protocol = get_protocol_name(protocol_number)

        # -----------------------------
        # Port Numbers
        # -----------------------------
        if packet.haslayer(TCP):

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif packet.haslayer(UDP):

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        else:

            source_port = "N/A"
            destination_port = "N/A"

        # -----------------------------
        # Packet Length
        # -----------------------------
        packet_length = len(packet)

        # -----------------------------
        # Current Time
        # -----------------------------
        current_time = datetime.now().strftime("%I:%M:%S %p")

        # -----------------------------
        # Display Packet
        # -----------------------------
        print("\n==========================================")
        print("Packet Number     :", packet_number)
        print("Time              :", current_time)
        print("Source IP         :", source_ip)
        print("Destination IP    :", destination_ip)
        print("Protocol          :", protocol)
        print("Source Port       :", source_port)
        print("Destination Port  :", destination_port)
        print("Packet Length     :", packet_length, "Bytes")
        print("==========================================")

        # -----------------------------
        # Save Packet Log
        # -----------------------------
        log_packet(
            packet_number,
            current_time,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_length
        )

        # -----------------------------
        # Run IDS Detection
        # -----------------------------
        detect_packet_flood(
            source_ip,
            current_time
        )

        detect_port_scan(
            source_ip,
            destination_port,
            current_time
        )

# ==========================================================
# Function : start_capture()
# Purpose  : Start packet capture
# ==========================================================

def start_capture():

    print("\n==========================================")
    print(" Network Traffic Detection Started ")
    print("==========================================")

    # Unlimited Capture
    if PACKET_LIMIT == 0:

        sniff(
            prn=packet_callback,
            store=False
        )

    # Limited Capture
    else:

        sniff(
            prn=packet_callback,
            count=PACKET_LIMIT,
            store=False
        )

    print("\nPacket Capture Completed!")
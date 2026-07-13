# =====================================================
# Network Traffic Detection Project
# File Name : capture.py
# Author    : Pradeep Tunga
# Purpose   : Capture live network packets using Scapy
# =====================================================

# Import the sniff() function from the Scapy library.
# sniff() is used to capture network packets.
from scapy.all import sniff


# -----------------------------------------------------
# This function is called automatically whenever
# a network packet is captured.
# -----------------------------------------------------
def packet_callback(packet):
    
    # packet.summary() returns a one-line summary
    # of the captured packet.
    print(packet.summary())


# Print a message so the user knows capturing has started.
print("===================================")
print(" Network Traffic Detection Started ")
print(" Capturing first 10 packets...")
print("===================================")


# Start capturing packets.
#
# prn = packet_callback
# Every captured packet is sent to the function above.
#
# count = 10
# Stop automatically after capturing 10 packets.
sniff(
    prn=packet_callback,
    count=10
)


# This line executes after all 10 packets are captured.
print("===================================")
print(" Packet Capture Completed ")
print("===================================")
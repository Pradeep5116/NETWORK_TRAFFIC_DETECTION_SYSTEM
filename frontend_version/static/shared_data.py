# ==========================================================
# File : shared_data.py
# Purpose : Share live packet data between Scapy and Flask
# ==========================================================

# Store the latest packets
live_packets = []

# Store alerts
live_alerts = []


# Shared data between Packet Capture and Flask
statistics = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0
}
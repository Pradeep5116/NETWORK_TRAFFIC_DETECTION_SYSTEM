# ==========================================================
# Project : Network Traffic Detection System
# File    : detector.py
# Author  : Pradeep Tunga
# Purpose : Detect suspicious network activities
# ==========================================================

# Import threshold values from config.py
from config import PACKET_THRESHOLD, PORT_SCAN_THRESHOLD

# Import alert logger
from logger import log_alert


# ==========================================================
# Global Variables
# ==========================================================

# Stores packet count for every Source IP
packet_counter = {}

# Stores destination ports visited by every Source IP
port_scan = {}

# Stores already alerted IPs
packet_alerted = set()

# Stores already alerted Port Scan IPs
port_scan_alerted = set()


# ==========================================================
# Function : detect_packet_flood()
# Purpose  : Detect excessive packets from one IP
# ==========================================================

def detect_packet_flood(source_ip, current_time):

    # First packet from this IP
    if source_ip not in packet_counter:
        packet_counter[source_ip] = 1

    else:
        packet_counter[source_ip] += 1

    # Check threshold
    if (
        packet_counter[source_ip] > PACKET_THRESHOLD
        and source_ip not in packet_alerted
    ):

        print("\n🚨 ALERT 🚨")
        print("Possible Packet Flood")
        print("Source IP :", source_ip)
        print("Packets   :", packet_counter[source_ip])

        # Save alert
        log_alert(
            "Packet Flood",
            current_time,
            source_ip,
            f"Packet Count : {packet_counter[source_ip]}"
        )

        # Prevent duplicate alerts
        packet_alerted.add(source_ip)


# ==========================================================
# Function : detect_port_scan()
# Purpose  : Detect Port Scanning
# ==========================================================

def detect_port_scan(source_ip,
                    destination_port,
                    current_time):

    # Ignore protocols without ports
    if destination_port == "N/A":
        return

    # First packet from this IP
    if source_ip not in port_scan:
        port_scan[source_ip] = set()

    # Save unique destination ports
    port_scan[source_ip].add(destination_port)

    # Check threshold
    if (
        len(port_scan[source_ip]) > PORT_SCAN_THRESHOLD
        and source_ip not in port_scan_alerted
    ):

        print("\n🚨 ALERT 🚨")
        print("Possible Port Scan")
        print("Source IP :", source_ip)
        print("Ports     :", len(port_scan[source_ip]))

        # Save alert
        log_alert(
            "Port Scan",
            current_time,
            source_ip,
            f"Ports Scanned : {len(port_scan[source_ip])}"
        )

        # Prevent duplicate alerts
        port_scan_alerted.add(source_ip)
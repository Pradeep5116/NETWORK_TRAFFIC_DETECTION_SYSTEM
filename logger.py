# ==========================================================
# Project : Network Traffic Detection System
# File    : logger.py
# Author  : Pradeep Tunga
# Purpose : Save packet logs and IDS alerts
# ==========================================================

# Import log file names from config.py
from config import LOG_FILE, ALERT_FILE


# ==========================================================
# Function : log_packet()
# Purpose  : Save normal packet details into logs.txt
# ==========================================================

def log_packet(packet_number,
        current_time,
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        packet_length):
        with open(LOG_FILE, "a") as file:
                file.write("\n=========================================\n")
                file.write(f"Packet Number     : {packet_number}\n")
                file.write(f"Time              : {current_time}\n")
                file.write(f"Source IP         : {source_ip}\n")
                file.write(f"Destination IP    : {destination_ip}\n")
                file.write(f"Protocol          : {protocol}\n")
                file.write(f"Source Port       : {source_port}\n")
                file.write(f"Destination Port  : {destination_port}\n")
                file.write(f"Packet Length     : {packet_length} Bytes\n")
                file.write("=========================================\n")


# ==========================================================
# Function : log_alert()
# Purpose  : Save IDS alerts into alerts.txt
# ==========================================================

def log_alert(alert_type,
        current_time,
        source_ip,
        message):

        with open(ALERT_FILE, "a") as file:

                file.write("\n=========================================\n")
                file.write(f"ALERT TYPE : {alert_type}\n")
                file.write(f"Time       : {current_time}\n")
                file.write(f"Source IP  : {source_ip}\n")
                file.write(f"Message    : {message}\n")
                
                file.write("=========================================\n")
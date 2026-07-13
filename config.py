# ==========================================================
# Project : Network Traffic Detection System
# File    : config.py
# Author  : Pradeep Tunga
# Purpose : Store project configuration settings
# ==========================================================

# -------------------------------
# Packet Capture Settings
# -------------------------------

# Number of packets to capture.
# Set to 0 for unlimited capture.
PACKET_LIMIT = 20

# -------------------------------
# IDS Thresholds
# -------------------------------

# Alert if one Source IP sends more than this many packets.
PACKET_THRESHOLD = 5

# Alert if one Source IP contacts more than this many different ports.
PORT_SCAN_THRESHOLD = 10

# -------------------------------
# Log Files
# -------------------------------

# File for normal packet logs
LOG_FILE = "logs.txt"

# File for IDS alerts
ALERT_FILE = "alerts.txt"

# -------------------------------
# Project Information
# -------------------------------

PROJECT_NAME = "Network Traffic Detection System"

VERSION = "2.0"

AUTHOR = "Pradeep Tunga"
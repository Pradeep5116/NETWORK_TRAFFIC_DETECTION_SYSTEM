# 🛡️ Network Traffic Detection System

A Python-based Network Traffic Detection and Basic Intrusion Detection System (IDS) developed using **Scapy**.

This project captures live network packets, analyzes network protocols, logs packet details, and detects suspicious activities such as packet flooding and basic port scanning.

---

## 🚀 Features

- 📡 Live Network Packet Capture
- 🌐 Source & Destination IP Detection
- 🔄 Protocol Identification (TCP, UDP, ICMP)
- 🔢 Source & Destination Port Detection
- 📦 Packet Length Detection
- 📝 Packet Logging
- 🚨 Suspicious Traffic Detection
- 🔍 Basic Port Scan Detection
- ⚙️ Modular Project Architecture
- 💾 Configurable Settings

---

## 🛠️ Technologies Used

- Python 3.12
- Scapy
- VS Code
- Git
- GitHub

---

## 📂 Project Structure

```
NetworkTrafficDetection/
│
├── config.py
├── detector.py
├── logger.py
├── packet_capture.py
├── protocol_utils.py
├── main.py
│
├── alerts.txt
├── logs.txt
├── requirements.txt
└── README.md
```

---

## ▶️ How to Run

### Install Scapy

```bash
pip install scapy
```

### Clone Repository

```bash
git clone https://github.com/Pradeep5116/Network-Traffic-Detection-System.git
```

### Open Project

```bash
cd Network-Traffic-Detection-System
```

### Run

```bash
python main.py
```

---

## 📊 Sample Output

```
====================================================
Packet Number      : 1
Time               : 09:15:21 PM
Source IP          : 192.168.1.5
Destination IP     : 142.250.183.78
Protocol           : TCP
Source Port        : 52136
Destination Port   : 443
Packet Length      : 79 Bytes
====================================================
```

---

## 🚨 Detection Capabilities

✔ Packet Flood Detection

✔ Basic Port Scan Detection

✔ Packet Logging

✔ Alert Logging

---

## 📈 Future Improvements

- SYN Flood Detection
- ICMP Flood Detection
- DNS Monitoring
- CSV Export
- Live Dashboard (Flask)
- Email Alerts
- Threat Intelligence Integration

---

## 👨‍💻 Author

**Pradeep Tunga**

B.Tech Cyber Security

GitHub: https://github.com/Pradeep5116
# ==========================================================
# Project : Network Traffic Detection System
# File    : app.py
# Purpose : Flask Dashboard
# ==========================================================

import threading
from packet_capture import start_capture

from flask import Flask, render_template
from shared_data import live_packets, statistics

# Create Flask App
app = Flask(__name__)


# Home Page
@app.route("/")
def home():

    return render_template(
        "index.html",
        packets=live_packets,
        stats=statistics
    )


# Run Flask
if __name__ == "__main__":

    # Start packet capture in a separate thread
    capture_thread = threading.Thread(target=start_capture)

    capture_thread.daemon = True

    capture_thread.start()

    # Start Flask
    app.run(
        host="127.0.0.1",
        port=8000,
        debug=True,
        use_reloader=False
    )
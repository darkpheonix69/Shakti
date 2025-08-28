from flask import Flask, jsonify, request
import subprocess
from database import fetch_logs
import yaml
import socket
import sys
import logging
import re

logging.basicConfig(level=logging.INFO)

try:
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
except Exception as e:
    logging.error(f"Failed to load config.yaml: {e}")
    config = {}

app = Flask(__name__)

FIREWALL_SERVER_HOST = config.get("firewall_host", "127.0.0.1")
FIREWALL_SERVER_PORT = config.get("firewall_port", 9000)
SOCKET_TIMEOUT = config.get("socket_timeout", 5)

MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

@app.route("/start")
def start_sniffer():
    try:
        subprocess.Popen([sys.executable, "main.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info("Sniffer started.")
        return jsonify({"status": "sniffing started"})
    except Exception as e:
        logging.error(f"Failed to start sniffer: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/logs")
def get_logs():
    try:
        data = fetch_logs()
        logs = []
        for row in data:
            logs.append({
                "timestamp": row[0],
                "mac": row[1],
                "signal": row[2],
                "channel": row[3],
                "message": row[4]
            })
        return jsonify(logs)
    except Exception as e:
        logging.error(f"Failed to fetch logs: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/block/<mac>")
def block_mac(mac):
    if not MAC_REGEX.match(mac):
        return jsonify({"error": "Invalid MAC address format"}), 400
    try:
        with socket.create_connection((FIREWALL_SERVER_HOST, FIREWALL_SERVER_PORT), timeout=SOCKET_TIMEOUT) as sock:
            sock.sendall((mac + "\n").encode())
            response = sock.recv(1024).decode()
        return jsonify({"status": response.strip()})
    except Exception as e:
        logging.error(f"Failed to block MAC {mac}: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=config.get("api_port", 5000), host='0.0.0.0', debug=config.get("debug", False))

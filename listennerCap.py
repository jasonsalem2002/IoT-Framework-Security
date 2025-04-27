"""
live_io_listener.py
────────────────────────────────────────────────────────────────────────
• Listens on the standard MQTT (TCP 1883) and CoAP (UDP 5683) ports.
• Converts every incoming packet to the raw-feature dictionary used at
  training time, passes it through the model, and appends the result to
  received_traffic.csv.
"""

import csv
import os
import socket
import threading
import time
from datetime import datetime

import joblib
import pandas as pd
from model.preprocessing import preprocess_packets   # ← your original helper

# ─────────────────────────── Configuration ──────────────────────────
LISTEN_IP   = "0.0.0.0"     # listen on all interfaces
MQTT_PORT   = 1883
COAP_PORT   = 5683
CSV_FILENAME = "received_traffic.csv"

TARGET_IP   = "192.168.0.121"        # replace if needed
SRC_MAC     = "AA:BB:CC:DD:EE:FF"    # dummy; sniff real MAC if available
DST_MAC     = "AA:BB:CC:DD:EE:FF"

# ─────────────────────────────── Model ──────────────────────────────
with open("model/payload_packet_model.pkl", "rb") as f:
    bundle          = joblib.load(f)

model          = bundle["model"]
proto_encoder  = bundle["protocol_encoder"]
label_encoder  = bundle["label_encoder"]
scaler         = bundle.get("scaler", None)          # optional

# ─────────────── CSV header (prediction column added) ───────────────
CSV_HEADER = [
    "timestamp", "protocol", "payload",
    "flow_bytes", "payload_size", "source_port", "destination_port",
    "source_ip", "destination_ip", "source_mac", "destination_mac",
    "predicted_label",
]

if not os.path.exists(CSV_FILENAME):
    with open(CSV_FILENAME, "w", newline="") as f:
        csv.writer(f).writerow(CSV_HEADER)

# ──────────────────────────── Helpers ───────────────────────────────
def predict_packet(pkt_dict: dict) -> str:
    """Return human-readable class label."""
    X_num, _ = preprocess_packets(pd.DataFrame([pkt_dict]), proto_encoder)
    if scaler is not None:
        X_num = scaler.transform(X_num)
    y_idx = model.predict(X_num)
    return label_encoder.inverse_transform(y_idx)[0]


def save_to_csv(pkt_dict: dict) -> None:
    with open(CSV_FILENAME, "a", newline="") as f:
        csv.writer(f).writerow([pkt_dict[col] for col in CSV_HEADER])

# ───────────────────────── MQTT (TCP) ───────────────────────────────
def mqtt_listener() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((LISTEN_IP, MQTT_PORT))
    server.listen(5)
    print(f"[+] MQTT listener on {LISTEN_IP}:{MQTT_PORT}")

    while True:
        client_sock, client_addr = server.accept()
        threading.Thread(
            target=handle_mqtt_client,
            args=(client_sock, client_addr),
            daemon=True
        ).start()


def handle_mqtt_client(sock: socket.socket, addr: tuple) -> None:
    try:
        data = sock.recv(4096)
        if not data:
            return

        payload = data[2:].decode(errors="ignore")  # strip MQTT header
        pkt_dict = {
            "timestamp":        datetime.now().isoformat(timespec="microseconds"),
            "protocol":         "MQTT",
            "payload":          payload,
            "flow_bytes":       len(payload.encode()),
            "payload_size":     len(payload),
            "source_port":      addr[1],
            "destination_port": MQTT_PORT,
            "source_ip":        addr[0],
            "destination_ip":   TARGET_IP,
            "source_mac":       SRC_MAC,
            "destination_mac":  DST_MAC,
        }
        pkt_dict["predicted_label"] = predict_packet(pkt_dict)

        save_to_csv(pkt_dict)
        print(f"[MQTT] {addr[0]}:{addr[1]} → {pkt_dict['predicted_label']} – {payload[:50]}…")

    except Exception as e:
        print(f"[MQTT] error: {e}")
    finally:
        sock.close()

# ───────────────────────── CoAP (UDP) ───────────────────────────────
def coap_listener() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((LISTEN_IP, COAP_PORT))
    print(f"[+] CoAP listener on {LISTEN_IP}:{COAP_PORT}")

    while True:
        try:
            data, addr = server.recvfrom(4096)
            if not data:
                continue

            payload = data[4:].decode(errors="ignore")  # strip CoAP header
            pkt_dict = {
                "timestamp":        datetime.now().isoformat(timespec="microseconds"),
                "protocol":         "CoAP",
                "payload":          payload,
                "flow_bytes":       len(payload.encode()),
                "payload_size":     len(payload),
                "source_port":      addr[1],
                "destination_port": COAP_PORT,
                "source_ip":        addr[0],
                "destination_ip":   TARGET_IP,
                "source_mac":       SRC_MAC,
                "destination_mac":  DST_MAC,
            }
            pkt_dict["predicted_label"] = predict_packet(pkt_dict)

            save_to_csv(pkt_dict)
            print(f"[CoAP] {addr[0]}:{addr[1]} → {pkt_dict['predicted_label']} – {payload[:50]}…")

        except Exception as e:
            print(f"[CoAP] error: {e}")

# ──────────────────────────── Main ─────────────────────────────────
# if __name__ == "__main__":
def process():
    threading.Thread(target=mqtt_listener, daemon=True).start()
    threading.Thread(target=coap_listener, daemon=True).start()

    print("[*] Server running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down …")

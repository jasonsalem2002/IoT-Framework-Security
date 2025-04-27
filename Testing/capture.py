import socket
import threading
import csv
import os
from datetime import datetime

# Configuration
LISTEN_IP = "0.0.0.0"
MQTT_PORT = 1883
COAP_PORT = 5683
CSV_FILENAME = "captured_traffic.csv"

# Create CSV file if not exists
if not os.path.exists(CSV_FILENAME):
    with open(CSV_FILENAME, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "protocol", "payload", "predicted_label"])

# Payload Pattern Detection
def predict_label(payload):
    payload_lower = payload.lower()
    if "<script>" in payload_lower or "onerror=" in payload_lower:
        return "xss"
    elif "' or " in payload_lower or "union select" in payload_lower or "drop table" in payload_lower:
        return "sql_injection"
    elif "; ls" in payload_lower or "| nc" in payload_lower or "& whoami" in payload_lower:
        return "command_injection"
    elif "../" in payload_lower or "..\\" in payload_lower:
        return "path_traversal"
    elif len(payload) > 1000:
        return "overflow"
    else:
        return "normal"

# Save captured packet to CSV
def save_to_csv(protocol, payload, label):
    with open(CSV_FILENAME, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now().isoformat(), protocol, payload, label])

# MQTT Server (TCP)
def mqtt_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_IP, MQTT_PORT))
    server.listen(100)
    print(f"[MQTT] Listening on {LISTEN_IP}:{MQTT_PORT}")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_mqtt_client, args=(client_socket, addr)).start()

def handle_mqtt_client(client_socket, addr):
    try:
        data = client_socket.recv(4096)
        if data:
            payload = extract_mqtt_payload(data)
            label = predict_label(payload)
            print(f"[MQTT] {addr} Payload: {payload[:50]}... Label: {label}")
            save_to_csv("MQTT", payload, label)
    except Exception as e:
        print(f"[MQTT] Error: {e}")
    finally:
        client_socket.close()

# Extract MQTT payload
def extract_mqtt_payload(data):
    if len(data) > 2:
        remaining_length = data[1]
        payload = data[2:2+remaining_length]
        return payload.decode('utf-8', errors='ignore')
    return ""

# CoAP Server (UDP)
def coap_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((LISTEN_IP, COAP_PORT))
    print(f"[CoAP] Listening on {LISTEN_IP}:{COAP_PORT}")

    while True:
        data, addr = server.recvfrom(4096)
        threading.Thread(target=handle_coap_client, args=(data, addr)).start()

def handle_coap_client(data, addr):
    try:
        if len(data) > 4:
            payload = data[4:]  # Skip CoAP header
            payload_text = payload.decode('utf-8', errors='ignore')
            label = predict_label(payload_text)
            print(f"[CoAP] {addr} Payload: {payload_text[:50]}... Label: {label}")
            save_to_csv("CoAP", payload_text, label)
    except Exception as e:
        print(f"[CoAP] Error: {e}")


def capture():
    threading.Thread(target=mqtt_server, daemon=True).start()
    threading.Thread(target=coap_server, daemon=True).start()

    print("Packet capture started...")
    while True:
        pass

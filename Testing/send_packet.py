import random
import string
import socket
import time
import threading

# Configuration
TARGET_IP = "192.168.0.121"
MQTT_PORT = 1883  # MQTT over TCP
COAP_PORT = 5683  # CoAP over UDP

# Utility: Generate random payload
def random_payload(length=20):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# MQTT Sender
def send_mqtt_packet():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((TARGET_IP, MQTT_PORT))
        payload = random_payload()
        packet_type_flags = b'\x30'  # MQTT PUBLISH packet
        payload_bytes = payload.encode('utf-8')
        remaining_length = len(payload_bytes)
        remaining_length_encoded = bytes([remaining_length])
        packet = packet_type_flags + remaining_length_encoded + payload_bytes
        sock.sendall(packet)
        print(f"[MQTT] Sent: {payload}")
        response = sock.recv(1024)
        print(f"[MQTT] Response: {response}")
        sock.close()
    except Exception as e:
        print(f"[MQTT] Error: {e}")

# CoAP Sender
def send_coap_packet():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = random_payload()
        version_type_tokenlen = 0x40  # Ver=1, Type=0 (CON)
        code = 0x02  # POST
        message_id = random.randint(0, 65535)
        header = bytes([
            version_type_tokenlen,
            code,
            (message_id >> 8) & 0xFF,
            message_id & 0xFF
        ])
        packet = header + payload.encode('utf-8')
        sock.sendto(packet, (TARGET_IP, COAP_PORT))
        print(f"[CoAP] Sent: {payload}")

        # Wait for response
        sock.settimeout(2)
        try:
            data, addr = sock.recvfrom(1024)
            print(f"[CoAP] Response from {addr}: {data}")
        except socket.timeout:
            print("[CoAP] No response received")

        sock.close()
    except Exception as e:
        print(f"[CoAP] Error: {e}")

# Main loop
def main():
    while True:
        threading.Thread(target=send_mqtt_packet).start()
        time.sleep(random.uniform(0.5, 2))
        threading.Thread(target=send_coap_packet).start()
        time.sleep(random.uniform(0.5, 2))

if __name__ == "__main__":
    main()

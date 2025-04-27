import socket
import threading

# Configuration
LISTEN_IP = "0.0.0.0"  # Listen on all interfaces
MQTT_PORT = 1883
COAP_PORT = 5683

# MQTT Server (TCP)
def mqtt_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_IP, MQTT_PORT))
    server.listen(100)
    print(f"[MQTT] Listening on {LISTEN_IP}:{MQTT_PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"[MQTT] Connection from {addr}")
        threading.Thread(target=handle_mqtt_client, args=(client_socket, addr)).start()

def handle_mqtt_client(client_socket, addr):
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            print(f"[MQTT] Received from {addr}: {data}")
            # Fake MQTT ACK reply
            client_socket.sendall(b'\x20\x02\x00\x00')  # CONNACK or simple ACK
    except Exception as e:
        print(f"[MQTT] Error: {e}")
    finally:
        client_socket.close()

# CoAP Server (UDP)
def coap_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((LISTEN_IP, COAP_PORT))
    print(f"[CoAP] Listening on {LISTEN_IP}:{COAP_PORT}")

    while True:
        data, addr = server.recvfrom(1024)
        print(f"[CoAP] Received from {addr}: {data}")
        server.sendto(b"ACK from CoAP server", addr)

# Main launcher
def main():
    threading.Thread(target=mqtt_server, daemon=True).start()
    threading.Thread(target=coap_server, daemon=True).start()

    while True:
        pass

if __name__ == "__main__":
    main()
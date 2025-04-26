import socket
import threading

# Configuration
LISTEN_IP = "0.0.0.0"  # Listen on all interfaces
MQTT_PORT = 1883
COAP_PORT = 5683

# MQTT Server (TCP)
def mqtt_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((LISTEN_IP, MQTT_PORT))
    server.listen(5)
    print(f"[MQTT] Listening on {LISTEN_IP}:{MQTT_PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"[MQTT] Connection from {addr}")
        data = client_socket.recv(1024)
        print(f"[MQTT] Received: {data}")
        client_socket.sendall(b"ACK from MQTT server")
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
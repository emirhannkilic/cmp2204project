import socket
import json
import time
import threading
import os
from PyQt5.QtWidgets import QPushButton

last_seen = time.time()

def listen(udp_socket):
    global last_seen
    while True:
        try:
            data, addr = udp_socket.recvfrom(1024)
            msg = data.decode()
            try:
                data_json = json.loads(msg)
                peer_user = data_json["username"]
                print(f"[DISCOVERY] {peer_user} is online")
                last_seen = time.time()
            except Exception:
                pass
        except Exception as e:
            print(f"[ERROR] Listening error: {e}")

def send_message(udp_socket, message, broadcast_ip, port):
    udp_socket.sendto(message.encode(), (broadcast_ip, port))
    with open("chat_history.txt", "a") as log:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"{timestamp} | SENT | {message}\n")

def display_message(chat_history, parsed):
    if 'decrypted' in parsed:
        decrypted = parsed['decrypted']
        chat_history.append(decrypted)
        with open("chat_history.txt", "a") as log:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"{timestamp} | RECEIVED | {decrypted}\n")
    elif 'unencrypted_message' in parsed:
        chat_history.append(parsed['unencrypted_message'])
        with open("chat_history.txt", "a") as log:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"{timestamp} | RECEIVED | {parsed['unencrypted_message']}\n")

def setup_ui(self):
    # existing UI setup code...
    self.send_button = QPushButton("Send")
    # ... other UI elements
    input_layout.addWidget(self.send_button)
    self.view_log_button = QPushButton("View Log")
    self.view_log_button.clicked.connect(self.view_log)
    input_layout.addWidget(self.view_log_button)

def view_log(self):
    if os.path.exists("chat_history.txt"):
        with open("chat_history.txt", "r") as f:
            content = f.read()
        self.chat_history.append("[Log History]\n" + content)
    else:
        self.chat_history.append("[Log History] No log file found.")

def main():
    global last_seen

    username = input("Enter your username: ")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #udp_socket.bind(('', 6000))  # Gerek yok, istemci sadece gönderim yapıyor

    broadcast_ip = '192.168.1.255'
    port = 6000

    threading.Thread(target=listen, args=(udp_socket,), daemon=True).start()

    while True:
        try:
            # DISCOVERY broadcast
            discovery_msg = json.dumps({"username": username})
            udp_socket.sendto(discovery_msg.encode(), (broadcast_ip, port))
            print(f"[+] Broadcasted discovery: {discovery_msg}")
            # with open("chat_history.txt", "a") as log:
            #     timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            #     log.write(f"{timestamp} | SENT | {discovery_msg}\n")

        except Exception as e:
            print(f"Error broadcasting message: {e}")

        time.sleep(8)

if __name__ == "__main__":
    main()
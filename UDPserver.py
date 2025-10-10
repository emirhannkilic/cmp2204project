from socket import *
import json
import time
import threading

serverPort = 6000
serverSocket = socket(AF_INET, SOCK_DGRAM)

serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
serverSocket.bind(('', serverPort))

user_dict = {}
offline_users = set()

print("UDP Server is listening for peer broadcasts...")

def check_offline_users():
    global user_dict, offline_users
    while True:
        time.sleep(8)
        now = time.time()

        for ip, info in user_dict.items():
            username = info["username"]
            last_update = info["last_update"]

            if now - last_update > 900:  # 15 dakika
                if ip not in offline_users:
                    print(f"{username} is offline (IP: {ip})")
                    offline_users.add(ip)
                    user_dict[ip]['status'] = 'offline'
                    with open('peers.json', 'w') as f:
                        json.dump(user_dict, f)

            elif now - last_update > 10:  # 10 saniye
                if user_dict[ip]['status'] != 'away':
                    print(f"{username} is away (IP: {ip})")
                    user_dict[ip]['status'] = 'away'
                    with open('peers.json', 'w') as f:
                        json.dump(user_dict, f)

            else:
                if user_dict[ip]['status'] != 'online':
                    print(f"{username} is back online (IP: {ip})")
                    user_dict[ip]['status'] = 'online'
                    with open('peers.json', 'w') as f:
                        json.dump(user_dict, f)
                offline_users.discard(ip)

# Başlat offline kontrol thread’i
offline_checker_thread = threading.Thread(target=check_offline_users, daemon=True)
offline_checker_thread.start()

while True:
    data, addr = serverSocket.recvfrom(1024)
    ip = addr[0]

    try:
        decoded = data.decode()

        if decoded.startswith("STATUS:"):
            _, username, status = decoded.split(":")

        else:
            try:
                json_data = json.loads(decoded)
                username = json_data["username"]
                status = "online"
            except json.JSONDecodeError:
                print(f"Unknown message format from {ip}: {decoded}")
                continue

        print(f"{username} is {status} from {ip}")

        user_dict[ip] = {
            "username": username,
            "status": status,
            "last_update": time.time()
        }

        with open('peers.json', 'w') as f:
            json.dump(user_dict, f)

    except Exception as e:
        print(f"Error processing message: {e}")
from PyQt5.QtCore import QThread, pyqtSignal
from socket import *
import json
import time
import base64
from pyDes import triple_des, ECB, PAD_PKCS5
import threading

# Generates a DES cipher using the shared secret key
def get_cipher(shared_secret):
    key = str(shared_secret).zfill(24).encode()[:24]  # Ensure 24-byte key
    return triple_des(key, ECB, padmode=PAD_PKCS5)

def handle_client(conn, addr):
    client_ciphers = {}  # Başlangıçta cipher yok
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break  # Bağlantı kapandı

            try:
                message = data.decode()
                parsed_message = json.loads(message)

                if "key" in parsed_message:
                    print(f"[+] Received new key from {addr}: {parsed_message['key']}")

                    # Perform Diffie-Hellman key exchange
                    p = 19
                    g = 2
                    client_public_key = int(parsed_message["key"])
                    server_private_key = 5  
                    server_public_key = (g ** server_private_key) % p

                    # Send server's public key back to client
                    response = json.dumps({"key": str(server_public_key)})
                    conn.send(response.encode())

                    # Compute the shared secret
                    shared_secret = (client_public_key ** server_private_key) % p
                    print(f"[+] New shared secret established with {addr}: {shared_secret}")

                    # Yeni cipher oluştur ve bu bağlantı için sakla
                    client_ciphers[conn] = get_cipher(shared_secret)

                elif "unencrypted_message" in parsed_message:
                    print(f"Unsecure message from {addr}: {parsed_message['unencrypted_message']}")
                    try:
                        with open("peers.json", "r") as f_peers:
                            peers = json.load(f_peers)
                        sender_username = peers.get(addr[0], {}).get("username", str(addr[0]))
                    except:
                        sender_username = str(addr[0])

                    receiver_username = "You"  # Adjusted for log clarity

                    with open("chat_history.txt", "a") as f:
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        f.write(f"{timestamp} | {sender_username} -> {receiver_username} | {parsed_message['unencrypted_message']}\n")

                elif "encrypted_message" in parsed_message:
                    cipher = client_ciphers.get(conn)
                    if cipher is None:
                        print("Error: Secure message received but no cipher established.")
                    else:
                        encrypted_b64 = parsed_message['encrypted_message']
                        encrypted_bytes = base64.b64decode(encrypted_b64)
                        decrypted = cipher.decrypt(encrypted_bytes)
                        print(f"Decrypted secure message from {addr}: {decrypted.decode()}")
                        try:
                            with open("peers.json", "r") as f_peers:
                                peers = json.load(f_peers)
                            sender_username = peers.get(addr[0], {}).get("username", str(addr[0]))
                        except:
                            sender_username = str(addr[0])

                        receiver_username = "You"  # Adjusted for log clarity

                        with open("chat_history.txt", "a") as f:
                            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                            f.write(f"{timestamp} | {sender_username} -> {receiver_username} | {decrypted.decode()}\n")

                else:
                    print("Unknown message format.")
                    print(f"Received data: {parsed_message}")

            except json.JSONDecodeError:
                print("Invalid JSON received.")

    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()

def main():
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(("", 6001))
    server_socket.listen(5)
    print("[+] TCP Server listening on port 6001...")

    while True:
        try:
            conn, addr = server_socket.accept()
            print(f"[+] Accepted connection from {addr}")
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
        except Exception as e:
            print(f"Error accepting connections: {e}")

if __name__ == "__main__":
    main()
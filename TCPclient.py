from socket import *
import json
import random
import base64
import datetime
import time
from pyDes import triple_des, ECB, PAD_PKCS5

USERNAME = "server"  # replace with actual username if needed

# Generate DES cipher from shared secret
def get_cipher(shared_secret):
    key = str(shared_secret).zfill(24).encode()[:24]  # Ensure 24 bytes for triple DES
    return triple_des(key, ECB, padmode=PAD_PKCS5)

# Load discovered peers from file
def load_peers():
    try:
        with open('peers.json', 'r') as f:
            peers = json.load(f)
            return peers
    except FileNotFoundError:
        return {}

# Log chat messages
def log_chat(message, sender, receiver):
    with open("chat_history.txt", "a") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{timestamp} | {sender} -> {receiver} | {message}\n")

# View chat log
def view_chat_history():
    try:
        with open("chat_history.txt", "r") as f:
            content = f.read()
            if content.strip():
                print("\n--- Chat History ---")
                print(content)
            else:
                print("No chat history found.")
    except FileNotFoundError:
        print("No chat history found.")

# Main client code
def main():
    peers = load_peers()
    if not peers:
        print("No online peers found. Exiting...")
        return

    last_selected_ip = None

    # Display peer list
    now = time.time()
    peer_list = list(peers.items())

    print("\nAvailable Peers:")
    for idx, (ip, info) in enumerate(peer_list):
        username_peer = info["username"]
        status = info["status"]
        last_update = info["last_update"]

        if now - last_update > 20:
            display_status = "offline"
        else:
            display_status = status

        print(f"{idx+1}) {username_peer} ({ip}) - {display_status}")

    # User selects peer
    while True:
        choice = input("Select a peer number to connect: ").strip()
        try:
            choice_idx = int(choice) - 1
            selected_ip, selected_info = peer_list[choice_idx]
            selected_username = selected_info["username"]
            break
        except:
            print("Invalid choice. Try again.")

    while True:
        try:
            clientSocket = socket(AF_INET, SOCK_STREAM)
            clientSocket.connect((selected_ip, 6001))
            if selected_ip != last_selected_ip:
                print(f"\nConnected to {selected_username} at {selected_ip}")
                last_selected_ip = selected_ip

            # Show menu
            print("\nMenu:")
            print("1) Send Unsecure Message")
            print("2) Send Secure Message")
            print("3) View Chat History")
            print("4) Select a different peer")
            print("5) Exit")

            subchoice = input("Enter your choice: ").strip()

            if subchoice == "1":
                message = input("Enter your message: ").lower()
                json_message = json.dumps({"unencrypted_message": message})
                clientSocket.send(json_message.encode())
                log_chat(message, "You", selected_username)

            elif subchoice == "2":
                p = 19
                g = 2
                private_key = random.randint(1, 10)
                public_key = (g ** private_key) % p

                json_key_message = json.dumps({"key": str(public_key)})
                clientSocket.send(json_key_message.encode())

                server_response = clientSocket.recv(1024).decode()
                server_data = json.loads(server_response)
                server_public_key = int(server_data["key"])

                shared_secret = (server_public_key ** private_key) % p
                print(f"[+] New shared secret key established: {shared_secret}")

                cipher = get_cipher(shared_secret)

                message = input("Enter your secure message: ").lower()
                encrypted_bytes = cipher.encrypt(message.encode())
                encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
                json_encrypted = json.dumps({"encrypted_message": encrypted_b64})
                clientSocket.send(json_encrypted.encode())

                log_chat(message, "You", selected_username)

            elif subchoice == "3":
                view_chat_history()

            elif subchoice == "4":
                # re-display peer list
                print("\nAvailable Peers:")
                peers = load_peers()
                now = time.time()
                peer_list = list(peers.items())
                for idx, (ip, info) in enumerate(peer_list):
                    username_peer = info["username"]
                    status = info["status"]
                    last_update = info["last_update"]

                    if now - last_update > 20:
                        display_status = "offline"
                    else:
                        display_status = status

                    print(f"{idx+1}) {username_peer} ({ip}) - {display_status}")

                while True:
                    choice = input("Select a peer number to connect: ").strip()
                    try:
                        choice_idx = int(choice) - 1
                        selected_ip, selected_info = peer_list[choice_idx]
                        selected_username = selected_info["username"]
                        break
                    except:
                        print("Invalid choice. Try again.")

            elif subchoice == "5":
                clear_choice = input("Do you want to clear the chat history? (yes/no): ").lower()
                if clear_choice == "yes":
                    open("chat_history.txt", "w").close()
                    print("Chat history cleared.")
                else:
                    print("Chat history preserved.")
                clientSocket.close()
                break

            else:
                print("Invalid choice. Please try again.")

            clientSocket.close()

        except Exception as e:
            print(f"Error occurred: {e}")

if __name__ == "__main__":
    main()
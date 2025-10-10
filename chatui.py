import time
import json
import os
import sys
import socket
import base64
import random
import threading
from pyDes import triple_des, ECB, PAD_PKCS5
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtCore import QMetaObject
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QListWidget, QLineEdit, QLabel, QCheckBox, QInputDialog,
    QDialog, QVBoxLayout, QDialogButtonBox
)
from PyQt5.QtGui import QTextCursor

# --- Constants ---
UDP_PORT = 6000
TCP_PORT = 6001
PEERS_FILE = "peers.json"
LOG_FILE = "chat_history.txt"
DISCOVERY_INTERVAL = 8  # seconds
PEER_TIMEOUT = 15 # seconds (time after which peer is considered away/offline)
PEER_OFFLINE_THRESHOLD = 900 # seconds (15 minutes)

# Diffie-Hellman Parameters 
DH_P = 19 # Prime number
DH_G = 2 # Primitive root modulo p

class ChatWindow(QWidget):
    class ReceiverThread(QThread):
        message_received = pyqtSignal(str)
        connection_closed = pyqtSignal()

        def __init__(self, tcp_socket):
            super().__init__()
            self.tcp_socket = tcp_socket
            self._is_running = True

        def run(self):
            print("[DEBUG] ReceiverThread started")
            self.tcp_socket.settimeout(1.0) # Add timeout to allow checking _is_running
            while self._is_running:
                try:
                    data = self.tcp_socket.recv(4096) # Increased buffer size
                    if not data:
                        print("[RECEIVER] Connection closed by peer.")
                        break
                    try:
                        msg = data.decode()
                        print(f"[RECEIVER] Received raw: {msg}")
                        # Handle potential multiple JSON objects received together
                        for part in msg.strip().split('\n'):
                             if part:
                                self.message_received.emit(part)
                    except UnicodeDecodeError:
                        print(f"[RECEIVER] Received non-UTF8 data (possibly binary): {data}")
                        # Handle binary/other data if necessary, or ignore
                except socket.timeout:
                    continue # Just loop again to check _is_running
                except socket.error as e:
                    print(f"[RECEIVER] Socket error: {e}")
                    break
                except Exception as e:
                    print(f"[RECEIVER] Error receiving data: {e}")
                    break
            print("[DEBUG] ReceiverThread finished.")
            self.connection_closed.emit()

        def stop(self):
            self._is_running = False

    def __init__(self):
        super().__init__()

        self.setWindowTitle("p2p chat")
        self.setGeometry(100, 100, 800, 500)

        # Network State
        self.udp_socket = None
        self.tcp_server_socket = None
        self.client_socket = None # The socket for the *current* active chat connection
        self.receiver_thread = None
        self.selected_peer_ip = None
        # Thread control flags
        self.udp_running = True
        self.tcp_server_running = True

        # Security State
        self.current_cipher = None
        self.dh_private_key = None
        self.pending_secure_message = None # Store message if key exchange is needed first

        # UI Setup
        self.setup_ui()
        # Delete old peers.json if it exists
        try:
            if os.path.exists(PEERS_FILE):
                os.remove(PEERS_FILE)
                print("[INIT] Cleared old peers.json.")
        except Exception as e:
            print(f"[INIT] Could not remove peers.json: {e}")
        self.update_peer_list() # Initial population
        self.peer_update_timer = QTimer(self)
        self.peer_update_timer.timeout.connect(self.update_peer_list)
        self.peer_update_timer.start(5000) # Update peer list every 5 seconds

        self.username, ok = self.get_username()
        if not ok or not self.username:
            print("[ERROR] Username is required.")
            sys.exit()

        # Start networking
        self.start_udp_discovery()
        self.start_tcp_server()
        self._shutting_down = False

    def closeEvent(self, event):
        """Ensure sockets are closed and threads stopped on exit."""
        self._shutting_down = True
        print("[SYSTEM] Closing application...")
        # Set thread control flags to stop UDP and TCP loops
        self.udp_running = False
        self.tcp_server_running = False
        # Try to unblock TCP accept() if needed
        try:
            dummy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dummy_socket.connect(('127.0.0.1', TCP_PORT))
            dummy_socket.close()
        except Exception:
            pass
        if self.receiver_thread:
            self.receiver_thread.stop()
            self.receiver_thread.wait() # Wait for thread to finish
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
            except socket.error as e:
                 print(f"[SOCKET] Error closing client socket: {e}")
        if self.tcp_server_socket:
             try:
                self.tcp_server_socket.close()
             except socket.error as e:
                 print(f"[SOCKET] Error closing server socket: {e}")
        if self.udp_socket:
             try:
                self.udp_socket.close()
             except socket.error as e:
                 print(f"[SOCKET] Error closing UDP socket: {e}")
        print("[SYSTEM] All sockets and threads shut down gracefully.")
        print("[SYSTEM] Application closed.")
        event.accept()


    def get_username(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Username")
        layout = QVBoxLayout(dialog)

        label = QLabel("Enter your username:")
        label.setStyleSheet("color: #3C4F76; font-weight: bold; font-size: 14px;")
        layout.addWidget(label)

        input_field = QLineEdit()
        input_field.setStyleSheet("background-color: #AB9F9D; color: #3C4F76; padding: 6px; border-radius: 6px;")
        layout.addWidget(input_field)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addWidget(button_box)

        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)

        ok = dialog.exec_()
        return input_field.text().strip(), bool(ok)

    def setup_ui(self):
        main_layout = QHBoxLayout(self) # Set layout on self
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        self.peer_list = QListWidget()
        self.peer_list.setFixedWidth(200)
        self.peer_list.itemClicked.connect(self.handle_peer_selection) # Connect click event

        chat_panel = QVBoxLayout()
        chat_panel.setSpacing(8)
        # Status label above chat label
        self.status_label = QLabel("🔴 Not connected")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")
        chat_panel.addWidget(self.status_label)

        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)

        input_layout = QHBoxLayout()
        input_layout.setSpacing(10)
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        self.message_input.returnPressed.connect(self.send_message) # Send on Enter
        

        self.secure_checkbox = QCheckBox("Secure")
        self.secure_checkbox.setContentsMargins(0, 0, 5, 0)
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)

        self.view_log_button = QPushButton("View Log")
        self.view_log_button.clicked.connect(self.view_log)

        self.clear_log_button = QPushButton("Clear Log")
        self.clear_log_button.clicked.connect(self.clear_log)

        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.secure_checkbox)
        input_layout.addWidget(self.send_button)
        input_layout.addWidget(self.view_log_button)
        input_layout.addWidget(self.clear_log_button)

        label = QLabel("Chat")
        label.setStyleSheet("font-size: 18px; font-weight: 800; color: #3C4F76;")
        chat_panel.addWidget(label)
        chat_panel.addWidget(self.chat_history)
        chat_panel.addLayout(input_layout)

        main_layout.addWidget(self.peer_list)
        main_layout.addLayout(chat_panel)
        # self.setLayout(main_layout) # Already set in constructor

        self.send_button.setFixedHeight(32)
        self.view_log_button.setFixedHeight(32)
        self.clear_log_button.setFixedHeight(32)

        # Styling for modern appearance with updated palette
        self.setStyleSheet("""
            QWidget {
                background-color: #DDDBF1;
                font-family: 'Arial', 'Helvetica Neue', 'DejaVu Sans';
                font-size: 14px;
            }
            QListWidget {
                background-color: #AB9F9D;
                color: black;
                border-radius: 6px;
            }
            QTextEdit {
                background-color: #3C4F76;
                color: white;
                border: 1px solid #523F38;
                border-radius: 6px;
                padding: 6px;
            }
            QLineEdit {
                background-color: #AB9F9D;
                color: #3C4F76;
                border: 1px solid #523F38;
                border-radius: 6px;
                padding: 6px;
            }
            QPushButton {
                background-color: #3C4F76;
                color: white;
                border-radius: 6px;
                padding: 6px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #1EA896;
            }
            QCheckBox {
                margin-left: 4px;
                color: #AB9F9D;
            }

            /* --- Enhancements --- */
            QPushButton {
                border-radius: 6px;
                padding: 6px;
                font-size: 14px;
            }
            QLineEdit, QTextEdit {
                font-family: 'Arial', 'Helvetica Neue', 'DejaVu Sans';
                font-size: 13px;
                font-weight: 600;
                border-radius: 8px;
                padding: 8px;
            }
            QCheckBox {
                padding: 4px;
                spacing: 8px;
                font-weight: 800;
                font-size: 14px;
            }
            QCheckBox:hover {
                font-weight: 800;
            }

            QLineEdit::placeholder {
                color: #3C4F76;
                font-style: italic;
                font-weight: 600;
            }
        """)

    def log_message(self, direction, peer_username, message, secure):
        """Logs message to file."""
        try:
            with open(LOG_FILE, "a", encoding='utf-8') as log:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                sec_flag = "(Secure)" if secure else "(Unsecure)"
                log.write(f"{timestamp} | {direction} | {peer_username} {sec_flag} | {message}\n")
        except Exception as e:
            print(f"[LOG ERROR] Failed to write to log file: {e}")

    def get_peer_username(self, ip_address):
        """Gets username for a given IP from the peers file."""
        try:
            if os.path.exists(PEERS_FILE):
                with open(PEERS_FILE, "r") as f:
                    peers = json.load(f)
                    return peers.get(ip_address, {}).get("username", ip_address)
        except Exception as e:
            print(f"[PEER FILE ERROR] Could not read peer username: {e}")
        return ip_address # Fallback to IP

    def get_cipher(self, shared_secret):
        """Generates a 3DES cipher object from a shared secret."""
        try:
            # Ensure the key is exactly 24 bytes long for 3DES
            key = str(shared_secret).zfill(24).encode('utf-8')[:24]
            return triple_des(key, ECB, padmode=PAD_PKCS5)
        except Exception as e:
            print(f"[CRYPTO ERROR] Failed to create cipher: {e}")
            return None

    # --- UDP Discovery ---

    def start_udp_discovery(self):
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # Explicitly use UDP
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.udp_socket.bind(('', UDP_PORT))
            print(f"[UDP] Bound to port {UDP_PORT}")

            # Start listening thread
            threading.Thread(target=self.listen_for_discovery, daemon=True).start()
            # Start broadcasting thread
            threading.Thread(target=self.send_discovery_loop, daemon=True).start()

        except OSError as e:
            print(f"[UDP ERROR] Binding to port {UDP_PORT} failed: {e}. Discovery might not work correctly.")
            # Consider trying a different port or informing the user.
            self.udp_socket = None # Indicate failure
        except Exception as e:
            print(f"[UDP ERROR] Unexpected error starting discovery: {e}")
            self.udp_socket = None

    def send_discovery_loop(self):
        if not self.udp_socket:
            print("[UDP] Cannot broadcast, UDP socket not available.")
            return

        
        broadcast_ip = '192.168.1.255'  

        print(f"[UDP] Starting discovery broadcast to {broadcast_ip}:{UDP_PORT}")
        while True:
            try:
                discovery_msg = json.dumps({"username": self.username, "tcp_port": TCP_PORT})
                self.udp_socket.sendto(discovery_msg.encode('utf-8'), (broadcast_ip, UDP_PORT))
                # print(f"[UDP] Broadcasted discovery: {discovery_msg}") # Reduce console noise
            except socket.error as e:
                print(f"[UDP SEND ERROR] {e}")
                # handle specific errors if needed, like network down
            except Exception as e:
                 print(f"[UDP SEND ERROR] Unexpected: {e}")

            time.sleep(DISCOVERY_INTERVAL)

    def listen_for_discovery(self):
        if not self.udp_socket:
            print("[UDP] Cannot listen, UDP socket not available.")
            return

        print(f"[UDP] Listening for discovery packets on port {UDP_PORT}")
        while self.udp_running:
            try:
                data, addr = self.udp_socket.recvfrom(1024)
                ip = addr[0]
                # Ignore self discovery packets
                if ip == self.get_local_ip():
                    continue

                msg = data.decode('utf-8')
                # print(f"[UDP RECV] From {ip}: {msg}") # Debugging
                try:
                    msg_json = json.loads(msg)
                    peer_name = msg_json.get("username")
                    peer_tcp_port = msg_json.get("tcp_port", TCP_PORT) # Assume default if not provided

                    if peer_name:
                        # print(f"[DISCOVERY] Found {peer_name} at {ip}:{peer_tcp_port}")
                        self.update_peer_file(ip, peer_name, peer_tcp_port)
                        # No need to call update_peer_list here, timer will handle it
                    else:
                         print(f"[UDP RECV] Invalid discovery message from {ip}: missing username")

                except json.JSONDecodeError:
                    print(f"[UDP RECV] Non-JSON message from {ip}: {msg}")
                except Exception as e:
                    print(f"[UDP RECV] Error processing discovery from {ip}: {e}")

            except socket.error as e:
                # Handle socket being closed during shutdown
                if "closed" in str(e).lower():
                    print("[UDP] Listener socket closed.")
                    break
                if self.udp_running:
                    print(f"[UDP RECV ERROR] Socket error: {e}")
            except Exception as e:
                print(f"[UDP RECV ERROR] Unexpected: {e}")


    def update_peer_file(self, ip, username, tcp_port):
        """Updates the peers JSON file with info and timestamp."""
        try:
            if os.path.exists(PEERS_FILE):
                try:
                    with open(PEERS_FILE, "r") as f:
                        peers = json.load(f)
                except json.JSONDecodeError:
                    peers = {} # Start fresh if file is corrupt
            else:
                peers = {}

            peers[ip] = {
                "username": username,
                "tcp_port": tcp_port,
                "last_seen": time.time()
            }
            # print(f"[PEER FILE] Updated {username} ({ip}:{tcp_port})")

            with open(PEERS_FILE, "w") as f:
                json.dump(peers, f, indent=4) # Pretty print JSON
        except Exception as e:
            print(f"[PEER FILE ERROR] Failed to update {PEERS_FILE}: {e}")

    def update_peer_list(self):
        """Refreshes the QListWidget from the peers file and removes old peers."""
        # print("[PEER LIST] Refreshing...")
        self.peer_list.clear()
        peers_changed = False
        current_peers = {}

        if not os.path.exists(PEERS_FILE):
            return

        try:
            with open(PEERS_FILE, 'r') as f:
                try:
                    peers = json.load(f)
                except json.JSONDecodeError:
                    print(f"[PEER FILE ERROR] {PEERS_FILE} is corrupted.")
                    os.remove(PEERS_FILE) # Remove corrupt file
                    return
        except FileNotFoundError:
             return # File doesn't exist yet
        except Exception as e:
            print(f"[PEER FILE ERROR] Failed to read {PEERS_FILE}: {e}")
            return

        now = time.time()
        active_peer_ips = set()

        for ip, info in peers.items():
            username = info.get("username", "Unknown")
            last_seen = info.get("last_seen", 0)
            age = now - last_seen

            current_peers[ip] = info # Keep this peer

            if age < PEER_TIMEOUT:
                status = "🟢 Online"
            elif age < PEER_OFFLINE_THRESHOLD:
                status = "🟡 Away"
            else:
                status = "🔴 Offline"

            # Only add to the list if not offline
            if age < PEER_OFFLINE_THRESHOLD:
                item_text = f"{username} ({ip}) - {status}"
                self.peer_list.addItem(item_text)
                active_peer_ips.add(ip)
            else:
                # print(f"[PEER LIST] Removing offline peer: {username} ({ip})")
                peers_changed = True
                # Do not add to peer list or active_peer_ips
                continue

        # If the currently selected peer is no longer active, deselect
        if self.selected_peer_ip and self.selected_peer_ip not in active_peer_ips:
            print(f"[SYSTEM] Selected peer {self.selected_peer_ip} is no longer active.")
            self.disconnect_current_peer() # Disconnect if they went offline

        # Write back the cleaned peer list if changes were made
        if peers_changed:
            try:
                with open(PEERS_FILE, "w") as f:
                    json.dump(current_peers, f, indent=4)
            except Exception as e:
                print(f"[PEER FILE ERROR] Failed to write cleaned {PEERS_FILE}: {e}")


    def get_local_ip(self):
        """Tries to get the primary local IP address."""
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)) # Connect to external server (doesn't send data)
            ip = s.getsockname()[0]
            return ip
        except Exception:
            return "127.0.0.1" # Fallback
        finally:
            if s:
                s.close()

    # --- TCP Communication ---

    def start_tcp_server(self):
        """Starts the TCP server to listen for incoming connections."""
        try:
            self.tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_server_socket.bind(('', TCP_PORT))
            self.tcp_server_socket.listen(5)
            print(f"[TCP SERVER] Listening on port {TCP_PORT}...")
            threading.Thread(target=self.accept_connections, daemon=True).start()
        except OSError as e:
            print(f"[TCP SERVER ERROR] Binding to port {TCP_PORT} failed: {e}. Cannot accept connections.")
            self.tcp_server_socket = None
        except Exception as e:
            print(f"[TCP SERVER ERROR] Unexpected error: {e}")
            self.tcp_server_socket = None

    def accept_connections(self):
        """Thread function to accept incoming TCP connections."""
        if not self.tcp_server_socket:
            return
        while self.tcp_server_running:
            try:
                conn, addr = self.tcp_server_socket.accept()
                print(f"[TCP SERVER] Accepted connection from {addr[0]}:{addr[1]}")
                # If already connected, decide whether to replace or reject
                if self.client_socket:
                    print(f"[TCP SERVER] Already connected to {self.selected_peer_ip}. Rejecting new connection from {addr[0]}.")
                    try:
                        reject_msg = json.dumps({"error": "Already in a chat."}) + "\n"
                        conn.sendall(reject_msg.encode('utf-8'))
                        conn.close()
                    except socket.error as e:
                        print(f"[TCP SERVER] Error sending rejection: {e}")
                    continue

                # Handle the new connection
                self.handle_incoming_connection(conn, addr[0])

            except socket.error as e:
                 # Handle server socket being closed during shutdown
                if "closed" in str(e).lower():
                    print("[TCP SERVER] Server socket closed.")
                    break
                if self.tcp_server_running:
                    print(f"[TCP SERVER ERROR] Accepting connection failed: {e}")
            except Exception as e:
                 print(f"[TCP SERVER ERROR] Unexpected error accepting connection: {e}")


    def handle_incoming_connection(self, connection_socket, peer_ip):
        """Sets up the chat state for an accepted incoming connection."""
        self.disconnect_current_peer() # Disconnect any previous connection

        self.client_socket = connection_socket
        self.selected_peer_ip = peer_ip
        peer_username = self.get_peer_username(peer_ip)
        self.current_cipher = None # Reset security state for new connection
        self.dh_private_key = None
        self.pending_secure_message = None

        self.chat_history.append(f"[System] Incoming connection from {peer_username} ({peer_ip}).")
        self.status_label.setText(f"🟢 Connected to {peer_username}")
        self.status_label.setStyleSheet("color: green; font-weight: bold;")
        
        # Start receiver thread for this connection
        self.receiver_thread = self.ReceiverThread(self.client_socket)
        self.receiver_thread.message_received.connect(self.process_received_message)
        self.receiver_thread.connection_closed.connect(self.handle_connection_closed)
        self.receiver_thread.start()

    def handle_peer_selection(self, item):
        """Handles clicking a peer in the list to initiate a connection."""
        try:
            # Extract IP: "Username (IP) - Status" -> IP
            parts = item.text().split('(')
            if len(parts) < 2: return
            ip_part = parts[1].split(')')[0]
            target_ip = ip_part.strip()

            # Check for Offline status
            if "Offline" in item.text():
                self.chat_history.append("[System] Cannot connect: selected peer is offline. Messages cannot be sent.")
                return

            if target_ip == self.selected_peer_ip:
                self.chat_history.append("[System] Already connected to this peer.")
                return

            # Get target port from peers file
            target_port = TCP_PORT # Default
            if os.path.exists(PEERS_FILE):
                 with open(PEERS_FILE, "r") as f:
                     peers = json.load(f)
                     target_port = peers.get(target_ip, {}).get("tcp_port", TCP_PORT)

            self.connect_to_peer(target_ip, target_port)

        except Exception as e:
            print(f"[UI ERROR] Error handling peer selection: {e}")
            self.chat_history.append(f"[Error] Could not parse peer information: {item.text()}")

    def connect_to_peer(self, peer_ip, peer_port):
        """Initiates a TCP connection to the selected peer."""
        self.disconnect_current_peer() # Disconnect existing connection first

        peer_username = self.get_peer_username(peer_ip)
        self.chat_history.append(f"[System] Attempting to connect to {peer_username} ({peer_ip}:{peer_port})...")

        try:
            new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            new_socket.settimeout(5) # Connection timeout
            new_socket.connect((peer_ip, peer_port))
            new_socket.settimeout(None) # Reset timeout after connection

            self.client_socket = new_socket
            self.selected_peer_ip = peer_ip
            self.current_cipher = None # Reset security
            self.dh_private_key = None
            self.pending_secure_message = None

            self.chat_history.append(f"[System] Connected successfully to {peer_username}.")
            self.status_label.setText(f"🟢 Connected to {peer_username}")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")

            # Start receiver thread for the new connection
            self.receiver_thread = self.ReceiverThread(self.client_socket)
            self.receiver_thread.message_received.connect(self.process_received_message)
            self.receiver_thread.connection_closed.connect(self.handle_connection_closed)
            self.receiver_thread.start()

        except socket.timeout:
            self.chat_history.append(f"[Error] Connection to {peer_username} timed out.")
            self.disconnect_current_peer() # Clean up failed attempt
        except socket.error as e:
            self.chat_history.append(f"[Error] Could not connect to {peer_username}: {e}")
            self.disconnect_current_peer()
        except Exception as e:
             self.chat_history.append(f"[Error] Unexpected error connecting: {e}")
             self.disconnect_current_peer()

    def disconnect_current_peer(self):
        """Safely disconnects from the current peer, if any."""
        if self.receiver_thread:
            self.receiver_thread.stop()
            self.receiver_thread.wait(1000) # Wait briefly for it to stop
            self.receiver_thread = None
        if self.client_socket:
            print(f"[SYSTEM] Disconnecting from {self.selected_peer_ip}...")
            try:
                # self.client_socket.shutdown(socket.SHUT_RDWR) # Can cause issues if already closed
                self.client_socket.close()
            except socket.error as e:
                print(f"[SOCKET] Error closing client socket during disconnect: {e}")
            finally:
                self.client_socket = None
        if self.selected_peer_ip:
             peer_username = self.get_peer_username(self.selected_peer_ip)
             self.chat_history.append(f"[System] Disconnected from {peer_username}.")
             self.selected_peer_ip = None
            # Update status label to not connected
        self.status_label.setText("🔴 Not connected")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")

        # Reset security state
        self.current_cipher = None
        self.dh_private_key = None
        self.pending_secure_message = None

    def handle_connection_closed(self):
        """Called when the receiver thread detects the connection is closed."""
        print("[SYSTEM] Connection closed signal received.")
        if self.selected_peer_ip: # Check if we were actually connected
             peer_username = self.get_peer_username(self.selected_peer_ip)
             self.chat_history.append(f"[System] Connection with {peer_username} lost.")
             self.disconnect_current_peer()


    # --- Message Handling ---

    def send_message(self):
        """Handles sending a message (securely or insecurely)."""
        if not self.client_socket or not self.selected_peer_ip:
            self.chat_history.append("[Error] No active connection. Select a peer first.")
            return

        message = self.message_input.text().strip()
        if not message:
            return

        peer_username = self.get_peer_username(self.selected_peer_ip)
        secure = self.secure_checkbox.isChecked()

        # Display message locally immediately
        lock_icon = "🔒" if secure else "🔓"
        self.chat_history.append(
            f"<div style='background-color:#1c2c3c66; border-radius:8px; padding:6px; margin:4px 0;'>"
            f"<b>You</b> {lock_icon} : {message}</div>"
        )
        QTimer.singleShot(0, self.scroll_chat_to_end)
        self.message_input.clear()

        # Log the sent message
        self.log_message(f"SENT to {peer_username}", self.username, message, secure)

        if secure:
            if self.current_cipher:
                # Secure channel already established, just encrypt and send
                self._send_encrypted(message)
            else:
                # Need to perform Diffie-Hellman key exchange first
                if self.pending_secure_message:
                    self.chat_history.append("[System] Please wait for the current secure setup to complete.")
                    return # Prevent starting another exchange

                print("[SECURE] No existing cipher. Initiating key exchange.")
                self.pending_secure_message = message # Store message to send after exchange
                self.initiate_key_exchange()
        else:
            # Send unencrypted message
            msg_obj = {"type": "unsecure", "content": message}
            self._send_json(msg_obj)

    def _send_json(self, data_dict):
        """Sends a dictionary as a JSON string over the TCP socket."""
        if not self.client_socket:
            print("[SEND ERROR] No client socket to send JSON.")
            self.chat_history.append("[Error] Connection lost. Cannot send message.")
            # Consider attempting reconnect or informing user more clearly
            return False
        try:
            json_string = json.dumps(data_dict) + "\n" # Add newline as delimiter
            self.client_socket.sendall(json_string.encode('utf-8'))
            print(f"[SEND] Sent JSON: {data_dict}")
            return True
        except socket.error as e:
            print(f"[SEND ERROR] Socket error sending JSON: {e}")
            self.chat_history.append(f"[Error] Failed to send message: {e}")
            self.handle_connection_closed() # Assume connection is dead
            return False
        except Exception as e:
            print(f"[SEND ERROR] Unexpected error sending JSON: {e}")
            self.chat_history.append(f"[Error] Failed to send message: {e}")
            return False

    def _send_encrypted(self, plain_text):
        """Encrypts and sends a message using the current cipher."""
        if not self.current_cipher:
            print("[SEND ERROR] Cannot encrypt, no cipher available.")
            self.chat_history.append("[Error] Secure channel not established.")
            # This case should ideally be handled before calling _send_encrypted
            return False

        try:
            encrypted_bytes = self.current_cipher.encrypt(plain_text.encode('utf-8'))
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
            msg_obj = {"type": "secure", "content": encrypted_b64}
            print(f"[SECURE SEND] Encrypted '{plain_text}' as b64: {encrypted_b64[:20]}...") # Debug
            return self._send_json(msg_obj)
        except Exception as e:
            print(f"[CRYPTO/SEND ERROR] Failed to encrypt and send: {e}")
            self.chat_history.append(f"[Error] Failed to send secure message: {e}")
            return False


    def process_received_message(self, json_string):
        """Processes a received JSON string message."""
        from PyQt5.QtCore import QThread, QTimer
        try:
            message_data = json.loads(json_string)
            msg_type = message_data.get("type")
            peer_username = self.get_peer_username(self.selected_peer_ip) if self.selected_peer_ip else "Unknown Peer"

            print(f"[PROCESS RECV] Received type: {msg_type} from {peer_username}") # Debug

            if msg_type == "unsecure":
                content = message_data.get("content", "")
                self.chat_history.append(
                    f"<div style='background-color:#ffffff22; border-radius:8px; padding:6px; margin:4px 0;'>"
                    f"<b>{peer_username}</b> 🔓 : {content}</div>"
                )
                QTimer.singleShot(0, self.scroll_chat_to_end)
                self.log_message(f"RECV from {peer_username}", self.username, content, False)

            elif msg_type == "secure":
                if self.current_cipher:
                    try:
                        encrypted_b64 = message_data.get("content", "")
                        encrypted_bytes = base64.b64decode(encrypted_b64)
                        decrypted_bytes = self.current_cipher.decrypt(encrypted_bytes)
                        decrypted_message = decrypted_bytes.decode('utf-8')
                        self.chat_history.append(
                            f"<div style='background-color:#2f4f4f44; border-radius:8px; padding:6px; margin:4px 0;'>"
                            f"<b>{peer_username}</b> 🔒 : {decrypted_message}</div>"
                        )
                        QTimer.singleShot(0, self.scroll_chat_to_end)
                        self.log_message(f"RECV from {peer_username}", self.username, decrypted_message, True)
                    except (base64.binascii.Error, ValueError) as e: # Catch padding/decoding errors
                        print(f"[CRYPTO ERROR] Decryption/Decode failed: {e}")
                        self.chat_history.append(f"[Error] Received corrupted secure message from {peer_username}.")
                        QTimer.singleShot(0, self.scroll_chat_to_end)
                    except Exception as e:
                        print(f"[CRYPTO ERROR] Decryption failed unexpectedly: {e}")
                        self.chat_history.append(f"[Error] Failed to decrypt message from {peer_username}.")
                        QTimer.singleShot(0, self.scroll_chat_to_end)

                else:
                    print("[PROCESS RECV] Received secure message but no cipher is set up.")
                    self.chat_history.append(f"[Warning] Received secure message from {peer_username} before secure channel was established.")
                    QTimer.singleShot(0, self.scroll_chat_to_end)
                    # Optionally: Request key exchange again? Or drop message?

            elif msg_type == "key_init":
                # Peer wants to start key exchange, they sent their public key
                print("[SECURE] Received key exchange initiation request.")
                peer_public_key = int(message_data.get("public_key", 0))
                if peer_public_key:
                    self.respond_to_key_exchange(peer_public_key)
                else:
                    print("[SECURE] Invalid key_init message received.")

            elif msg_type == "key_resp":
                # Peer responded with their public key to our initiation
                print("[SECURE] Received key exchange response.")
                peer_public_key = int(message_data.get("public_key", 0))
                if peer_public_key and self.dh_private_key is not None:
                    self.complete_key_exchange(peer_public_key)
                else:
                    print("[SECURE] Invalid key_resp or missing private key.")
                    # Reset state maybe?
                    self.pending_secure_message = None
                    self.dh_private_key = None

            elif msg_type == "error":
                error_msg = message_data.get("message", "Unknown error")
                self.chat_history.append(f"[Peer Error] {peer_username}: {error_msg}")
                QTimer.singleShot(0, self.scroll_chat_to_end)

            else:
                print(f"[PROCESS RECV] Unknown message type received: {msg_type}")

        except json.JSONDecodeError:
            print(f"[PROCESS RECV ERROR] Received non-JSON message: {json_string}")
        except Exception as e:
            print(f"[PROCESS RECV ERROR] Error processing message: {e}")


    # --- Key Exchange ---

    def initiate_key_exchange(self):
        """Starts the Diffie-Hellman key exchange by sending our public key."""
        if not self.client_socket:
             print("[SECURE] Cannot initiate key exchange, no connection.")
             self.pending_secure_message = None # Clear pending message
             return

        # 1. Generate our private/public keys
        self.dh_private_key = random.randint(1, DH_P - 1)
        public_key = pow(DH_G, self.dh_private_key, DH_P)
        print(f"[DH] Initiating: Private={self.dh_private_key}, Public={public_key}") # Debug

        # 2. Send our public key to the peer
        key_init_msg = {"type": "key_init", "public_key": str(public_key)}
        if self._send_json(key_init_msg):
            self.chat_history.append("[System] Initiating secure channel setup...")
        else:
             # Sending failed, reset state
             self.chat_history.append("[Error] Failed to initiate secure channel setup.")
             self.dh_private_key = None
             self.pending_secure_message = None

    def respond_to_key_exchange(self, peer_public_key):
        """Responds to a key exchange initiation from a peer."""
        if not self.client_socket:
            print("[SECURE] Cannot respond to key exchange, no connection.")
            return

        # 1. Generate our private/public keys
        self.dh_private_key = random.randint(1, DH_P - 1) # Use self.dh_private_key consistently
        public_key = pow(DH_G, self.dh_private_key, DH_P)
        print(f"[DH] Responding: Private={self.dh_private_key}, Public={public_key}") # Debug

        # 2. Calculate the shared secret
        shared_secret = pow(peer_public_key, self.dh_private_key, DH_P)
        print(f"[DH] Responder calculated Shared Secret: {shared_secret}") # Debug

        # 3. Create the cipher
        self.current_cipher = self.get_cipher(shared_secret)
        if not self.current_cipher:
            self.chat_history.append("[Error] Failed to create cipher during key exchange response.")
            self.dh_private_key = None # Reset state
            return

        # 4. Send our public key back to the initiator
        key_resp_msg = {"type": "key_resp", "public_key": str(public_key)}
        if self._send_json(key_resp_msg):
            self.chat_history.append("[System] Secure channel established (Responder).")
        else:
            # Sending response failed
            self.chat_history.append("[Error] Failed to send key exchange response.")
            self.current_cipher = None # Reset security state
            self.dh_private_key = None

    def complete_key_exchange(self, peer_public_key):
        """Completes the key exchange after receiving the peer's response key."""
        if self.dh_private_key is None:
             print("[SECURE] Cannot complete key exchange, initiator's private key is missing.")
             # This might happen if we receive key_resp unexpectedly
             return

        # 1. Calculate the shared secret
        shared_secret = pow(peer_public_key, self.dh_private_key, DH_P)
        print(f"[DH] Initiator calculated Shared Secret: {shared_secret}") # Debug

        # 2. Create the cipher
        self.current_cipher = self.get_cipher(shared_secret)
        if not self.current_cipher:
             self.chat_history.append("[Error] Failed to create cipher during key exchange completion.")
             self.dh_private_key = None
             self.pending_secure_message = None
             return

        self.chat_history.append("[System] Secure channel established (Initiator).")

        # 3. Send the originally intended message (if any)
        if self.pending_secure_message:
             print(f"[SECURE] Sending pending message: {self.pending_secure_message}")
             if self._send_encrypted(self.pending_secure_message):
                 # Successfully sent
                 pass
             else:
                  # Failed to send pending message
                  self.chat_history.append("[Error] Failed to send the message after secure setup.")
                  # Keep cipher, but maybe clear pending message? Or allow retry?

        # 4. Clear pending state
        self.pending_secure_message = None
        # Keep self.dh_private_key? No strong reason to keep it after secret is derived.
        # self.dh_private_key = None # Optional: Clear private key after use


    # --- Utility / UI ---

    def view_log(self):
        """Displays the content of the log file in the chat history."""
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, "r", encoding='utf-8') as f:
                    content = f.read()
                self.chat_history.append("\n--- Log History ---\n" + content + "--- End Log ---")
            except Exception as e:
                self.chat_history.append(f"[Log Error] Failed to read log file: {e}")
        else:
            self.chat_history.append("[Log History] No log file found.")

    def clear_log(self):
        """Clears the log file and updates the chat history."""
        try:
            if os.path.exists(LOG_FILE):
                os.remove(LOG_FILE)
                self.chat_history.append("Chat history cleared.")
            else:
                self.chat_history.append("No log file to clear.")
        except Exception as e:
            self.chat_history.append(f"[Log Error] Failed to clear log file: {e}")

    ## for auto scrolling bug
    def scroll_chat_to_end(self):
        app = QApplication.instance()
        if not app or app.closingDown() or getattr(self, "_shutting_down", False) or not hasattr(self, "chat_history"):
            return
        if QThread.currentThread() == app.thread():
            if self.chat_history:
                cursor = self.chat_history.textCursor()
                cursor.movePosition(QTextCursor.End)
                self.chat_history.setTextCursor(cursor)
                self.chat_history.ensureCursorVisible()
        else:
            try:
                QMetaObject.invokeMethod(self.chat_history, "moveCursor", Qt.QueuedConnection, QTextCursor.End)
            except RuntimeError:
                print("[DEBUG] Skipped invokeMethod during shutdown.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    from PyQt5.QtGui import QFont
    app.setFont(QFont("Arial", 11))
    app.setStyle('Fusion')
    window = ChatWindow()
    window.show()
    sys.exit(app.exec_())

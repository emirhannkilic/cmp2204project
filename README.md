# Peer-to-Peer Chat Application (CMP2204)

A LAN-based peer-to-peer chat application implemented in Python using UDP for peer discovery and TCP for reliable messaging.

This project demonstrates practical networking concepts including socket programming, client-server architecture, multithreading, and optional encrypted communication.

---

## Overview

The system enables users within the same Local Area Network (LAN) to:

- Discover active peers dynamically
- Establish TCP connections
- Exchange real-time messages
- Optionally encrypt messages before transmission

The architecture separates discovery and communication layers to maintain modularity and clarity.

---

## System Architecture

### Peer Discovery (UDP)
- Uses UDP broadcasting
- Service announcer broadcasts availability
- Discovery server listens and maintains active peer list

### Messaging Layer (TCP)
- TCP used for reliable communication
- Supports client/server interaction model
- Multiple peers can connect simultaneously

### Optional Encryption
- Messages can be encrypted before transmission
- Encryption handled using `pyDes`
- Designed to demonstrate secure communication principles

---

## Tech Stack

- Python 3
- socket (TCP & UDP)
- threading
- PyQt5 (GUI version)
- pyDes (encryption)

---

## Installation

Install required dependencies:

```bash
pip install pyDes
pip install PyQt5
```
---

## Running the Application

### Modular Terminal Mode

Open separate terminals:

Terminal 1 – Service Announcer
```bash
python3 UDPclient.py
```
Terminal 2 – Peer Discovery
```bash
python3 UDPserver.py
```
Terminal 3 – Chat Server
```bash
python3 TCPserver.py
```
Terminal 4 – Chat Client
```bash
python3 TCPclient.py
```
### All-in-One Console Version
```bash
python3 chatui.py
```
---
## Networking Concepts Demonstrated
- TCP vs UDP communication
- Broadcast-based peer discovery
- Client-server architecture
- Real-time messaging systems
---
## Academic Context
Developed for:
### CMP2204 – Introduction to Computer Networks | Bahçeşehir University

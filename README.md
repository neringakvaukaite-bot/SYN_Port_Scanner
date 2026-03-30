# 🔍 SYN Port Scanner
A multi-threaded TCP SYN (half-open) port scanner built in Python using Scapy.

This project demonstrates low-level network scanning by crafting raw TCP packets and analyzing responses. It is designed for educational purposes and to better understand how real-world tools like Nmap work internally.

---

## 🚀 Features

- ⚡ Multi-threaded scanning (faster performance)
- 🧠 Low-level packet crafting using Scapy
- 🎯 SYN (half-open) scanning technique
- 🔧 Custom port range support
- ⏱ Adjustable timeout and thread count
- 🧼 Clean and readable output

---

## ⚙️ How It Works

This scanner performs a **TCP SYN scan**:

1. Sends a SYN packet to a target port  
2. Waits for a response  
3. Interprets the response:
   - `SYN-ACK (0x12)` → Port is **OPEN**
   - `RST-ACK (0x14)` → Port is **CLOSED**
4. Sends a `RST` packet to avoid completing the full TCP handshake  

This technique is known as a **half-open scan**.

---

## 🧪 Example Usage

Below is a real example of the scanner in action:

### Command:

```bash

sudo python3 syn_scanner.py -p 1-500 192.168.101.5

```

### Output

```bash

[!] SYN scanning 192.168.101.5 from port 1 to 500

[+] Port 139 OPEN
[+] Port 135 OPEN
[+] Port 445 OPEN

[!] Scan complete.
[!] Open ports found: 135, 139, 445

```
---

## 🧩 Technologies Used

- Python 3  
- Scapy (packet manipulation)  
- ThreadPoolExecutor (multi-threading)  
- Argparse (CLI interface)  

---

## 📦 Installation

```bash
git clone https://github.com/neringakvaukaite-bot/syn-port-scanner.git
cd syn-port-scanner
pip install scapy

```

⚠️ Important
This tool requires root (administrator) privileges to send raw packets.
👉 Without root privileges, the scanner may not work correctly.


## Author
Neringa Kvaukaite

import argparse
import threading
import logging
from concurrent.futures import ThreadPoolExecutor

from scapy.all import IP, TCP, sr1, send, conf, RandShort

# Silence Scapy output
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# Argument parser

def parse_args():
    parser = argparse.ArgumentParser(description="SYN Port Scanner")
    parser.add_argument("target", help="Target Ip address")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g. 20-80)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout in seconds per probe")

    return parser.parse_args()

# Validate port range
def validate_port_range(port_range: str):
    try:
        start_port, end_port = map(int,port_range.split("-"))

    except ValueError:
        raise ValueError("Port range must be in format start-end, e.g. 1-1024")

    if not (1<= start_port <= 65535 and 1<= end_port <=65535):
        raise ValueError("Ports must be between 1 and 65535")

    if start_port > end_port:
        raise ValueError("Start port cannot be greater than end port")

    return start_port, end_port

def syn_scan(target: str, start_port: int, end_port: int, threads: int, timeout: float):
    lock = threading.Lock()
    open_ports = []

    print(f"\n[!] SYN scanning {target} from port  {start_port} to {end_port}\n")


    def scan(port):
        try:
            # Use a random source port so the reset matches the probe
            sport = RandShort()
            # Create SYN packet
            syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
            # Send and receive response
            response = sr1(syn_packet, timeout=timeout, verbose=0)

            if response is None:
                return

            if response.haslayer(TCP):
                flags = int(response[TCP].flags)

                #SYN-ACK = OPEN
                if flags == 0x12:
                    with lock:
                        print(f"[+] Port {port} OPEN")
                        open_ports.append(port)

                   # Send RST to close connection (stealth)
                    rst_packet = IP(dst=target)/TCP( dport=port, flags="R")
                    send(rst_packet, verbose=0)

                # RST-ACK = CLOSED

                elif flags == 0x14:
                    return

        except Exception as e:
            with lock:
                print(f"[!] There's been a mistake with port {port}: {e}")

    # Run threads
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(scan, range(start_port, end_port + 1))


    print("\n[!] Scan complete.")

    if open_ports:
        print("[!] Open ports found:", ", ".join(map(str, sorted(open_ports))))

    else:
        print("[!] No open ports found.")


def main():
    args = parse_args()

    try:
        start_port, end_port = validate_port_range(args.ports)

    except ValueError as e:
        print(f"[!] Argument error: {e}")
        return


    syn_scan(
        target=args.target,
        start_port=start_port,
        end_port=end_port,
        threads=args.threads,
        timeout=args.timeout
)

if __name__ == "__main__":
    main()



import socket
import threading
from queue import Queue

def scan_port(ip, port):
    """Scans a single port on a given IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[+] Port {port} is open on {ip}")
        sock.close()
    except socket.error as e:
        print(f"Error connecting to {ip}:{port} - {e}")

def port_scanner(ip_address, ports):
    """Scans a range of ports on a given IP address using threads."""
    try:
        ip = socket.gethostbyname(ip_address)
    except socket.gaierror:
        print(f"[-] Could not resolve hostname: {ip_address}")
        return

    print(f"[*] Scanning ports on {ip}")
    port_queue = Queue()
    for port in ports:
        port_queue.put(port)

    def worker():
        while not port_queue.empty():
            port = port_queue.get()
            scan_port(ip, port)

    threads = []

    for _ in range(20):  # Adjust the number of threads as needed
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    target_ip = input("Enter target IP address or hostname: ")
    port_range_str = input("Enter port range (e.g., 1-1024, 80,443): ")

    ports_to_scan = []
    port_ranges = port_range_str.split(',')
    for prange in port_ranges:
        if '-' in prange:
            start, end = map(int, prange.split('-'))
            ports_to_scan.extend(range(start, end + 1))
        else:
            ports_to_scan.append(int(prange))

    port_scanner(target_ip, ports_to_scan)
    
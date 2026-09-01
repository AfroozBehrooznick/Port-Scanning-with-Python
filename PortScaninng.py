import socket
import concurrent.futures
import time
from scapy.all import IP, TCP, sr1


def check_ip(target):
    # Resolve hostname to IP address
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Could not resolve target: {target}")
        return None


def identify_service(port):
    # Identify service by port number
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(ip_address, port):
    # Try to grab service banner
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        sock.connect((ip_address, port))

        # Send HTTP request to web servers
        if port in [80, 8000, 8008, 8080]:
            request = (
                f"HEAD / HTTP/1.0\r\n"
                f"Host: {ip_address}\r\n\r\n"
            )
            sock.send(request.encode())

        banner = sock.recv(1024).decode(errors="ignore").strip()

        if banner:
            return banner.split("\n")[0].strip()

    except (socket.timeout, socket.error):
        pass

    finally:
        sock.close()

    return "Unknown"


def scan_port(ip_address, port):
    # Scan one TCP port using socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    try:
        result = sock.connect_ex((ip_address, port))

        if result == 0:
            return {
                "port": port,
                "state": "OPEN"
            }

    except socket.error:
        pass

    finally:
        sock.close()

    return None


def syn_scan_port(ip_address, port):
    # Send TCP SYN packet using Scapy
    packet = IP(dst=ip_address) / TCP(dport=port,flags="S")

    try:
        response = sr1(packet,timeout=1,verbose=0)

        if response is None:
            return None

        if response.haslayer(TCP):

            # SYN-ACK means the port is open
            if response[TCP].flags & 0x12 == 0x12:
                return {
                    "port": port,
                    "state": "OPEN"
                }

            # RST means the port is closed
            if response[TCP].flags & 0x04:
                return {
                    "port": port,
                    "state": "CLOSED"
                }

    except Exception:
        pass

    return None


def scan(target, start_port, end_port, threads, scan_type):
    # Run socket-based TCP scan or SYN scan 
    ip_address = check_ip(target)

    if ip_address is None:
        return []

    start_time = time.time()
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        if scan_type == 1:
            futures = [ executor.submit(scan_port,ip_address,port) for port in range(start_port,end_port+1) ]
        elif scan_type ==2:
            futures = [ executor.submit(syn_scan_port,ip_address,port) for port in range(start_port,end_port+1) ]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()

            if result:
                results.append(result)

    elapsed = time.time() - start_time

    return {
        "target": target,
        "ip": ip_address,
        "results": results,
        "time": elapsed
    }


def print_scan_results(scan_data):
    # Print scan information
    print(f"\n[#] Target: {scan_data['target']}")
    print(f"[#] IP Address: {scan_data['ip']}")
    print(f"[#] Scan Time: {scan_data['time']:.2f} seconds")
    print("\nPORT\t\tSTATE\tSERVICE\t\tBANNER")
    print("-" * 60)

    for result in sorted(scan_data["results"],key=lambda x: x["port"]):
        port = result["port"]

        service = identify_service(port)
        banner = grab_banner(scan_data["ip"],port)

        print(
            f"{port}/tcp\t\t"
            f"{result['state']}\t"
            f"{service}\t\t"
            f"{banner}"
        )


# Start project
target = input("Enter target IP or hostname: ")
rangePort = input("Enter range port: (like 1-1024) ").split('-')
startPort, endPort = int(rangePort[0]), int(rangePort[1])
scanType = int(input("Enter number of scan type <1.TCP Connect 2.SYN> : "))

scanData = scan(target,startPort,endPort,100,scanType)

if scanData:
    print_scan_results(scanData)
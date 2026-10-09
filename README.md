# Python Port Scanner

A simple TCP port scanner written in Python.

This project scans a target IP address or hostname and finds open TCP ports. It supports two scanning methods:

- TCP Connect Scan using Python `socket`
- TCP SYN Scan using `Scapy`

It also identifies common services based on port numbers and tries to grab service banners.

## Features

- Scan an IP address or hostname
- Scan a custom port range
- TCP Connect Scan
- TCP SYN Scan
- Multi-threaded scanning
- Basic service identification
- Simple banner grabbing
- Scan time measurement
- Simple and readable output

## Technologies

- Python
- Socket
- Scapy
- Concurrent Futures
- TCP/IP

## Installation

Make sure Python is installed.

Install Scapy with:

```bash
pip install scapy
```

## Usage

Run the program:

```bash
python PortScanning.py
```

The program asks for:

```text
Enter target IP or hostname:
Enter range port: (like 1-1024)
Enter number of scan type <1.TCP Connect 2.SYN> :
```

### Example

```text
Enter target IP or hostname: 127.0.0.1
Enter range port: (like 1-1024) 1-1000
Enter number of scan type <1.TCP Connect 2.SYN> : 1
```

## Scan Types

### 1. TCP Connect Scan

Uses Python's `socket` library to connect to each TCP port.

If the connection succeeds, the port is considered open.

```text
Socket → TCP Connection → Open Port
```

### 2. SYN Scan

Uses Scapy to send TCP SYN packets.

The scanner checks the response:

```text
SYN-ACK → Open
RST     → Closed
No response → No result
```

This method works at the packet level and does not use a normal TCP connection like the socket scanner.

## Service Identification

When an open port is found, the program tries to identify the common service associated with that port.

For example:

```text
22   → SSH
80   → HTTP
443  → HTTPS
25   → SMTP
3306 → MySQL
```

This is based on the standard service-to-port mapping, so it should be considered an initial identification rather than complete service fingerprinting.

## Banner Grabbing

The scanner also tries to read a service banner from open ports.

For HTTP ports, it sends a simple HTTP request and reads the response.

Example:

```text
22/tcp    OPEN    ssh      SSH-2.0-OpenSSH
80/tcp    OPEN    http     HTTP/1.1 200 OK
```

Not every service provides a readable banner, so some results may show:

```text
Unknown
```

## Multi-threading

The scanner uses `ThreadPoolExecutor` to scan multiple ports at the same time.

This makes scanning much faster than checking every port sequentially.

The current scanner uses:

```text
100 threads
```

## Project Structure

The project is currently implemented in a single Python file:

```text
PortScanning.py
```

Main functions:

```text
check_ip()
    Resolves the target hostname or IP.

identify_service()
    Identifies common services by port number.

grab_banner()
    Tries to retrieve a service banner.

scan_port()
    Performs a TCP Connect Scan.

syn_scan_port()
    Performs a TCP SYN Scan using Scapy.

scan()
    Runs the selected scanning method.

print_scan_results()
    Displays the scan results.
```

## Example Output

```text
[#] Target: 127.0.0.1
[#] IP Address: 127.0.0.1
[#] Scan Time: 1.42 seconds

PORT            STATE   SERVICE         BANNER
------------------------------------------------------------
22/tcp          OPEN    ssh             SSH-2.0-OpenSSH
80/tcp          OPEN    http            HTTP/1.1 200 OK
443/tcp         OPEN    https           Unknown
------------------------------------------------------------
```

## Limitations

This project is a simple educational port scanner.

Current limitations include:

- Service identification is mainly based on port numbers.
- Banner grabbing does not work with every service.
- Only TCP ports are scanned.
- UDP scanning is not implemented.
- Advanced service version detection is not implemented.
- OS detection is not implemented.

## Disclaimer

Use this tool only on systems you own or have permission to test.

Unauthorized port scanning may be considered suspicious or prohibited depending on the target and network.

### Writer

Afrooz Behrooznick

#!/usr/bin/env python3

import socket
import os
import sys
import subprocess
from datetime import datetime
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

# Create logs directory if not exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Banner
def banner():
    print(Fore.MAGENTA + Style.BRIGHT + r"""
    ================================================
          P R O F E S S O R   S C A N N E R
    -----------------------------------------------
      Auto IP Resolver | Port Scanner | Ping Check
      HTTP/HTTPS Detect | Log Saver | Python Tool
    ================================================
    """)

# Resolve domain to IP
def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        print(Fore.CYAN + f"[✓] Resolved {target} to {ip}")
        return ip
    except socket.gaierror:
        print(Fore.RED + f"[×] Failed to resolve domain: {target}")
        sys.exit()

# Ping check (cross-platform)
def ping_target(ip):
    print(Fore.YELLOW + f"[i] Pinging {ip}...")
    try:
        output = subprocess.check_output(["ping", "-c", "1", ip], stderr=subprocess.DEVNULL)
        print(Fore.GREEN + "[✓] Host is ONLINE")
        return True
    except subprocess.CalledProcessError:
        print(Fore.RED + "[×] Host is OFFLINE or not reachable")
        return False

# Scan ports with range
def scan_ports(ip, start_port, end_port, log_file):
    open_ports = []
    unsecured_ports = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}
    print(Fore.YELLOW + f"\n[~] Scanning {ip} from port {start_port} to {end_port}...\n")

    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.1)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                service = unsecured_ports.get(port, "")
                tag = f" (Unsecured: {service})" if service else ""
                print(Fore.GREEN + f"[+] Port {port} is OPEN{tag}")
                log_file.write(f"OPEN PORT: {port}{tag}\n")
            s.close()
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Scan interrupted by user.")
            sys.exit()
        except socket.error:
            print(Fore.RED + f"[×] Could not connect to port {port}")
            continue

    return open_ports

# Detect HTTP/HTTPS
def detect_http_https(open_ports):
    if 443 in open_ports:
        return "HTTPS"
    elif 80 in open_ports:
        return "HTTP"
    else:
        return "None"

# Main function
def main():
    banner()
    target = input(Fore.CYAN + "[?] Enter target domain or IP: ").strip()
    ip = resolve_target(target)

    start_port = int(input(Fore.CYAN + "[?] Start port (e.g. 1): "))
    end_port = int(input(Fore.CYAN + "[?] End port (e.g. 65535): "))

    # Create log file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"logs/professor_{target.replace('.', '_')}_{timestamp}.txt"
    with open(log_filename, "w") as log_file:
        log_file.write(f"Professor Scan Report\nTarget: {target} ({ip})\n")
        log_file.write(f"Port Range: {start_port}-{end_port}\n")
        log_file.write(f"Scan Time: {timestamp}\n\n")

        # Ping check
        online = ping_target(ip)
        log_file.write(f"Host Online: {online}\n")

        # Port scan
        open_ports = scan_ports(ip, start_port, end_port, log_file)

        # HTTP/HTTPS detection
        protocol = detect_http_https(open_ports)
        log_file.write(f"\nHTTP/HTTPS: {protocol}\n")

    print(Fore.CYAN + f"\n[✓] Scan complete. Log saved to: {log_filename}")

if __name__ == "__main__":
    main()

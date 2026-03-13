import nmap
import shutil
import socket
from urllib.parse import urlparse
from colorama import Fore, Style

# common ports to scan
PORTS = "21,22,23,25,80,443,3306,3389,8080"


def scan_ports(target: str) -> None:
    # extract hostname if url provided
    if target.startswith("http"):
        target = urlparse(target).hostname

    print(f"[+] Scanning ports on {target}")

    if shutil.which("nmap"):
        try:
            nm = nmap.PortScanner()
            nm.scan(target, PORTS)
        except Exception as e:
            print(f"[!] nmap scan failed; falling back to simple socket scan ({e})")
        else:
            if target not in nm.all_hosts():
                print(f"[!] No hosts found during scan")
                return

            hostinfo = nm[target]
            for proto in hostinfo.all_protocols():
                lport = hostinfo[proto].keys()
                for port in sorted(lport):
                    state = hostinfo[proto][port]["state"]
                    service = hostinfo[proto][port].get("name", "")
                    print(f"{Fore.YELLOW}Port {port}/{proto} {state} {service}{Style.RESET_ALL}")
            return
    else:
        print("[!] nmap not found in PATH; using simple socket scan")

    # Fallback: try connecting to each well-known port
    for port in map(int, PORTS.split(",")):
        try:
            with socket.create_connection((target, port), timeout=1):
                print(f"{Fore.YELLOW}Port {port}/tcp open{Style.RESET_ALL}")
        except Exception:
            pass

    if target not in nm.all_hosts():
        print(f"[!] No hosts found during scan")
        return

    hostinfo = nm[target]
    for proto in hostinfo.all_protocols():
        lport = hostinfo[proto].keys()
        for port in sorted(lport):
            state = hostinfo[proto][port]["state"]
            service = hostinfo[proto][port].get("name", "")
            print(f"{Fore.YELLOW}Port {port}/{proto} {state} {service}{Style.RESET_ALL}")

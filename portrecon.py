#!/usr/bin/env python3
"""
portrecon - quick and dirty TCP port scanner with banner grabbing.

I got tired of firing up nmap for a simple "is this port open and what's
listening on it" check during recon, so this is a small standalone script
that does just that. Nothing fancy - threaded connect() scans plus a raw
banner grab, with a fallback service guess table for the common stuff.

Usage:
    python3 portrecon.py 10.0.0.5
    python3 portrecon.py 10.0.0.5 -p 1-1000
    python3 portrecon.py scanme.nmap.org -p 22,80,443,8080 --json out.json
"""

import argparse
import concurrent.futures
import json
import socket
import sys
import time

# Fallback guesses for when a service doesn't send a banner on connect.
# Not exhaustive, just the ports I run into most often.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}

DEFAULT_TIMEOUT = 1.0


def parse_port_range(spec):
    """Turns '22,80,1000-1010' into a sorted list of ints."""
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p <= 65535)


def grab_banner(sock, port):
    """Try to read whatever the service says first. HTTP-ish ports need a nudge."""
    try:
        sock.settimeout(0.8)
        if port in (80, 8080, 8000, 8888):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(256)
        return data.decode(errors="replace").strip().replace("\r\n", " | ")[:120]
    except Exception:
        return ""


def scan_port(host, port, timeout):
    result = {"port": port, "state": "closed", "service": COMMON_PORTS.get(port, ""), "banner": ""}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((host, port))
        if rc == 0:
            result["state"] = "open"
            banner = grab_banner(s, port)
            if banner:
                result["banner"] = banner
    except socket.gaierror:
        raise
    except Exception:
        pass
    finally:
        s.close()
    return result


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {host}", file=sys.stderr)
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="Small threaded TCP port scanner with banner grabbing.")
    ap.add_argument("target", help="hostname or IP to scan")
    ap.add_argument("-p", "--ports", default="1-1024",
                     help="ports/ranges, e.g. '22,80,443' or '1-1024' (default: 1-1024)")
    ap.add_argument("-t", "--threads", type=int, default=200, help="worker threads (default: 200)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-port timeout in seconds")
    ap.add_argument("--json", metavar="FILE", help="also write results as JSON to this file")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print open ports")
    args = ap.parse_args()

    ip = resolve(args.target)
    ports = parse_port_range(args.ports)

    print(f"[*] Scanning {args.target} ({ip}) - {len(ports)} ports, {args.threads} threads")
    started = time.time()

    open_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_port, ip, p, args.timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                continue
            if res["state"] == "open":
                open_results.append(res)
                line = f"  {res['port']:>5}/tcp  open"
                if res["service"]:
                    line += f"  {res['service']}"
                if res["banner"]:
                    line += f"  -- {res['banner']}"
                print(line)

    open_results.sort(key=lambda r: r["port"])
    elapsed = time.time() - started
    if not args.quiet:
        print(f"[*] Done in {elapsed:.2f}s - {len(open_results)} open port(s) found")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"target": args.target, "ip": ip, "open_ports": open_results}, f, indent=2)
        print(f"[*] Results written to {args.json}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted, bailing out")
        sys.exit(130)

#!/usr/bin/env python3
"""CodeAlpha Task 1 - Network Sniffer v2 (scapy).

Adds: DNS query names, HTTP request parsing, cleartext-credential alerts,
and simple port-scan detection.

    sudo python3 sniffer_v2.py -i eth0 -c 100 -o capture.pcap
"""
import argparse
import time
from collections import Counter, defaultdict, deque
from datetime import datetime

from scapy.all import (ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, Raw,
                       sniff, wrpcap)

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ")
SENSITIVE = (b"password", b"passwd", b"pwd=", b"username=", b"token",
             b"authorization:", b"api_key", b"apikey")
SCAN_WINDOW = 10      # seconds
SCAN_THRESHOLD = 15   # distinct ports from one source within the window

captured = []
stats = Counter()
alerts = []
syn_tracker = defaultdict(deque)   # src -> deque[(time, dport)]
scan_alerted = set()


def now():
    return datetime.now().strftime("%H:%M:%S")


def alert(msg):
    alerts.append(f"[{now()}] {msg}")
    print(f"  [!] ALERT: {msg}")


def payload_preview(pkt, limit=60):
    if pkt.haslayer(Raw):
        data = bytes(pkt[Raw].load)[:limit]
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return ""


def describe(pkt):
    proto, sport, dport = "OTHER", "", ""
    if pkt.haslayer(ARP):
        return pkt[ARP].psrc, pkt[ARP].pdst, "ARP", sport, dport
    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return "?", "?", proto, sport, dport
    if pkt.haslayer(TCP):
        proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    return src, dst, proto, sport, dport


def dns_query(pkt):
    """Return the queried name for DNS requests, else None."""
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        return pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    return None


def http_request(pkt):
    """Return (request_line, host) for plain HTTP requests, else None."""
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        data = bytes(pkt[Raw].load)
        if data.startswith(HTTP_METHODS):
            lines = data.split(b"\r\n")
            host = ""
            for line in lines[1:]:
                if line.lower().startswith(b"host:"):
                    host = line.split(b":", 1)[1].strip().decode(errors="ignore")
            return lines[0].decode(errors="ignore"), host
    return None


def check_port_scan(pkt, src):
    """Flag a source that sends SYNs to many distinct ports quickly."""
    if not pkt.haslayer(TCP) or src in scan_alerted:
        return
    flags = int(pkt[TCP].flags)
    if flags & 0x02 and not flags & 0x10:      # SYN without ACK
        t = time.time()
        q = syn_tracker[src]
        q.append((t, pkt[TCP].dport))
        while q and t - q[0][0] > SCAN_WINDOW:
            q.popleft()
        ports = {p for _, p in q}
        if len(ports) >= SCAN_THRESHOLD:
            scan_alerted.add(src)
            alert(f"Possible port scan from {src} "
                  f"({len(ports)} ports in {SCAN_WINDOW}s)")


def handle(pkt):
    captured.append(pkt)
    src, dst, proto, sport, dport = describe(pkt)
    stats[proto] += 1

    left = f"{src}:{sport}" if sport != "" else src
    right = f"{dst}:{dport}" if dport != "" else dst
    print(f"[{now()}] {proto:<5} {left} -> {right}  len={len(pkt)}")

    name = dns_query(pkt)
    if name:
        stats["DNS-query"] += 1
        print(f"         DNS query: {name}")

    http = http_request(pkt)
    if http:
        stats["HTTP-request"] += 1
        print(f"         HTTP: {http[0]}  (Host: {http[1]})")
    elif not name:
        preview = payload_preview(pkt)
        if preview:
            print(f"         payload: {preview}")

    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        low = bytes(pkt[Raw].load).lower()
        hits = [k.decode() for k in SENSITIVE if k in low]
        if hits:
            alert(f"Sensitive keyword(s) {hits} in cleartext "
                  f"{src} -> {dst}:{dport}")

    check_port_scan(pkt, src)


def main():
    p = argparse.ArgumentParser(description="Network sniffer v2")
    p.add_argument("-i", "--iface")
    p.add_argument("-c", "--count", type=int, default=0)
    p.add_argument("-f", "--filter", default="")
    p.add_argument("-o", "--output", help="save capture to .pcap")
    args = p.parse_args()

    print("Sniffing... press Ctrl+C to stop.\n")
    try:
        sniff(iface=args.iface, filter=args.filter, prn=handle,
              count=args.count, store=False)
    except KeyboardInterrupt:
        pass

    print("\n--- Summary ---")
    for k, n in stats.most_common():
        print(f"{k:<13} {n}")
    print(f"Total packets: {len(captured)}")
    if alerts:
        print("\n--- Alerts ---")
        for a in alerts:
            print(a)
    if args.output and captured:
        wrpcap(args.output, captured)
        print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()

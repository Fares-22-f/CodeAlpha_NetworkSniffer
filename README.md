# CodeAlpha_NetworkSniffer

Basic network sniffer built with Python and Scapy (CodeAlpha Cyber Security Internship - Task 1).

## Features
- Captures packets and shows time, protocol, source/destination IP and ports, size, payload preview
- Extracts DNS query names and HTTP request lines
- Alerts on sensitive keywords in cleartext traffic
- Simple port-scan detection
- Saves captures to .pcap (openable in Wireshark)

## Usage
sudo python3 sniffer.py -i eth0 -o capture.pcap

## Testing
- curl http://example.com (DNS + HTTP GET)
- curl -d "username=admin&password=123" http://example.com (triggers sensitive-keyword alert)
- sudo nmap -sS -p 1-100 scanme.nmap.org (triggers port-scan alert)

## Screenshots
See the `screenshots/` folder:
1. Sniffer summary and alerts
2. Wireshark DNS filter
3. Wireshark HTTP filter + Follow HTTP Stream (shows cleartext credentials)
4. Wireshark port-scan filter (SYN packets)

## Disclaimer
For educational use on networks you own or are authorized to test.

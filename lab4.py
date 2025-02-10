#!/usr/bin/env python3
import sys
from scapy.all import sr1, IP, ICMP, TCP

def send_icmp(target, num):
    for i in range(num):
        pkt = IP(dst=target)/ICMP()
        reply = sr1(pkt, timeout=2, verbose=0)
        if reply:
            print(format_reply(reply , i))
        else:
            print(f"[ICMP] Packet {i+1}: No reply received")

def send_tcp(target, num):
    for i in range(num):
        pkt = IP(dst=target)/TCP(dport=80, flags='S')
        reply = sr1(pkt, timeout=2, verbose=0)
        if reply:
            print(format_reply(reply , i))
        else:
            print(f"[TCP] Packet {i+1}: No reply received")

def format_reply(reply , i) -> str:
    return(f"[TCP] Packet {i+1}: Received reply with IPID = {reply[IP].id}")

def main() -> None:
    if len(sys.argv) != 4:
        print("Script expects: Number of Packets, targer IP, Protocol")
        sys.exit(1)

    num_packets : int = int(sys.argv[1])
    target_ip : str = sys.argv[2]
    protocol : str = sys.argv[3].lower()

    if protocol == "icmp":
        send_icmp(target_ip, num_packets)
    elif protocol == "tcp":
        send_tcp(target_ip, num_packets)
    else:
        print("Invalid protocol. Use 'icmp' or 'tcp'")
        sys.exit(1)

if __name__ == "__main__":
    main()

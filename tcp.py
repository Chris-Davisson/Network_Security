#!/usr/bin/env python3
import sys
import random
import time
from scapy.all import IP, TCP, send, sniff, conf
import numpy as np

def send_syn_and_get_ip_id(target_ip: str, target_port: int = 80, df: bool = True, spoof: str = None) -> int | None:
    """
    Sends a TCP SYN packet to the target and returns the IP ID from the SYN-ACK or RST response.

    Args:
        target_ip: The IP address of the target.
        target_port: The destination port.
        df: Whether to set the Don't Fragment flag.
        spoof: Optional source IP to spoof.

    Returns:
        The IP ID from the response packet, or None if no suitable response was received.
    """
    try:
        if spoof:
            ip_layer = IP(src=spoof, dst=target_ip, flags="DF" if df else 0)
        else:
            ip_layer = IP(dst=target_ip, flags="DF" if df else 0)

        sport = random.randint(1024, 65535)  # Random source port
        tcp_layer = TCP(sport=sport, dport=target_port, flags="S", seq=random.randint(0, 2**32 - 1))
        packet = ip_layer / tcp_layer

        # Send the SYN packet using send() (raw socket)
        send(packet, verbose=0)

        # Sniff for the response (SYN-ACK or RST)
        filter_str = f"tcp and src host {target_ip} and src port {target_port} and dst port {sport}"
        #Increased timeout slightly, in case.
        response = sniff(filter=filter_str, timeout=3, count=1, iface=conf.iface)

        if response and IP in response[0] and TCP in response[0]:
            tcp_resp = response[0][TCP]
            ip_id = response[0][IP].id
            print(repr(response[0])) #Debugging

            if tcp_resp.flags & 0x12 == 0x12:  # SYN-ACK
                print("Received SYN-ACK")
                # Send ACK to complete the handshake (important!)
                ack_pkt = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="A", seq=tcp_resp.ack, ack=tcp_resp.seq + 1)
                send(ack_pkt, verbose=0)
                return ip_id
            elif tcp_resp.flags & 0x04 == 0x04:  # RST
                print("Received RST")
                return ip_id  # Return IP ID even for RST
            else:
                print(f"Unexpected flags: {tcp_resp.flags}")
                return None
        else:
            print("No response or error.")
            return None


    except Exception as e:
        print(f"Error: {e}")
        return None


def test_tcp_ipids(target_ip: str, port: int, count: int = 5, df: bool = True, spoof: str = None):
    """
    Tests TCP IP ID retrieval.

    Args:
        target_ip: Target IP address.
        port: Target port.
        count: Number of packets to send.
        df: Don't Fragment flag.
        spoof: Source IP to spoof (optional).
    """
    print(f"\n--- Testing TCP IP IDs against {target_ip}:{port} (DF={'set' if df else 'clear'}) ---")
    if spoof:
      print(f"Using Spooofed Source: {spoof}")
    ids = []
    for _ in range(count):
        ip_id = send_syn_and_get_ip_id(target_ip, target_port=port, df=df, spoof=spoof)
        if ip_id is not None:
            print(f"Received IP ID: {ip_id}")
            ids.append(ip_id)
        time.sleep(0.5)  # Short delay

    if ids:
        diffs = [(ids[i + 1] - ids[i]) % 65536 for i in range(len(ids) - 1)]
        print("\nIP IDs:", ids)
        print("Differences:", diffs)
        if len(ids) > 1: #prevent errors when calculating std.
          print("Standard Deviation:", np.std(diffs))
    else:
        print("No valid IP IDs received.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python tcp_ipid_test.py <target_ip> [port] [count] [df] [spoof_ip]")
        print("  <target_ip>: Required. The IP address of the target machine.")
        print("  [port]: Optional. The target TCP port. Defaults to 80.")
        print("  [count]: Optional. The number of packets to send. Defaults to 5.")
        print("  [df]: Optional. 'true' (default) or 'false' for Don't Fragment flag.")
        print("  [spoof_ip]: Optional. Spoof the source IP address.")
        sys.exit(1)

    target_ip = sys.argv[1]
    port = 80  # Default port
    count = 5  # Default count
    df = True #Default DF
    spoof_ip = None

    if len(sys.argv) > 2:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Error: Invalid port number.")
            sys.exit(1)
    if len(sys.argv) > 3:
        try:
            count = int(sys.argv[3])
        except ValueError:
            print("Error: Invalid count number.")
            sys.exit(1)
    if len(sys.argv) > 4:
        df_str = sys.argv[4].lower()
        if df_str == 'true':
          df = True
        elif df_str == 'false':
          df = False
        else:
          print("df must be 'true' or 'false'")
          sys.exit(1)
    if len(sys.argv) > 5:
        spoof_ip = sys.argv[5]

    test_tcp_ipids(target_ip, port, count, df, spoof_ip)


if __name__ == "__main__":
    main()
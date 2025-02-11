import sys
from scapy.all import sr1 , ICMP, IP, TCP, send, sniff
import random
import numpy as np
import time
import threading

def test_TTL(target_ip: str):
    """Tests the TTL of the target IP and infers the OS."""
    pkt = IP(dst=target_ip) / ICMP()
    response = sr1(pkt, timeout=2, verbose=0)
    if response is None:
        print("No ICMP response received.")
        return "No Response"
    
    # print("ICMP Response:")
    # print(repr(response))
    
    if IP in response:
        ttl = response[IP].ttl
        print(f"TTL:\t{ttl}")
        if ttl <= 64:
            return "Linux/BSD/Mac/IOS"  # Common for Unix-like systems
        elif ttl <= 128:
            return "Windows"  # Common for Windows
        elif ttl <= 255:
            return "Possibly macOS (or other with high TTL)" # Some older Macs, and other devices
        else:
            return "Custom TTL"
    else:
        print("No IP layer found in the response.")
        return "Invalid Response"

def test_window_size(target_ip: str , target_port: int):
    """Tests the TCP window size of the target IP and infers the OS."""
    pkt = IP(dst=target_ip)/TCP(dport=target_port, flags='S')
    reply = sr1(pkt,timeout=2,verbose=0)
    if reply:
        # reply[IP].show()
        window = reply[TCP].window
        print(f"TCP Window size: {window}")
        #I got these values by testing and looking at the window sizes.
        if window == 65535:
            return "Windows/Mac"
        elif window == 64240:
            return "Linux"
        else:
            return "Unknown"
    else:
        print(f"[TCP] Packet: No reply received")
        return None
    

def sniff_responses(target_ip, spoof_ip, timeout, batch2):
    # print("Sniffing started...")
    bpf_filter = f"src host {target_ip} and dst host {spoof_ip}"

    def packet_callback(pkt):
        if IP in pkt and pkt[IP].id != 0:  # Drop packets with ID = 0
            batch2.append(pkt[IP].id)
    sniff(filter=bpf_filter, timeout=timeout, prn=packet_callback)



def test_IPID(target_ip: str, target_port: int, spoof: bool):
    '''Tests IP ID behavior'''
    spoof_ip = "8.8.8.8"
    size = 10

    batch1 = []
    pkt = IP(dst=target_ip)/ICMP()

    #Capture initial IP IDs via ICMP
    for i in range(size):
        response = sr1(pkt, timeout=2, verbose=0)
        if response is not None:
            batch1.append(response[IP].id)
        time.sleep(0.1)
  
    
    if not batch1:
        print("No initial IP ID responses. Cannot continue IPID test.")
        return
    
    print(f"Initial IP IDs: {batch1}")
    batch2 = []
    if spoof:
        sniff_thread = threading.Thread(target=sniff_responses, args=(target_ip, spoof_ip,5 ,batch2 ))
        sniff_thread.start()
        # print("Sending spoofed packets...")
        pkt = IP(src=spoof_ip, dst=target_ip) / ICMP()
        for i in range(size):
            send(pkt, verbose=0)
            time.sleep(0.1)  # Small delay to prevent rapid-fire issues
        sniff_thread.join()

        print(f"Spoofed Packet ID IDs: {batch2}")

    #Capture New IP IDs via ICMP
    pkt = IP(dst=target_ip)/ICMP()
    batch3 = []
    for i in range(size):
        response = sr1(pkt, timeout=2, verbose=0)
        if response is not None:
            batch3.append(response[IP].id)

    print(f"Post-Spoofing IP IDs: {batch3}")

    return (batch1, batch2, batch3)

def doin_the_maths(batches):
    print()

def parse_arguments():
    target_ip = "127.0.0.1"
    target_port = 80

    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    if len(sys.argv) > 2:
        try:
            target_port = int(sys.argv[2])
        except ValueError:
            print("Invalid port provided. Defaulting to port 80.")
            target_port = 80

    return target_ip, target_port

def main():
    print("\nStarting ICMP Ping Test for IP ID and TTL Analysis")
    print("-" * 50 + "\n")

    target_ip, target_port = parse_arguments()
    print(f"Target IP:\t{target_ip}")
    print(f"Target Port:\t{target_port}\n")

    ttl = test_TTL(target_ip)
    window_size = test_window_size(target_ip, target_port)
    print(f"TTL: {ttl}")
    print(f"Window Size: {window_size}")

    batches = test_IPID(target_ip, target_port, True)
    doin_the_maths(batches)

if __name__ == "__main__":
    main()

'''
+-------------------------+-----------+-------+--------+-------------+----------+-----------+
|                         | Windows   | Mac   | Linux  | FreeBSD     | OpenBSD  | NetBSD    |
+-------------------------+-----------+-------+--------+-------------+----------+-----------+
| IPID                    | Per-Bucket| Random| Global | Incremental | Random   | Incremental|
+-------------------------+-----------+-------+--------+-------------+----------+-----------+
| TTL                     | 128       | 255?   | 64     | 64          | 64       | 64        |
+-------------------------+-----------+-------+--------+-------------+----------+-----------+
| TCP window size         | 8192      | 4128  | 5840   | 65535       | 32768    | 32768     |
+-------------------------+-----------+-------+--------+-------------+----------+-----------+
| Window Scaling Value    | 7         | 2     | 0      | 0           | 0        | 0         |
+-------------------------+-----------+-------+--------+-------------+----------+-----------+
tcp window size windows: 65535 | WSL: 64240

nc -l -p 5000 -v
socat TCP-LISTEN:5000,fork,reuseaddr -

what im thinking for windows is a two pointer and counting the distance between. 
    Start at i, then check the difference abs(batch[i] - batch[i+1]) < 5
        if yes then count++ go to the next one
        if count is ~ 4 +- 3 then it is prob windows. 
        if count is ~ 1 then it is random. check random with standard devation too
        if count > 4 then it is global 
'''

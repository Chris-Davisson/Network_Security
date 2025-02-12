import sys
from scapy.all import sr1 , ICMP, IP, TCP, send, sniff
import random
import numpy as np
import time
import threading

FINGERPRINTS = [
    # Windows
    {
        "os": "Windows (Modern)",
        "ttl": [65, 128],
        "window_size": [8192, 16384, 32768, 65535, 29200, 5840, 5720],
        "ipid": ["Incremental"],
        "rst_ipid": "Continue",  # Windows usually continues the sequence
        "confidence": "high"
    },
    {
          "os": "Windows (Modern)",
          "ttl": [65, 128],
          "window_size": [65535],
          "ipid": ["Incremental"],
          "rst_ipid": "Continue",
          "confidence": "high"
    },
    {
        "os": "Windows (Modern, or other per-flow)",
        "ttl": [65, 128],
        "window_size": "Unknown",
        "ipid": ["Incremental"],
        "rst_ipid": "Continue",
        "confidence": "medium"
    },
    # Linux
    {
        "os": "Linux (Modern)",
        "ttl": [0, 64],
        "window_size": [5840, 29200, 64240, 5720],
        "ipid": ["Incremental"],
        "rst_ipid": "Continue",  # Typically continues
        "confidence": "high"
    },
    {
         "os": "Linux (Modern)",
         "ttl": [0, 64],
         "window_size": [5840, 29200, 64240, 5720],
         "ipid": ["Big Endian"],
         "rst_ipid": "Continue",
         "confidence":"medium"
    },
    {
        "os": "Linux (or other global incremental)",
        "ttl": [0, 64],
        "window_size": "Unknown",
        "ipid": ["Incremental"],
        "rst_ipid": "Continue",
        "confidence": "medium"
    },

    # OpenBSD
    {
        "os": "OpenBSD",
        "ttl": [0, 64],
        "window_size": "Unknown",
        "ipid": ["Randomized"],
        "rst_ipid": "Randomized",  # OpenBSD randomizes everything
        "confidence": "high"
    },
    {
        "os": "OpenBSD",
        "ttl": [0, 64],
        "window_size": [32768],
        "ipid": ["Randomized"],
        "rst_ipid": "Randomized",
        "confidence": "high"
    },
    # FreeBSD
    {
        "os": "FreeBSD",
        "ttl": [0, 64],
        "window_size": "Unknown",
        "ipid": ["Zero"],
        "rst_ipid": "Zero",  # FreeBSD often uses 0 for RST IPID
        "confidence": "high"
    },
    {
        "os": "FreeBSD",
        "ttl": [0, 64],
        "window_size": [65535],
        "ipid": ["Incremental"],
        "rst_ipid": "Zero",
        "confidence": "medium"
    },
     {
        "os": "FreeBSD",
        "ttl": [0, 64],
        "window_size": [65535],
        "ipid": ["Incremental"],
        "rst_ipid": "Continue", #Could also continue
        "confidence": "low"
    },

    # macOS
    {
        "os": "macOS (Modern)",
        "ttl": [0,64],
        "window_size": "Unknown",
        "ipid": ["Byte Swapped"],
        "rst_ipid": "Continue",  #macOS usually continues
        "confidence": "medium"
    },
    {
        "os": "macOS (Modern)",
        "ttl": [0,64],
        "window_size": [65535],
        "ipid": ["Byte Swapped"],
        "rst_ipid": "Continue",
        "confidence": "medium"
    },
    # NetBSD
    {
        "os": "NetBSD",
        "ttl": [0, 64],
        "window_size": "Unknown",
        "ipid": ["Big Endian"],
        "rst_ipid": "Continue", # Usually continue
        "confidence": "medium"
    },
    {
      "os": "NetBSD",
      "ttl": [0,64],
      "window_size": [32768],
      "ipid":["Big Endian"],
      "rst_ipid": "Continue",
      "confidence": "medium"
    },
    {
      "os": "NetBSD",
      "ttl": [0,64],
      "window_size": [32768],
      "ipid":["Incremental"],
      "rst_ipid": "Continue",
      "confidence":"low"
    }

]


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
    
    #Capture spoofed IPID via ICMP
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


    #Testing TCP ACK reset IP ID behaviour
    pkt = IP(dst=target_ip)/TCP(dport=target_port , flags="A")
    send(pkt)
    pkt = IP(dst=target_ip)/ICMP()
    batch4 = []
    for i in range(size):
        response = sr1(pkt, timeout=2, verbose=0)
        if response is not None:
            batch4.append(response[IP].id)
    print(f"Post-TCP IP IDs: {batch4}")

    return doin_the_maths(batch1, batch2, batch3 , batch4)

def doin_the_maths(batch1 , batch2, batch3, batch4):
    '''
    batch1 = initial ICMP IP ID's
    batch2 = spoofed ICMP IP ID's
    batch3 = like batch1 but after batch2
    batch4 = after tcp Ack
    This funciton takes the batches and performs the statistical magic to tell me the IPID behavor.  
    '''
    print()
    return "Nothing"

    #Clean the inputs

    #Test only batch1 standard devation for random behaviour - MacOS
    #How to test. I can think of two ways. 1. test the difference between each ipid, it should be less than 10 at the extreme. If larger then it's prob random
    #   2. Test the STD - assign a number as being the limit
    #       IDK which would be better...

    #Test batch1 and batch3 for big differences - if the difference is the number of packets from the spoof then its a global counter. Linux or FreeBSD

    #Test batch1 and batch2 for big differences - If i get batch2 (being spoofed thats not gaurenteed) then this is per-connection - Windows

    #Test batch3 and batch4 for big differences - IDK, test some more. I think they all just contiue or something....

    #I dont really know what to return... there are multiple behaviours im testing for...


def fingerPrinting():
    '''
    This function hold a list of fingerprints for the different OS's
    I did it this way to handle empty fields

    TTL: Time to Live       |   0       |   64          |
    WS: Window size         | fill this in later
    IPID: IPID behavior     |   Global  |   Per-Bucket  |   Random  |   Zero's  |
    '''
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
    print("\nStarting...")
    print("-" * 50 + "\n")

    target_ip, target_port = parse_arguments()
    print(f"Target IP:\t{target_ip}")
    print(f"Target Port:\t{target_port}\n")

    print("-" * 50 + "\n")
    print("Testing Time to Live")
    ttl = test_TTL(target_ip)

    print("-" * 50 + "\n")
    print("Testing Window Size")
    print("-" * 50 + "\n")
    window_size = test_window_size(target_ip, target_port)

    print("-" * 50 + "\n")
    print("Testing  IPID behavior")
    IPID = test_IPID(target_ip, target_port, True)

    print("-" * 50 + "\n")
    print("-" * 50 + "\n")
    print("-" * 50 + "\n")

    print(f"TTL:\t\t{ttl}")
    print(f"Window Size:\t{window_size}")
    print(f"IPID Behavior:\t{IPID}")
    

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
TODO: Finish math part for IPID behavor. 
    Connect to a fingerprint
    write a test script
    make a .md then take screenshot, the make the pdf
    I no longer am going to test for openbsd, netbsd
    now just testing for Windows, mac, linux, freebsd
'''

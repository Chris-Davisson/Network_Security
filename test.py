import sys
from scapy.all import sr1, ICMP, IP, TCP, send, sniff
import time

def test_TTL(target_ip: str):
    """Tests the TTL of the target IP and infers the OS."""
    pkt = IP(dst=target_ip) / ICMP()
    response = sr1(pkt, timeout=2, verbose=0)
    if response is None:
        print("No ICMP response received.")
        return "No Response"

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

def test_window_size(target_ip: str, target_port: int):
    """Tests the TCP window size of the target IP and infers the OS."""
    pkt = IP(dst=target_ip) / TCP(dport=target_port, flags='S')
    reply = sr1(pkt, timeout=2, verbose=0)
    if reply:
        window = reply[TCP].window
        print(f"TCP Window size: {window}")
        # More refined window size checks (based on common values)
        if window in (8192, 16384, 32768, 65535, 29200, 5840, 64240, 5720): #Added some from your chart, and nmap
           if window == 64240:
              return "Linux (Likely)"
           elif window == 65535:
              return "Windows/FreeBSD"
           else:
              return "Common OS (Further analysis needed)"
        else:
            return "Unknown (Less Common Window Size)"
    else:
        print(f"[TCP] Packet: No reply received")
        return None

def test_IPID(target_ip: str, target_port: int, spoof_ip: str):
    """
    Tests IP ID behavior, attempting to distinguish between random,
    incremental, and zero IP ID generation.
    """
    batch1 = []
    pkt = IP(dst=target_ip) / ICMP()

    # Step 1: Capture initial IP IDs via ICMP
    for i in range(5):  # Fewer packets for initial check
        response = sr1(pkt, timeout=2, verbose=0)
        if response is not None:
            batch1.append(response[IP].id)
        time.sleep(0.1)

    print(f"Initial IP IDs: {batch1}")
    if not batch1:
        print("No initial IP ID responses. Cannot continue IPID test.")
        return

    # Step 2: (Optional) Send Spoofed Packets -  LESS RELIABLE, REMOVED
    #  This part is often unreliable and can be misleading due to firewalls, NAT, etc.
    #  We're focusing on the direct response behavior from the target.

    # Step 3: Capture New IP IDs via ICMP (Directly after initial check)
    batch2 = []
    for i in range(10):  # More packets for the main analysis
        response = sr1(pkt, timeout=2, verbose=0)
        if response is not None:
            batch2.append(response[IP].id)
        time.sleep(0.1)
    print(f"Post-Initial IP IDs: {batch2}")

    # --- Analysis ---
    all_ids = batch1 + batch2
    if not all_ids:
        print("No IP ID responses received.")
        return "Unknown (No Response)"

    if all(id == 0 for id in all_ids):
        print("IP ID Analysis: All zeros")
        return "FreeBSD (or other system with IP ID = 0)"

    # Calculate differences
    differences = [batch2[i+1] - batch2[i] for i in range(len(batch2) - 1)]

    # Check for randomization
    is_random = True
    for diff in differences:
        if -5 < diff < 5:  # Allow small variations
            is_random = False
            break
    if is_random:
        print("IP ID Analysis: Randomized")
        return "OpenBSD (Likely - Randomized IP ID)"
    
    # Check for byte-swapped pattern (macOS)
    is_byte_swapped = True
    for i in range(len(all_ids) - 1):
        diff = all_ids[i+1] - all_ids[i]
        #Check if diff is near 256, 512, 768, etc.
        if not (abs(diff) % 256) < 10 and diff !=0:
             continue #Likely byte-swapped
        else:
            is_byte_swapped = False
            break
    if is_byte_swapped:
        return "macOS (Likely - Byte Swapped)"

    # Check for small increments
    is_incremental = True
    for diff in differences:
        if not (0 < diff < 256):  # Typical incremental range
            is_incremental = False
            break
    if is_incremental:
        print("IP ID Analysis: Incremental")
         # Check for large difference in first two ipids (NetBSD, byte order issue)
        if batch2[1] > batch2[0] + 500:
            return "NetBSD (Likely - Big Endian Counter)"
        return "Windows/Linux (Likely - Incremental IP ID)"


    print("IP ID Analysis: Inconclusive")
    return "Unknown (Complex IP ID behavior)"

def main():
    print("\nStarting OS Fingerprinting\n" + "-" * 50 + "\n")
    target_ip = "127.0.0.1"  # Default to loopback
    target_port = 80  # Default port
    spoof_ip = "192.168.1.100" #Default spoofed ip, but not used in the code anymore.

    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    if len(sys.argv) > 2:
        target_port = int(sys.argv[2])


    print(f"Target IP:\t{target_ip}\nTarget Port:\t{target_port}")

    ttl_result = test_TTL(target_ip)
    window_size_result = test_window_size(target_ip, target_port)
    ipid_result = test_IPID(target_ip, target_port, spoof_ip) #Spoof IP is still passed, just for consistency.

    print("\n--- Results ---")
    print(f"TTL Analysis: {ttl_result}")
    print(f"Window Size Analysis: {window_size_result}")
    print(f"IPID Analysis: {ipid_result}")

    # Combine Results for a Final Guess (Simple Logic)
    final_guess = "Unknown"
    if "Windows" in ttl_result and "Windows" in window_size_result:
        final_guess = "Windows (High Confidence)"
    elif "Linux" in ttl_result and "Linux" in window_size_result and "Linux" in ipid_result:
        final_guess = "Linux (High Confidence)"
    elif "OpenBSD" in ipid_result:
        final_guess = "OpenBSD (High Confidence)"
    elif "FreeBSD" in ipid_result or "FreeBSD" in window_size_result:
        final_guess = "FreeBSD (Moderate Confidence)"
    elif "NetBSD" in ipid_result:
         final_guess = "NetBSD(Moderate Confidence)"
    elif "macOS" in ipid_result:
        final_guess = "macOS (Moderate Confidence)"
    elif "Linux" in ttl_result:
        final_guess = "Linux/BSD/Mac (Moderate Confidence)"


    print(f"\nFinal OS Guess: {final_guess}")

if __name__ == "__main__":
    main()